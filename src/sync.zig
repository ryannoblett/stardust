/// DHCP Lease Synchronisation (Redundant Server Group)
///
/// Implements the stardust-dhcp-sync-v2 protocol:
///   - UDP datagrams on port 647 (default)
///   - AES-256-GCM payload encryption (key derived via HKDF-SHA-256 from TSIG secret)
///   - Per-pool SHA-256 hashes with voting for pool enable/disable
///   - Last-write-wins conflict resolution via last_modified timestamp on each lease
///
/// Wire format (every datagram):
///   [version:u8=1][type:u8][timestamp:i64][nonce:12][payload_len:u32] — Additional Data (AD)
///   [ciphertext: payload_len bytes]
///   [tag: 16 bytes]
///   Total overhead: 42 bytes
const std = @import("std");
const config_mod = @import("./config.zig");
const config_write = @import("./config_write.zig");
const state_mod = @import("./state.zig");
const dns_mod = @import("./dns.zig");
const util = @import("./util.zig");

const log_v = std.log.scoped(.verbose);

// ---------------------------------------------------------------------------
// Wire format constants
// ---------------------------------------------------------------------------

const wire_version: u8 = 1;
const ad_size = 1 + 1 + 8 + 12 + 4; // version + type + timestamp + nonce + payload_len
const tag_size = 16;
const nonce_size = 12;
const overhead = ad_size + tag_size; // 42 bytes

const MsgType = enum(u8) {
    hello = 1,
    hello_ack = 2,
    hello_nak = 3,
    lease_update = 4,
    lease_delete = 5,
    keepalive = 6,
    lease_hash = 7,
    _,
};

const NakReason = enum(u8) {
    wrong_group = 1,
    pool_hash_mismatch = 2,
    timestamp_out_of_window = 3,
    version_mismatch = 4,
    _,
};

const anti_replay_window: i64 = 300; // seconds
const HELLO_PROTOCOL_VERSION: u8 = 2;
const max_local_pools: u8 = 32;
const startup_sync_timeout_s: i64 = 5;

const PoolSyncState = struct {
    subnet_ip: [4]u8,
    prefix_len: u8,
    local_hash: [32]u8,
    enabled: std.atomic.Value(bool),
};

const PeerPoolHash = struct {
    subnet_ip: [4]u8,
    prefix_len: u8,
    hash: [32]u8,
};

const max_pools_per_peer: u8 = 32;

// ---------------------------------------------------------------------------
// SyncManager
// ---------------------------------------------------------------------------

pub const SyncManager = struct {
    allocator: std.mem.Allocator,
    cfg: *const config_mod.SyncConfig,
    full_cfg: *config_mod.Config, // full config for reservation write-back
    cfg_path: []const u8, // config file path for reservation write-back
    store: *state_mod.StateStore,
    aes_key: [32]u8,
    pool_states: [max_local_pools]PoolSyncState,
    pool_states_len: u8,
    self_ip: u32, // host-order IP for voting tie-break
    sock_fd: std.posix.fd_t,
    peers: std.ArrayList(Peer),
    last_full_sync: i64,
    last_keepalive: i64,
    /// Atomically-maintained count of currently authenticated peers.
    /// Safe to read from any thread (e.g. the SSH TUI) without a lock.
    authenticated_count: std.atomic.Value(u32),
    /// Sync event counters (read atomically by SSH TUI stats tab).
    sync_full_events: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    sync_lease_events: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    const max_peers = 8;
    const keepalive_interval_s: i64 = 30;
    const peer_timeout_s: i64 = 90;
    const hello_retry_interval_s: i64 = 30;

    pub const Peer = struct {
        addr: std.posix.sockaddr.in,
        authenticated: bool,
        last_seen: i64,
        last_hello_sent: i64, // for retry logic (unauthenticated peers)
        peer_pool_hashes: [max_pools_per_peer]PeerPoolHash,
        peer_pool_hashes_len: u8,
        peer_ip: u32, // host-order IP for voting tie-break
    };

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        cfg: *const config_mod.SyncConfig,
        full_cfg: *config_mod.Config,
        cfg_path: []const u8,
        store: *state_mod.StateStore,
    ) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        // Parse TSIG key file and derive AES key via HKDF
        var tsig_key = try dns_mod.parseTsigKey(allocator, cfg.key_file);
        defer tsig_key.deinit();
        const aes_key = deriveKey(tsig_key.secret);

        // Compute self_ip from listen_address for voting tie-break
        const self_ip_bytes = parseIpv4Local(full_cfg.listen_address) catch [4]u8{ 0, 0, 0, 0 };
        const self_ip = std.mem.readInt(u32, &self_ip_bytes, .big);
        if (self_ip == 0) {
            std.log.warn("sync: listen_address is 0.0.0.0; this server will win all sync voting ties. Consider using a specific IP.", .{});
        }

        // Create UDP socket
        const sock_fd = try std.posix.socket(
            std.posix.AF.INET,
            std.posix.SOCK.DGRAM,
            std.posix.IPPROTO.UDP,
        );
        errdefer std.posix.close(sock_fd);

        try std.posix.setsockopt(
            sock_fd,
            std.posix.SOL.SOCKET,
            std.posix.SO.REUSEADDR,
            &std.mem.toBytes(@as(c_int, 1)),
        );

        // Set non-blocking so handlePacket can drain without blocking
        const flags = try std.posix.fcntl(sock_fd, std.posix.F.GETFL, 0);
        _ = try std.posix.fcntl(sock_fd, std.posix.F.SETFL, flags | @as(u32, std.posix.SOCK.NONBLOCK));

        const bind_addr = std.posix.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, cfg.port),
            .addr = 0, // INADDR_ANY
        };
        try std.posix.bind(sock_fd, @ptrCast(&bind_addr), @sizeOf(std.posix.sockaddr.in));

        // Join multicast group if configured; non-fatal so unicast sync still works
        // if the network interface isn't ready yet when the service starts.
        if (cfg.multicast) |mc_addr| {
            joinMulticast(sock_fd, mc_addr) catch |err| {
                std.log.warn("sync: failed to join multicast group {s} ({s}); using unicast only", .{ mc_addr, @errorName(err) });
            };
        }

        self.* = .{
            .allocator = allocator,
            .cfg = cfg,
            .full_cfg = full_cfg,
            .cfg_path = cfg_path,
            .store = store,
            .aes_key = aes_key,
            .pool_states = undefined,
            .pool_states_len = 0,
            .self_ip = self_ip,
            .sock_fd = sock_fd,
            .peers = std.ArrayList(Peer){},
            .last_full_sync = 0,
            .last_keepalive = 0,
            .authenticated_count = std.atomic.Value(u32).init(0),
        };
        self.computeLocalPoolStates();

        // Seed configured unicast peers (unauthenticated initially)
        for (cfg.peers) |peer_ip| {
            const ip = parseIpv4Local(peer_ip) catch {
                std.log.warn("sync: invalid peer address '{s}', skipping", .{peer_ip});
                continue;
            };
            const addr = std.posix.sockaddr.in{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, cfg.port),
                .addr = @bitCast(ip),
            };
            try self.peers.append(self.allocator, .{
                .addr = addr,
                .authenticated = false,
                .last_seen = 0,
                .last_hello_sent = 0,
                .peer_pool_hashes = undefined,
                .peer_pool_hashes_len = 0,
                .peer_ip = 0,
            });
        }

        std.log.info("sync: manager initialized (group={s}, port={d})", .{ cfg.group_name, cfg.port });

        // Send initial HELLO
        self.sendHelloAll();

        return self;
    }

    pub fn deinit(self: *Self) void {
        std.posix.close(self.sock_fd);
        self.peers.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    /// Update pool states after a config reload (SIGHUP). Recomputes per-pool
    /// hashes, deauthenticates all peers (forcing re-handshake), and re-evaluates
    /// pool enable/disable state.
    pub fn updatePoolStates(self: *Self, new_cfg: *config_mod.Config) void {
        self.full_cfg = new_cfg;
        self.computeLocalPoolStates();
        // Deauthenticate all peers — they need to re-handshake.
        for (self.peers.items) |*p| {
            if (p.authenticated) {
                p.authenticated = false;
                p.peer_pool_hashes_len = 0;
            }
        }
        self.authenticated_count.store(0, .release);
        self.reevaluatePoolStates();
        self.sendHelloAll();
        std.log.info("sync: pool states recomputed, re-authenticating all peers", .{});
    }

    /// Compute per-pool hash states from the current config.
    fn computeLocalPoolStates(self: *Self) void {
        self.pool_states_len = @intCast(@min(self.full_cfg.pools.len, max_local_pools));
        for (self.full_cfg.pools[0..self.pool_states_len], 0..) |*pool, i| {
            const subnet_ip = config_mod.parseIpv4(pool.subnet) catch [4]u8{ 0, 0, 0, 0 };
            self.pool_states[i] = .{
                .subnet_ip = subnet_ip,
                .prefix_len = pool.prefix_len,
                .local_hash = config_mod.computePerPoolHash(pool),
                .enabled = std.atomic.Value(bool).init(true),
            };
        }
    }

    /// Voting algorithm: for each local pool, collect votes from self + all
    /// authenticated peers. The hash with the most votes wins; ties broken by
    /// lowest peer IP. If our local hash matches the winner, the pool stays
    /// enabled; otherwise it is disabled.
    fn reevaluatePoolStates(self: *Self) void {
        for (self.pool_states[0..self.pool_states_len]) |*ps| {
            const VoteEntry = struct { hash: [32]u8, count: u8, lowest_ip: u32 };
            var votes: [max_peers + 1]VoteEntry = undefined;
            var vote_count: usize = 0;

            // Self vote
            votes[0] = .{ .hash = ps.local_hash, .count = 1, .lowest_ip = self.self_ip };
            vote_count = 1;

            // Peer votes
            for (self.peers.items) |*peer| {
                if (!peer.authenticated) continue;
                for (peer.peer_pool_hashes[0..peer.peer_pool_hashes_len]) |pph| {
                    if (std.mem.eql(u8, &pph.subnet_ip, &ps.subnet_ip) and pph.prefix_len == ps.prefix_len) {
                        // Find or create vote entry for this hash
                        var found = false;
                        for (votes[0..vote_count]) |*v| {
                            if (std.mem.eql(u8, &v.hash, &pph.hash)) {
                                v.count += 1;
                                v.lowest_ip = @min(v.lowest_ip, peer.peer_ip);
                                found = true;
                                break;
                            }
                        }
                        if (!found and vote_count < votes.len) {
                            votes[vote_count] = .{ .hash = pph.hash, .count = 1, .lowest_ip = peer.peer_ip };
                            vote_count += 1;
                        }
                        break;
                    }
                }
            }

            // Find winner: highest count, then lowest IP on tie
            var winner_idx: usize = 0;
            for (1..vote_count) |i| {
                if (votes[i].count > votes[winner_idx].count or
                    (votes[i].count == votes[winner_idx].count and votes[i].lowest_ip < votes[winner_idx].lowest_ip))
                {
                    winner_idx = i;
                }
            }

            const should_enable = std.mem.eql(u8, &votes[winner_idx].hash, &ps.local_hash);
            const was_enabled = ps.enabled.load(.acquire);
            ps.enabled.store(should_enable, .release);

            if (!should_enable and was_enabled) {
                std.log.warn("sync: pool {d}.{d}.{d}.{d}/{d} disabled: config mismatch, winning peer has different config", .{
                    ps.subnet_ip[0], ps.subnet_ip[1], ps.subnet_ip[2], ps.subnet_ip[3], ps.prefix_len,
                });
            } else if (should_enable and !was_enabled) {
                std.log.info("sync: pool {d}.{d}.{d}.{d}/{d} re-enabled: config now matches peers", .{
                    ps.subnet_ip[0], ps.subnet_ip[1], ps.subnet_ip[2], ps.subnet_ip[3], ps.prefix_len,
                });
            }
        }
    }

    /// Check if a pool is enabled for serving. Returns true for unknown pools (conservative).
    pub fn isPoolEnabled(self: *const Self, subnet_ip: [4]u8, prefix_len: u8) bool {
        for (self.pool_states[0..self.pool_states_len]) |*ps| {
            if (std.mem.eql(u8, &ps.subnet_ip, &subnet_ip) and ps.prefix_len == prefix_len) {
                return ps.enabled.load(.acquire);
            }
        }
        return true; // unknown pool = enabled (conservative)
    }

    /// Wait for initial peer sync at startup. Polls for incoming packets
    /// up to startup_sync_timeout_s seconds. After timeout (or first peer auth),
    /// evaluates pool states and logs any disabled pools.
    pub fn waitForInitialSync(self: *Self) void {
        if (self.peers.items.len == 0) return; // no peers configured
        std.log.info("sync: waiting up to {d}s for peer responses...", .{startup_sync_timeout_s});
        const deadline = std.time.timestamp() + startup_sync_timeout_s;
        while (std.time.timestamp() < deadline) {
            self.pollOnce(1000);
            if (self.authenticated_count.load(.acquire) > 0) {
                std.log.info("sync: peer authenticated, evaluating pool states", .{});
                break;
            }
        }
        self.reevaluatePoolStates();
        // Log results
        for (self.pool_states[0..self.pool_states_len]) |*ps| {
            if (!ps.enabled.load(.acquire)) {
                std.log.warn("sync: pool {d}.{d}.{d}.{d}/{d} DISABLED at startup due to config mismatch", .{
                    ps.subnet_ip[0], ps.subnet_ip[1], ps.subnet_ip[2], ps.subnet_ip[3], ps.prefix_len,
                });
            }
        }
    }

    /// Poll for a single round of incoming packets with the given timeout in ms.
    /// Uses poll(2) to wait for data, then drains all available packets.
    fn pollOnce(self: *Self, timeout_ms: i32) void {
        var pfd = [1]std.posix.pollfd{.{
            .fd = self.sock_fd,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        _ = std.posix.poll(&pfd, timeout_ms) catch return;
        if (pfd[0].revents & std.posix.POLL.IN != 0) {
            self.handlePacket();
        }
    }

    /// Check if an IP string belongs to a pool that is currently disabled.
    /// Uses pool_states directly (no full_cfg dereference needed).
    fn isIpInDisabledPool(self: *Self, ip_str: []const u8) bool {
        if (self.pool_states_len == 0) return false;
        const ip_bytes = parseIpv4Local(ip_str) catch return false;
        const ip_int = std.mem.readInt(u32, &ip_bytes, .big);
        for (self.pool_states[0..self.pool_states_len]) |*ps| {
            const subnet_int = std.mem.readInt(u32, &ps.subnet_ip, .big);
            const mask: u32 = if (ps.prefix_len == 0) 0 else @as(u32, 0xFFFFFFFF) << @intCast(32 - @as(u6, @intCast(ps.prefix_len)));
            if ((ip_int & mask) == (subnet_int & mask)) {
                return !ps.enabled.load(.acquire);
            }
        }
        return false; // no matching pool = not disabled
    }

    /// Returns true if at least one peer is currently authenticated.
    pub fn hasAuthenticatedPeers(self: *Self) bool {
        for (self.peers.items) |p| {
            if (p.authenticated) return true;
        }
        return false;
    }

    /// Returns true if this server has the lowest IP address among all currently
    /// active servers (self + authenticated peers). Used to elect a single DNS
    /// delegate when the originating server is down: only the lowest-IP active
    /// server handles DNS for non-local leases, preventing duplicate updates in
    /// groups of 3+ servers.
    pub fn isLowestActivePeer(self: *Self, my_ip: [4]u8) bool {
        const my_int = std.mem.readInt(u32, &my_ip, .big);
        for (self.peers.items) |*p| {
            if (!p.authenticated) continue;
            const octets = peerIpOctets(p);
            const peer_int = std.mem.readInt(u32, &octets, .big);
            if (peer_int < my_int) return false;
        }
        return true;
    }

    /// Called each main loop iteration. Handles keepalives, retries, and periodic full-sync.
    pub fn tick(self: *Self, now: i64) void {
        // Expire timed-out peers
        var i: usize = 0;
        while (i < self.peers.items.len) {
            const p = &self.peers.items[i];
            if (p.authenticated and now - p.last_seen > peer_timeout_s) {
                std.log.info("sync: peer {d}.{d}.{d}.{d} timed out", .{
                    peerIpOctets(p)[0], peerIpOctets(p)[1], peerIpOctets(p)[2], peerIpOctets(p)[3],
                });
                // For unicast configured peers, keep in list but reset to unauthenticated.
                // For dynamically discovered multicast peers, remove entirely.
                if (isConfiguredPeer(self, p)) {
                    p.authenticated = false;
                    p.last_seen = 0;
                    p.peer_pool_hashes_len = 0;
                    _ = self.authenticated_count.fetchSub(1, .monotonic);
                    i += 1;
                } else {
                    _ = self.authenticated_count.fetchSub(1, .monotonic);
                    _ = self.peers.swapRemove(i);
                }
            } else {
                i += 1;
            }
        }

        // Send keepalives to authenticated peers
        if (now - self.last_keepalive >= keepalive_interval_s) {
            for (self.peers.items) |*p| {
                if (p.authenticated) self.sendMsg(p.addr, .keepalive, &[0]u8{});
            }
            // Multicast HELLO for discovery
            if (self.cfg.multicast) |mc| {
                const mc_ip = parseIpv4Local(mc) catch return;
                const mc_addr = std.posix.sockaddr.in{
                    .family = std.posix.AF.INET,
                    .port = std.mem.nativeToBig(u16, self.cfg.port),
                    .addr = @bitCast(mc_ip),
                };
                var hello_buf: [hello_max_payload]u8 = undefined;
                const hello_len = self.buildHelloPayload(&hello_buf);
                self.sendMsg(mc_addr, .hello, hello_buf[0..hello_len]);
            }
            self.last_keepalive = now;
        }

        // Retry HELLO to unauthenticated unicast peers
        for (self.peers.items) |*p| {
            if (!p.authenticated and now - p.last_hello_sent >= hello_retry_interval_s) {
                var retry_buf: [hello_max_payload]u8 = undefined;
                const retry_len = self.buildHelloPayload(&retry_buf);
                self.sendMsg(p.addr, .hello, retry_buf[0..retry_len]);
                p.last_hello_sent = now;
            }
        }

        // Periodic full-sync via LEASE_HASH
        const interval: i64 = @intCast(self.cfg.full_sync_interval);
        if (now - self.last_full_sync >= interval) {
            const lease_hash = self.computeLeaseHash();
            var lh_payload: [32]u8 = lease_hash;
            for (self.peers.items) |*p| {
                if (p.authenticated) self.sendMsg(p.addr, .lease_hash, &lh_payload);
            }
            self.last_full_sync = now;
        }
    }

    /// Called from the DHCP server's event loop when data is available on sock_fd.
    pub fn handlePacket(self: *Self) void {
        var buf: [8192]u8 = undefined;
        var src: std.posix.sockaddr.in = undefined;
        var src_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);

        while (true) {
            const n = std.posix.recvfrom(
                self.sock_fd,
                &buf,
                0,
                @ptrCast(&src),
                &src_len,
            ) catch |err| {
                switch (err) {
                    error.WouldBlock => break,
                    else => {
                        std.log.warn("sync: recvfrom error: {s}", .{@errorName(err)});
                        break;
                    },
                }
            };

            self.processRawPacket(buf[0..n], src) catch |err| {
                std.log.debug("sync: dropped packet from peer: {s}", .{@errorName(err)});
            };
        }
    }

    /// Notify all authenticated peers of a new/updated lease.
    pub fn notifyLeaseUpdate(self: *Self, lease: state_mod.Lease) void {
        const json = std.json.Stringify.valueAlloc(self.allocator, lease, .{}) catch return;
        defer self.allocator.free(json);
        if (json.len > 1400) {
            std.log.warn("sync: lease update for {s} is {d} bytes, may exceed UDP MTU", .{ lease.mac, json.len });
        }
        var sent: usize = 0;
        for (self.peers.items) |*p| {
            if (p.authenticated) {
                self.sendMsg(p.addr, .lease_update, json);
                sent += 1;
            }
        }
        if (sent > 0) {
            _ = self.sync_lease_events.fetchAdd(1, .monotonic);
            log_v.debug("sync: sent lease update {s} ({s}) to {d} peer(s)", .{
                lease.ip, lease.mac, sent,
            });
        }
    }

    /// Notify all authenticated peers that a lease was deleted (by MAC string).
    pub fn notifyLeaseDelete(self: *Self, mac: []const u8) void {
        var sent: usize = 0;
        for (self.peers.items) |*p| {
            if (p.authenticated) {
                self.sendMsg(p.addr, .lease_delete, mac);
                sent += 1;
            }
        }
        if (sent > 0) log_v.debug("sync: sent lease delete {s} to {d} peer(s)", .{ mac, sent });
    }

    // -----------------------------------------------------------------------
    // Internal: crypto
    // -----------------------------------------------------------------------

    /// Derive a 32-byte AES-256 key from a TSIG secret using HKDF-SHA-256.
    pub fn deriveKey(secret: []const u8) [32]u8 {
        const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
        const info = "stardust-dhcp-sync-v1";
        const prk = Hkdf.extract("", secret);
        var okm: [32]u8 = undefined;
        Hkdf.expand(&okm, info, prk);
        return okm;
    }

    /// Encrypt plaintext with AES-256-GCM. Writes into out_buf:
    ///   [AD: version|type|timestamp|nonce|payload_len][ciphertext][tag]
    /// Returns total bytes written or null if out_buf is too small.
    fn encrypt(
        self: *Self,
        msg_type: MsgType,
        plaintext: []const u8,
        out_buf: []u8,
    ) ?usize {
        if (out_buf.len < ad_size + plaintext.len + tag_size) return null;

        var nonce: [nonce_size]u8 = undefined;
        std.crypto.random.bytes(&nonce);

        const now: i64 = std.time.timestamp();

        // Build AD
        out_buf[0] = wire_version;
        out_buf[1] = @intFromEnum(msg_type);
        std.mem.writeInt(i64, out_buf[2..10], now, .big);
        @memcpy(out_buf[10..22], &nonce);
        std.mem.writeInt(u32, out_buf[22..26], @intCast(plaintext.len), .big);

        const ad = out_buf[0..ad_size];
        const ct_start = ad_size;
        const ct_end = ct_start + plaintext.len;
        const tag_start = ct_end;

        const Aes = std.crypto.aead.aes_gcm.Aes256Gcm;
        Aes.encrypt(
            out_buf[ct_start..ct_end],
            out_buf[tag_start..][0..tag_size],
            plaintext,
            ad,
            nonce,
            self.aes_key,
        );

        return ct_end + tag_size;
    }

    /// Decrypt a raw datagram. Returns plaintext slice into plaintext_buf, or error.
    fn decrypt(
        self: *Self,
        datagram: []const u8,
        plaintext_buf: []u8,
    ) !struct { msg_type: MsgType, plaintext: []u8 } {
        if (datagram.len < ad_size + tag_size) return error.TooShort;

        const ad = datagram[0..ad_size];
        const version = ad[0];
        const msg_type: MsgType = @enumFromInt(ad[1]);
        const timestamp = std.mem.readInt(i64, ad[2..10], .big);
        const nonce: [nonce_size]u8 = ad[10..22].*;
        const payload_len = std.mem.readInt(u32, ad[22..26], .big);

        if (version != wire_version) return error.UnknownVersion;

        // Guard against oversized or malicious payload_len values before arithmetic
        // that could overflow on 32-bit targets (ad_size + payload_len + tag_size).
        if (payload_len > 8192 or payload_len > datagram.len) return error.Truncated;

        const now = std.time.timestamp();
        if (@abs(now - timestamp) > anti_replay_window) return error.ReplayDetected;

        if (datagram.len < ad_size + payload_len + tag_size) return error.Truncated;
        const ct = datagram[ad_size .. ad_size + payload_len];
        const tag: [tag_size]u8 = datagram[ad_size + payload_len ..][0..tag_size].*;

        if (plaintext_buf.len < payload_len) return error.PlainBufTooSmall;

        const Aes = std.crypto.aead.aes_gcm.Aes256Gcm;
        Aes.decrypt(
            plaintext_buf[0..payload_len],
            ct,
            tag,
            ad,
            nonce,
            self.aes_key,
        ) catch return error.AuthFailed;

        return .{ .msg_type = msg_type, .plaintext = plaintext_buf[0..payload_len] };
    }

    // -----------------------------------------------------------------------
    // Internal: pool / lease hashing
    // -----------------------------------------------------------------------

    /// Compute a SHA-256 hash over all leases sorted by MAC — anti-entropy check.
    pub fn computeLeaseHash(self: *Self) [32]u8 {
        // Collect all leases
        const list = self.store.listLeases() catch return [_]u8{0} ** 32;
        defer self.store.allocator.free(list);

        // Sort by MAC string
        std.mem.sort(state_mod.Lease, list, {}, struct {
            fn lt(_: void, a: state_mod.Lease, b: state_mod.Lease) bool {
                return std.mem.lessThan(u8, a.mac, b.mac);
            }
        }.lt);

        var h = std.crypto.hash.sha2.Sha256.init(.{});
        for (list) |lease| {
            h.update(lease.mac);
            h.update(lease.ip);
            var exp_bytes: [8]u8 = undefined;
            std.mem.writeInt(i64, &exp_bytes, lease.expires, .big);
            h.update(&exp_bytes);
            var lm_bytes: [8]u8 = undefined;
            std.mem.writeInt(i64, &lm_bytes, lease.last_modified, .big);
            h.update(&lm_bytes);
            h.update(&[1]u8{if (lease.reserved) 1 else 0});
            h.update(lease.hostname orelse "");
            h.update(lease.client_id orelse "");
        }
        var digest: [32]u8 = undefined;
        h.final(&digest);
        return digest;
    }

    // -----------------------------------------------------------------------
    // Internal: sending
    // -----------------------------------------------------------------------

    fn sendMsg(self: *Self, addr: std.posix.sockaddr.in, msg_type: MsgType, plaintext: []const u8) void {
        var buf: [8192]u8 = undefined;
        const n = self.encrypt(msg_type, plaintext, &buf) orelse {
            std.log.warn("sync: message too large to encrypt (type={d}, len={d})", .{
                @intFromEnum(msg_type), plaintext.len,
            });
            return;
        };
        _ = std.posix.sendto(
            self.sock_fd,
            buf[0..n],
            0,
            @ptrCast(&addr),
            @sizeOf(std.posix.sockaddr.in),
        ) catch |err| {
            std.log.warn("sync: sendto error: {s}", .{@errorName(err)});
        };
    }

    fn sendHelloAll(self: *Self) void {
        var payload: [hello_max_payload]u8 = undefined;
        const len = self.buildHelloPayload(&payload);
        if (self.cfg.multicast) |mc| {
            const mc_ip = parseIpv4Local(mc) catch return;
            const mc_addr = std.posix.sockaddr.in{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, self.cfg.port),
                .addr = @bitCast(mc_ip),
            };
            self.sendMsg(mc_addr, .hello, payload[0..len]);
        }
        for (self.peers.items) |*p| {
            if (!p.authenticated) {
                self.sendMsg(p.addr, .hello, payload[0..len]);
                p.last_hello_sent = std.time.timestamp();
            }
        }
    }

    /// Maximum HELLO payload size: version(1) + gn_len(1) + group_name(255) + pool_count(1) + 32 * 37
    const hello_max_payload: usize = 1 + 1 + 255 + 1 + @as(usize, max_local_pools) * 37;

    /// Build a v2 HELLO/HELLO_ACK payload into the provided buffer.
    /// Format: [version:u8=2][gn_len:u8][group_name:N][pool_count:u8]
    ///         for each pool: [subnet_ip:4][prefix_len:1][hash:32]
    /// Returns the number of bytes written.
    fn buildHelloPayload(self: *Self, buf: []u8) usize {
        var off: usize = 0;
        buf[off] = HELLO_PROTOCOL_VERSION;
        off += 1;
        const gn = self.cfg.group_name;
        const gn_len: u8 = @intCast(@min(gn.len, 255));
        buf[off] = gn_len;
        off += 1;
        @memcpy(buf[off .. off + gn_len], gn[0..gn_len]);
        off += gn_len;
        buf[off] = self.pool_states_len;
        off += 1;
        for (self.pool_states[0..self.pool_states_len]) |*ps| {
            @memcpy(buf[off .. off + 4], &ps.subnet_ip);
            off += 4;
            buf[off] = ps.prefix_len;
            off += 1;
            @memcpy(buf[off .. off + 32], &ps.local_hash);
            off += 32;
        }
        return off;
    }

    fn helloPayloadLen(self: *Self) usize {
        return 1 + 1 + @min(self.cfg.group_name.len, 255) + 1 + @as(usize, self.pool_states_len) * 37;
    }

    // -----------------------------------------------------------------------
    // Internal: receive / dispatch
    // -----------------------------------------------------------------------

    fn processRawPacket(self: *Self, raw: []const u8, src: std.posix.sockaddr.in) !void {
        var plain_buf: [8192]u8 = undefined;
        const result = try self.decrypt(raw, &plain_buf);

        switch (result.msg_type) {
            // Handshake messages are always accepted (they establish/verify auth).
            .hello => self.processHello(src, result.plaintext, false),
            .hello_ack => self.processHello(src, result.plaintext, true),
            .hello_nak => self.processHelloNak(src, result.plaintext),
            // Lease and hash messages require the peer to be authenticated
            // (group name matched during the HELLO handshake).  After a pool
            // config change, updatePoolStates() marks all peers unauthenticated,
            // so stale-config peers are locked out until they re-handshake.
            .lease_update, .lease_delete, .keepalive, .lease_hash => {
                const peer = self.findPeer(src) orelse return;
                if (!peer.authenticated) {
                    log_v.debug("sync: ignoring {s} from unauthenticated peer", .{@tagName(result.msg_type)});
                    return;
                }
                peer.last_seen = std.time.timestamp();
                switch (result.msg_type) {
                    .lease_update => self.applyLeaseUpdate(result.plaintext),
                    .lease_delete => self.applyLeaseDelete(result.plaintext),
                    .lease_hash => self.processLeaseHash(src, result.plaintext),
                    .keepalive => {},
                    else => unreachable,
                }
            },
            else => {},
        }
    }

    fn processHello(self: *Self, src: std.posix.sockaddr.in, plaintext: []const u8, is_ack: bool) void {
        if (plaintext.len < 2) return;
        const version = plaintext[0];

        // Reject v1 peers
        if (version == 1) {
            std.log.warn("sync: HELLO from v1 peer, sending NAK version_mismatch", .{});
            var nak: [1]u8 = .{@intFromEnum(NakReason.version_mismatch)};
            self.sendMsg(src, .hello_nak, &nak);
            return;
        }
        if (version != HELLO_PROTOCOL_VERSION) {
            std.log.warn("sync: HELLO with unknown version {d}, ignoring", .{version});
            return;
        }

        const gn_len = plaintext[1];
        // Minimum: version(1) + gn_len(1) + group_name(gn_len) + pool_count(1)
        if (plaintext.len < 2 + @as(usize, gn_len) + 1) return;
        const group_name = plaintext[2 .. 2 + gn_len];

        // Validate group name
        if (!std.mem.eql(u8, group_name, self.cfg.group_name)) {
            std.log.warn("sync: HELLO from wrong group '{f}', sending NAK", .{util.escapedStr(group_name)});
            var nak: [1]u8 = .{@intFromEnum(NakReason.wrong_group)};
            self.sendMsg(src, .hello_nak, &nak);
            return;
        }

        // Authenticate peer (group name match is sufficient in v2)
        const now = std.time.timestamp();
        const peer = self.findOrAddPeer(src) catch return;
        const was_authenticated = peer.authenticated;
        peer.authenticated = true;
        peer.last_seen = now;
        if (!was_authenticated) _ = self.authenticated_count.fetchAdd(1, .monotonic);

        // Extract peer IP from source address (network-order → host-order)
        const peer_ip_bytes: [4]u8 = @bitCast(src.addr);
        peer.peer_ip = std.mem.readInt(u32, &peer_ip_bytes, .big);

        // Parse per-pool hashes from payload
        var off: usize = 2 + @as(usize, gn_len);
        const pool_count = plaintext[off];
        off += 1;
        peer.peer_pool_hashes_len = @intCast(@min(pool_count, max_pools_per_peer));
        var parsed: u8 = 0;
        while (parsed < pool_count and off + 37 <= plaintext.len and parsed < max_pools_per_peer) : (parsed += 1) {
            peer.peer_pool_hashes[parsed] = .{
                .subnet_ip = plaintext[off..][0..4].*,
                .prefix_len = plaintext[off + 4],
                .hash = plaintext[off + 5 ..][0..32].*,
            };
            off += 37;
        }
        peer.peer_pool_hashes_len = parsed;
        if (parsed < pool_count) {
            std.log.warn("sync: HELLO from peer advertised {d} pools but payload only contained {d}", .{ pool_count, parsed });
        }

        if (!is_ack) {
            // Send HELLO_ACK back
            var ack_buf: [hello_max_payload]u8 = undefined;
            const ack_len = self.buildHelloPayload(&ack_buf);
            self.sendMsg(src, .hello_ack, ack_buf[0..ack_len]);
        }

        // Re-evaluate pool enable/disable states
        self.reevaluatePoolStates();

        // Exchange lease hashes immediately
        var lh: [32]u8 = self.computeLeaseHash();
        self.sendMsg(src, .lease_hash, &lh);
        if (!was_authenticated) {
            std.log.info("sync: peer {d}.{d}.{d}.{d} authenticated", .{
                peerIpOctets(peer)[0], peerIpOctets(peer)[1], peerIpOctets(peer)[2], peerIpOctets(peer)[3],
            });
        }
    }

    fn processHelloNak(self: *Self, src: std.posix.sockaddr.in, plaintext: []const u8) void {
        _ = self;
        _ = src;
        if (plaintext.len < 1) return;
        const reason: NakReason = @enumFromInt(plaintext[0]);
        switch (reason) {
            .wrong_group => std.log.warn("sync: received HELLO_NAK: wrong group name", .{}),
            .pool_hash_mismatch => std.log.warn("sync: received HELLO_NAK: pool hash mismatch (ensure identical subnet/pool/reservation config)", .{}),
            .timestamp_out_of_window => std.log.warn("sync: received HELLO_NAK: timestamp out of anti-replay window (check NTP sync)", .{}),
            .version_mismatch => std.log.warn("sync: received HELLO_NAK: version mismatch (peer requires protocol v2)", .{}),
            else => std.log.warn("sync: received HELLO_NAK: unknown reason {d}", .{@intFromEnum(reason)}),
        }
    }

    fn processLeaseHash(self: *Self, src: std.posix.sockaddr.in, plaintext: []const u8) void {
        if (plaintext.len < 32) return;
        const peer_hash: [32]u8 = plaintext[0..32].*;
        const own_hash = self.computeLeaseHash();
        if (std.mem.eql(u8, &peer_hash, &own_hash)) return; // stores identical

        // Hashes differ — send full lease dump to peer
        const peer = self.findPeer(src) orelse return;
        if (!peer.authenticated) return;
        std.log.info("sync: lease hash mismatch with peer, sending full dump", .{});
        self.fullSyncToPeer(peer);
    }

    fn updatePeerSeen(self: *Self, src: std.posix.sockaddr.in) void {
        if (self.findPeer(src)) |p| p.last_seen = std.time.timestamp();
    }

    fn applyLeaseUpdate(self: *Self, plaintext: []const u8) void {
        const parsed = std.json.parseFromSlice(
            state_mod.Lease,
            self.allocator,
            plaintext,
            .{ .ignore_unknown_fields = true },
        ) catch return;
        defer parsed.deinit();
        // Force local=false: DNS ownership never transfers via sync. The originating
        // server retains local=true (persisted in leases.json) and handles DNS for its leases.
        var incoming = parsed.value;
        incoming.local = false;

        // Reject updates for IPs in disabled pools
        if (self.isIpInDisabledPool(incoming.ip)) {
            log_v.debug("sync: rejecting lease update for {s}: pool disabled", .{incoming.ip});
            return;
        }

        // Last-write-wins: only apply if incoming is newer
        if (self.store.leases.get(incoming.mac)) |existing| {
            if (incoming.last_modified <= existing.last_modified) return;
        }

        self.store.addLease(incoming) catch |err| {
            std.log.warn("sync: failed to apply received lease update: {s}", .{@errorName(err)});
            return;
        };
        log_v.debug("sync: received lease update {s} ({s})", .{ incoming.ip, incoming.mac });

        // If this is a reservation, persist it to config.yaml so it survives a reload.
        // Without this, the reservation would exist in the lease store at runtime but
        // disappear from config.yaml, causing it to vanish on SIGHUP or restart.
        if (incoming.reserved) {
            if (config_write.findPoolForIp(self.full_cfg, incoming.ip)) |pool| {
                _ = config_write.upsertReservation(
                    self.allocator,
                    pool,
                    incoming.mac,
                    incoming.ip,
                    incoming.hostname,
                    incoming.client_id,
                    null,
                ) catch |err| {
                    std.log.warn("sync: failed to update config.yaml for reservation {s}: {s}", .{ incoming.mac, @errorName(err) });
                    return;
                };
                config_write.writeConfig(self.allocator, self.full_cfg, self.cfg_path) catch |err| {
                    std.log.warn("sync: failed to write config.yaml for reservation {s}: {s}", .{ incoming.mac, @errorName(err) });
                };
                log_v.debug("sync: persisted reservation {s} ({s}) to config.yaml", .{ incoming.ip, incoming.mac });
            } else {
                std.log.warn("sync: received reservation {s} ({s}) does not match any pool, skipping config write", .{ incoming.ip, incoming.mac });
            }
        }
    }

    fn applyLeaseDelete(self: *Self, plaintext: []const u8) void {
        // plaintext is the MAC string (17 bytes "xx:xx:xx:xx:xx:xx")
        if (plaintext.len == 0) return;

        // Reject deletes for IPs in disabled pools
        if (self.store.leases.get(plaintext)) |existing| {
            if (self.isIpInDisabledPool(existing.ip)) {
                log_v.debug("sync: rejecting lease delete for {s}: pool disabled", .{existing.ip});
                return;
            }
        }

        self.store.removeLease(plaintext);
        log_v.debug("sync: received lease delete {f}", .{util.escapedStr(plaintext)});
    }

    fn fullSyncToPeer(self: *Self, peer: *Peer) void {
        const list = self.store.listLeases() catch return;
        defer self.store.allocator.free(list);
        for (list) |lease| {
            const json = std.json.Stringify.valueAlloc(self.allocator, lease, .{}) catch continue;
            defer self.allocator.free(json);
            self.sendMsg(peer.addr, .lease_update, json);
        }
        _ = self.sync_full_events.fetchAdd(1, .monotonic);
        const octets = peerIpOctets(peer);
        log_v.debug("sync: full dump sent to {d}.{d}.{d}.{d}: {d} lease(s)", .{
            octets[0], octets[1], octets[2], octets[3], list.len,
        });
    }

    // -----------------------------------------------------------------------
    // Internal: peer management
    // -----------------------------------------------------------------------

    fn findPeer(self: *Self, addr: std.posix.sockaddr.in) ?*Peer {
        for (self.peers.items) |*p| {
            if (p.addr.addr == addr.addr) return p;
        }
        return null;
    }

    fn findOrAddPeer(self: *Self, addr: std.posix.sockaddr.in) !*Peer {
        if (self.findPeer(addr)) |p| return p;
        if (self.peers.items.len >= max_peers) {
            std.log.warn("sync: max peer limit reached, ignoring new peer", .{});
            return error.TooManyPeers;
        }
        try self.peers.append(self.allocator, .{
            .addr = addr,
            .authenticated = false,
            .last_seen = 0,
            .last_hello_sent = 0,
            .peer_pool_hashes = undefined,
            .peer_pool_hashes_len = 0,
            .peer_ip = 0,
        });
        return &self.peers.items[self.peers.items.len - 1];
    }

    fn isConfiguredPeer(self: *Self, peer: *Peer) bool {
        for (self.cfg.peers) |peer_ip| {
            const ip = parseIpv4Local(peer_ip) catch continue;
            const addr_int: u32 = @bitCast(ip);
            if (peer.addr.addr == std.mem.nativeToBig(u32, addr_int)) return true;
        }
        return false;
    }
};

// -----------------------------------------------------------------------
// Multicast setup
// -----------------------------------------------------------------------

const ip_mreq = extern struct {
    imr_multiaddr: u32,
    imr_interface: u32,
};

const IPPROTO_IP = 0;
const IP_ADD_MEMBERSHIP = 35;
const IP_MULTICAST_TTL = 33;
const IP_MULTICAST_LOOP = 34;

fn joinMulticast(sock_fd: std.posix.fd_t, mc_addr: []const u8) !void {
    const ip = try parseIpv4Local(mc_addr);
    const mreq = ip_mreq{
        .imr_multiaddr = @bitCast(ip),
        .imr_interface = 0, // INADDR_ANY
    };
    try std.posix.setsockopt(
        sock_fd,
        IPPROTO_IP,
        IP_ADD_MEMBERSHIP,
        std.mem.asBytes(&mreq),
    );
    try std.posix.setsockopt(
        sock_fd,
        IPPROTO_IP,
        IP_MULTICAST_TTL,
        &std.mem.toBytes(@as(c_int, 1)),
    );
    try std.posix.setsockopt(
        sock_fd,
        IPPROTO_IP,
        IP_MULTICAST_LOOP,
        &std.mem.toBytes(@as(c_int, 0)),
    );
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn peerIpOctets(p: *const SyncManager.Peer) [4]u8 {
    return @bitCast(p.addr.addr);
}

fn parseIpv4Local(s: []const u8) ![4]u8 {
    var result: [4]u8 = undefined;
    var octet: u16 = 0;
    var idx: u8 = 0;
    for (s) |c| {
        if (c == '.') {
            if (idx >= 3) return error.InvalidAddress;
            result[idx] = @intCast(octet);
            octet = 0;
            idx += 1;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
            if (octet > 255) return error.InvalidAddress;
        } else {
            return error.InvalidAddress;
        }
    }
    if (idx != 3) return error.InvalidAddress;
    result[idx] = @intCast(octet);
    return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "deriveKey: HKDF output is deterministic" {
    const key1 = SyncManager.deriveKey("test-secret");
    const key2 = SyncManager.deriveKey("test-secret");
    try std.testing.expectEqualSlices(u8, &key1, &key2);
}

test "deriveKey: different secrets produce different keys" {
    const key1 = SyncManager.deriveKey("secret-a");
    const key2 = SyncManager.deriveKey("secret-b");
    try std.testing.expect(!std.mem.eql(u8, &key1, &key2));
}

test "computePoolHash: identical configs hash identically" {
    const alloc = std.testing.allocator;
    var cfg1 = makeTestConfig(alloc);
    defer cfg1.deinit();
    var cfg2 = makeTestConfig(alloc);
    defer cfg2.deinit();

    const h1 = config_mod.computePoolHash(&cfg1);
    const h2 = config_mod.computePoolHash(&cfg2);
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "computePoolHash: different pool_start produces different hash" {
    const alloc = std.testing.allocator;
    var cfg1 = makeTestConfig(alloc);
    defer cfg1.deinit();
    var cfg2 = makeTestConfig(alloc);
    defer cfg2.deinit();

    // Change pool_start on cfg2
    alloc.free(cfg2.pools[0].pool_start);
    cfg2.pools[0].pool_start = try alloc.dupe(u8, "192.168.1.20");

    const h1 = config_mod.computePoolHash(&cfg1);
    const h2 = config_mod.computePoolHash(&cfg2);
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "encrypt/decrypt round-trip: plaintext survives AES-GCM" {
    const aes_key = SyncManager.deriveKey("round-trip-test");
    const plaintext = "hello sync world";
    var mgr = makeTestManager(aes_key);
    defer mgr.peers.deinit(std.testing.allocator);

    var buf: [256]u8 = undefined;
    const n = mgr.encrypt(.lease_update, plaintext, &buf);
    try std.testing.expect(n != null);

    var plain_buf: [256]u8 = undefined;
    const result = try mgr.decrypt(buf[0..n.?], &plain_buf);
    try std.testing.expectEqualStrings(plaintext, result.plaintext);
    try std.testing.expectEqual(MsgType.lease_update, result.msg_type);
}

test "encrypt/decrypt: empty plaintext" {
    const aes_key = SyncManager.deriveKey("empty-test");
    var mgr = makeTestManager(aes_key);
    defer mgr.peers.deinit(std.testing.allocator);

    var buf: [256]u8 = undefined;
    const n = mgr.encrypt(.keepalive, "", &buf);
    try std.testing.expect(n != null);

    var plain_buf: [256]u8 = undefined;
    const result = try mgr.decrypt(buf[0..n.?], &plain_buf);
    try std.testing.expectEqualStrings("", result.plaintext);
}

test "decrypt rejects tampered ciphertext" {
    const aes_key = SyncManager.deriveKey("tamper-test");
    var mgr = makeTestManager(aes_key);
    defer mgr.peers.deinit(std.testing.allocator);

    var buf: [256]u8 = undefined;
    const n = mgr.encrypt(.lease_update, "data", &buf);
    try std.testing.expect(n != null);

    // Flip a bit in the ciphertext (after AD, before tag)
    buf[ad_size] ^= 0xFF;

    var plain_buf: [256]u8 = undefined;
    try std.testing.expectError(error.AuthFailed, mgr.decrypt(buf[0..n.?], &plain_buf));
}

test "decrypt rejects replayed timestamp" {
    const aes_key = SyncManager.deriveKey("replay-test");
    var mgr = makeTestManager(aes_key);
    defer mgr.peers.deinit(std.testing.allocator);

    var buf: [256]u8 = undefined;
    const n = mgr.encrypt(.lease_update, "data", &buf);
    try std.testing.expect(n != null);

    // Overwrite timestamp with one far in the past (> 300s ago).
    // Timestamp is at bytes 2..10 in the AD header.
    // We must re-encrypt with the fake timestamp so the AEAD tag still verifies.
    // Since we can't forge a valid tag, instead test that a stale timestamp is rejected
    // by directly manipulating the AD bytes and check the anti-replay logic.
    // We simulate this by writing a timestamp 400s in the past into the AD,
    // then re-encrypting (using our own key).
    const stale_ts: i64 = std.time.timestamp() - 400;
    std.mem.writeInt(i64, buf[2..10], stale_ts, .big);
    // Nonce is still valid but AD changed → tag mismatch → AuthFailed
    // But we want to test replay specifically, so re-encrypt with stale timestamp:
    buf[0] = wire_version;
    buf[1] = @intFromEnum(MsgType.lease_update);
    std.mem.writeInt(i64, buf[2..10], stale_ts, .big);
    // nonce already in buf[10..22] — reuse it
    // payload_len already in buf[22..26]
    const nonce: [nonce_size]u8 = buf[10..22].*;
    const payload_len = std.mem.readInt(u32, buf[22..26], .big);
    // Re-encrypt plaintext with stale AD
    const Aes = std.crypto.aead.aes_gcm.Aes256Gcm;
    Aes.encrypt(
        buf[ad_size .. ad_size + payload_len],
        buf[ad_size + payload_len ..][0..tag_size],
        "data",
        buf[0..ad_size],
        nonce,
        aes_key,
    );
    var plain_buf: [256]u8 = undefined;
    try std.testing.expectError(error.ReplayDetected, mgr.decrypt(buf[0..n.?], &plain_buf));
}

test "applyLeaseUpdate: newer last_modified wins" {
    const alloc = std.testing.allocator;
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("lw-test");
    var mgr = makeTestManagerWithStore(aes_key, store);
    defer mgr.peers.deinit(std.testing.allocator);

    // Insert an existing lease with last_modified = 100
    const mac1 = try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff");
    try store.leases.put(
        mac1,
        .{
            .mac = mac1,
            .ip = try alloc.dupe(u8, "192.168.1.10"),
            .hostname = null,
            .expires = std.time.timestamp() + 3600,
            .client_id = null,
            .last_modified = 100,
        },
    );

    // Apply incoming lease with last_modified = 200 (newer)
    const incoming: state_mod.Lease = .{
        .mac = "aa:bb:cc:dd:ee:ff",
        .ip = "192.168.1.11",
        .hostname = null,
        .expires = std.time.timestamp() + 3600,
        .client_id = null,
        .last_modified = 200,
    };
    const json = try std.json.Stringify.valueAlloc(alloc, incoming, .{});
    defer alloc.free(json);
    mgr.applyLeaseUpdate(json);

    const entry = store.leases.get("aa:bb:cc:dd:ee:ff");
    try std.testing.expect(entry != null);
    try std.testing.expectEqualStrings("192.168.1.11", entry.?.ip);
}

test "applyLeaseUpdate: older last_modified discarded" {
    const alloc = std.testing.allocator;
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("lw-old-test");
    var mgr = makeTestManagerWithStore(aes_key, store);
    defer mgr.peers.deinit(std.testing.allocator);

    // Insert existing lease with last_modified = 500
    const mac2 = try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff");
    try store.leases.put(
        mac2,
        .{
            .mac = mac2,
            .ip = try alloc.dupe(u8, "192.168.1.10"),
            .hostname = null,
            .expires = std.time.timestamp() + 3600,
            .client_id = null,
            .last_modified = 500,
        },
    );

    // Apply incoming lease with last_modified = 100 (older — should be discarded)
    const incoming: state_mod.Lease = .{
        .mac = "aa:bb:cc:dd:ee:ff",
        .ip = "192.168.1.99",
        .hostname = null,
        .expires = std.time.timestamp() + 3600,
        .client_id = null,
        .last_modified = 100,
    };
    const json = try std.json.Stringify.valueAlloc(alloc, incoming, .{});
    defer alloc.free(json);
    mgr.applyLeaseUpdate(json);

    const entry = store.leases.get("aa:bb:cc:dd:ee:ff");
    try std.testing.expect(entry != null);
    try std.testing.expectEqualStrings("192.168.1.10", entry.?.ip); // unchanged
}

test "computeLeaseHash: identical stores produce identical hashes" {
    const alloc = std.testing.allocator;
    const store1 = try makeTestStateStore(alloc);
    defer store1.deinit();
    const store2 = try makeTestStateStore(alloc);
    defer store2.deinit();

    // Insert same leases in different order
    const mac_s1a = try alloc.dupe(u8, "aa:bb:cc:dd:ee:01");
    try store1.leases.put(mac_s1a, .{
        .mac = mac_s1a,
        .ip = try alloc.dupe(u8, "192.168.1.10"),
        .hostname = null,
        .expires = 9999,
        .client_id = null,
        .last_modified = 1,
    });
    const mac_s1b = try alloc.dupe(u8, "aa:bb:cc:dd:ee:02");
    try store1.leases.put(mac_s1b, .{
        .mac = mac_s1b,
        .ip = try alloc.dupe(u8, "192.168.1.11"),
        .hostname = null,
        .expires = 9999,
        .client_id = null,
        .last_modified = 2,
    });

    // Insert in reverse order in store2
    const mac_s2b = try alloc.dupe(u8, "aa:bb:cc:dd:ee:02");
    try store2.leases.put(mac_s2b, .{
        .mac = mac_s2b,
        .ip = try alloc.dupe(u8, "192.168.1.11"),
        .hostname = null,
        .expires = 9999,
        .client_id = null,
        .last_modified = 2,
    });
    const mac_s2a = try alloc.dupe(u8, "aa:bb:cc:dd:ee:01");
    try store2.leases.put(mac_s2a, .{
        .mac = mac_s2a,
        .ip = try alloc.dupe(u8, "192.168.1.10"),
        .hostname = null,
        .expires = 9999,
        .client_id = null,
        .last_modified = 1,
    });

    const aes_key = SyncManager.deriveKey("hash-test");
    var mgr1 = makeTestManagerWithStore(aes_key, store1);
    defer mgr1.peers.deinit(std.testing.allocator);
    var mgr2 = makeTestManagerWithStore(aes_key, store2);
    defer mgr2.peers.deinit(std.testing.allocator);

    const h1 = mgr1.computeLeaseHash();
    const h2 = mgr2.computeLeaseHash();
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "computeLeaseHash: adding a lease changes the hash" {
    const alloc = std.testing.allocator;
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("hash-change-test");
    var mgr = makeTestManagerWithStore(aes_key, store);
    defer mgr.peers.deinit(std.testing.allocator);

    const h1 = mgr.computeLeaseHash();

    const mac_h = try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff");
    try store.leases.put(mac_h, .{
        .mac = mac_h,
        .ip = try alloc.dupe(u8, "192.168.1.10"),
        .hostname = null,
        .expires = 9999,
        .client_id = null,
        .last_modified = 1,
    });

    const h2 = mgr.computeLeaseHash();
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn makeTestConfig(alloc: std.mem.Allocator) config_mod.Config {
    const pools = alloc.alloc(config_mod.PoolConfig, 1) catch unreachable;
    pools[0] = config_mod.PoolConfig{
        .subnet = alloc.dupe(u8, "192.168.1.0") catch unreachable,
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = alloc.dupe(u8, "192.168.1.1") catch unreachable,
        .pool_start = alloc.dupe(u8, "192.168.1.10") catch unreachable,
        .pool_end = alloc.dupe(u8, "192.168.1.200") catch unreachable,
        .dns_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .domain_name = alloc.dupe(u8, "") catch unreachable,
        .domain_search = alloc.alloc([]const u8, 0) catch unreachable,
        .lease_time = 3600,
        .time_offset = null,
        .time_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .log_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .ntp_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .mtu = null,
        .wins_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .tftp_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .boot_filename = alloc.dupe(u8, "") catch unreachable,
        .http_boot_url = alloc.dupe(u8, "") catch unreachable,
        .dns_update = .{
            .enable = false,
            .server = alloc.dupe(u8, "") catch unreachable,
            .zone = alloc.dupe(u8, "") catch unreachable,
            .rev_zone = alloc.dupe(u8, "") catch unreachable,
            .key_name = alloc.dupe(u8, "") catch unreachable,
            .key_file = alloc.dupe(u8, "") catch unreachable,
            .lease_time = 3600,
        },
        .dhcp_options = std.StringHashMap([]const u8).init(alloc),
        .reservations = alloc.alloc(config_mod.Reservation, 0) catch unreachable,
        .static_routes = alloc.alloc(config_mod.StaticRoute, 0) catch unreachable,
    };
    return config_mod.Config{
        .allocator = alloc,
        .listen_address = alloc.dupe(u8, "0.0.0.0") catch unreachable,
        .state_dir = alloc.dupe(u8, "/tmp") catch unreachable,
        .log_level = .info,
        .pool_allocation_random = false,
        .sync = null,
        .pools = pools,
        .admin_ssh = .{ .enable = false, .port = 2267, .bind = alloc.dupe(u8, "0.0.0.0") catch unreachable, .read_only = false, .host_key = alloc.dupe(u8, "") catch unreachable, .authorized_keys = alloc.dupe(u8, "") catch unreachable },
        .metrics = .{ .collect = false, .http_enable = false, .http_port = 9167, .http_bind = alloc.dupe(u8, "127.0.0.1") catch unreachable },
    };
}

fn makeTestManager(aes_key: [32]u8) SyncManager {
    return SyncManager{
        .allocator = std.testing.allocator,
        .cfg = undefined,
        .full_cfg = undefined,
        .cfg_path = "",
        .store = undefined,
        .aes_key = aes_key,
        .pool_states = undefined,
        .pool_states_len = 0,
        .self_ip = 0,
        .sock_fd = -1,
        .peers = std.ArrayList(SyncManager.Peer){},
        .last_full_sync = 0,
        .last_keepalive = 0,
        .authenticated_count = std.atomic.Value(u32).init(0),
    };
}

fn makeTestManagerWithStore(aes_key: [32]u8, store: *state_mod.StateStore) SyncManager {
    return SyncManager{
        .allocator = std.testing.allocator,
        .cfg = undefined,
        .full_cfg = undefined,
        .cfg_path = "",
        .store = store,
        .aes_key = aes_key,
        .pool_states = undefined,
        .pool_states_len = 0,
        .self_ip = 0,
        .sock_fd = -1,
        .peers = std.ArrayList(SyncManager.Peer){},
        .last_full_sync = 0,
        .last_keepalive = 0,
        .authenticated_count = std.atomic.Value(u32).init(0),
    };
}

fn makeTestManagerWithCfg(aes_key: [32]u8, full_cfg: *config_mod.Config, store: *state_mod.StateStore) SyncManager {
    var mgr = SyncManager{
        .allocator = std.testing.allocator,
        .cfg = undefined,
        .full_cfg = full_cfg,
        .cfg_path = "",
        .store = store,
        .aes_key = aes_key,
        .pool_states = undefined,
        .pool_states_len = 0,
        .self_ip = 0,
        .sock_fd = -1,
        .peers = std.ArrayList(SyncManager.Peer){},
        .last_full_sync = 0,
        .last_keepalive = 0,
        .authenticated_count = std.atomic.Value(u32).init(0),
    };
    mgr.computeLocalPoolStates();
    return mgr;
}

fn makeTestStateStore(alloc: std.mem.Allocator) !*state_mod.StateStore {
    const store = try alloc.create(state_mod.StateStore);
    store.* = .{
        .allocator = alloc,
        .dir = "/tmp",
        .leases = std.StringHashMap(state_mod.Lease).init(alloc),
    };
    return store;
}

// ---------------------------------------------------------------------------
// Additional tests: parseIpv4Local
// ---------------------------------------------------------------------------

test "parseIpv4Local: valid address parses correctly" {
    const ip = try parseIpv4Local("192.168.1.1");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 1 }, &ip);
}

test "parseIpv4Local: 0.0.0.0 parses correctly" {
    const ip = try parseIpv4Local("0.0.0.0");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, &ip);
}

test "parseIpv4Local: 255.255.255.255 parses correctly" {
    const ip = try parseIpv4Local("255.255.255.255");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 255, 255, 255, 255 }, &ip);
}

test "parseIpv4Local: rejects too few octets" {
    try std.testing.expectError(error.InvalidAddress, parseIpv4Local("192.168.1"));
}

test "parseIpv4Local: rejects empty string" {
    try std.testing.expectError(error.InvalidAddress, parseIpv4Local(""));
}

test "parseIpv4Local: rejects letters" {
    try std.testing.expectError(error.InvalidAddress, parseIpv4Local("not.an.ip.addr"));
}

test "parseIpv4Local: rejects octet out of range" {
    try std.testing.expectError(error.InvalidAddress, parseIpv4Local("256.0.0.1"));
}

test "parseIpv4Local: rejects too many octets" {
    try std.testing.expectError(error.InvalidAddress, parseIpv4Local("1.2.3.4.5"));
}

// ---------------------------------------------------------------------------
// Additional tests: applyLeaseDelete
// ---------------------------------------------------------------------------

test "applyLeaseDelete: removes existing lease" {
    const alloc = std.testing.allocator;
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const mac_del = try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff");
    try store.leases.put(
        mac_del,
        .{
            .mac = mac_del,
            .ip = try alloc.dupe(u8, "192.168.1.10"),
            .hostname = null,
            .expires = std.time.timestamp() + 3600,
            .client_id = null,
        },
    );

    const aes_key = SyncManager.deriveKey("delete-test");
    var mgr = makeTestManagerWithStore(aes_key, store);
    defer mgr.peers.deinit(std.testing.allocator);

    mgr.applyLeaseDelete("aa:bb:cc:dd:ee:ff");
    try std.testing.expect(store.leases.get("aa:bb:cc:dd:ee:ff") == null);
}

test "applyLeaseDelete: no-op for unknown MAC" {
    const alloc = std.testing.allocator;
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("delete-noop-test");
    var mgr = makeTestManagerWithStore(aes_key, store);
    defer mgr.peers.deinit(std.testing.allocator);

    // Should not crash.
    mgr.applyLeaseDelete("de:ad:be:ef:00:01");
    try std.testing.expectEqual(@as(usize, 0), store.leases.count());
}

test "applyLeaseDelete: empty plaintext is a no-op" {
    const alloc = std.testing.allocator;
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("delete-empty-test");
    var mgr = makeTestManagerWithStore(aes_key, store);
    defer mgr.peers.deinit(std.testing.allocator);

    mgr.applyLeaseDelete("");
    try std.testing.expectEqual(@as(usize, 0), store.leases.count());
}

// ---------------------------------------------------------------------------
// Additional tests: computeLeaseHash edge cases
// ---------------------------------------------------------------------------

test "computeLeaseHash: reserved lease (expires=0) is included in hash" {
    const alloc = std.testing.allocator;
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("reserved-hash-test");
    var mgr = makeTestManagerWithStore(aes_key, store);
    defer mgr.peers.deinit(std.testing.allocator);

    const h_before = mgr.computeLeaseHash();

    // Add a reservation with expires=0.
    const mac_res = try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff");
    try store.leases.put(mac_res, .{
        .mac = mac_res,
        .ip = try alloc.dupe(u8, "192.168.1.50"),
        .hostname = null,
        .expires = 0,
        .client_id = null,
        .reserved = true,
    });

    const h_after = mgr.computeLeaseHash();
    try std.testing.expect(!std.mem.eql(u8, &h_before, &h_after));
}

test "computeLeaseHash: expired lease is included in hash" {
    const alloc = std.testing.allocator;
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("expired-hash-test");
    var mgr = makeTestManagerWithStore(aes_key, store);
    defer mgr.peers.deinit(std.testing.allocator);

    const h_before = mgr.computeLeaseHash();

    // Add an already-expired lease (expires in the past).
    const mac_exp = try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff");
    try store.leases.put(mac_exp, .{
        .mac = mac_exp,
        .ip = try alloc.dupe(u8, "192.168.1.10"),
        .hostname = null,
        .expires = 1, // epoch + 1s, definitely expired
        .client_id = null,
    });

    const h_after = mgr.computeLeaseHash();
    try std.testing.expect(!std.mem.eql(u8, &h_before, &h_after));
}

// ---------------------------------------------------------------------------
// Additional tests: encrypt edge cases
// ---------------------------------------------------------------------------

test "encrypt: buffer too small returns null" {
    const aes_key = SyncManager.deriveKey("small-buf-test");
    var mgr = makeTestManager(aes_key);
    defer mgr.peers.deinit(std.testing.allocator);

    // Buffer is smaller than overhead (42 bytes) + plaintext.
    var tiny_buf: [10]u8 = undefined;
    const result = mgr.encrypt(.keepalive, "hello", &tiny_buf);
    try std.testing.expect(result == null);
}

test "encrypt: maximum message type values round-trip" {
    const aes_key = SyncManager.deriveKey("msgtype-test");
    var mgr = makeTestManager(aes_key);
    defer mgr.peers.deinit(std.testing.allocator);

    var buf: [256]u8 = undefined;
    const n = mgr.encrypt(.lease_hash, "a" ** 32, &buf);
    try std.testing.expect(n != null);

    var plain_buf: [256]u8 = undefined;
    const res = try mgr.decrypt(buf[0..n.?], &plain_buf);
    try std.testing.expectEqual(MsgType.lease_hash, res.msg_type);
    try std.testing.expectEqualStrings("a" ** 32, res.plaintext);
}

// ---------------------------------------------------------------------------
// Additional tests: findOrAddPeer peer limit
// ---------------------------------------------------------------------------

test "findOrAddPeer: respects max_peers limit" {
    const alloc = std.testing.allocator;
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("peer-limit-test");
    var mgr = makeTestManagerWithStore(aes_key, store);
    defer mgr.peers.deinit(alloc);

    // Fill up to max_peers.
    var i: u8 = 0;
    while (i < SyncManager.max_peers) : (i += 1) {
        const addr = std.posix.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = 647,
            .addr = std.mem.nativeToBig(u32, @as(u32, 0xC0A80100) + i),
        };
        _ = try mgr.findOrAddPeer(addr);
    }
    try std.testing.expectEqual(@as(usize, SyncManager.max_peers), mgr.peers.items.len);

    // The next peer should be rejected.
    const extra_addr = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = 647,
        .addr = std.mem.nativeToBig(u32, 0xC0A80200),
    };
    try std.testing.expectError(error.TooManyPeers, mgr.findOrAddPeer(extra_addr));
    // List length must not have grown.
    try std.testing.expectEqual(@as(usize, SyncManager.max_peers), mgr.peers.items.len);
}

// ---------------------------------------------------------------------------
// Additional tests: decrypt rejects unknown protocol version
// ---------------------------------------------------------------------------

test "decrypt rejects unknown protocol version" {
    const aes_key = SyncManager.deriveKey("version-test");
    var mgr = makeTestManager(aes_key);
    defer mgr.peers.deinit(std.testing.allocator);

    var buf: [256]u8 = undefined;
    const n = mgr.encrypt(.keepalive, "", &buf);
    try std.testing.expect(n != null);

    // Flip the version byte (buf[0]) to an unknown value.
    buf[0] = 99;

    var plain_buf: [256]u8 = undefined;
    // Tag will fail because AD changed, but we want UnknownVersion from the
    // version check. Either error is acceptable — the packet must be rejected.
    const err = mgr.decrypt(buf[0..n.?], &plain_buf);
    try std.testing.expect(err == error.UnknownVersion or err == error.AuthFailed);
}

// ---------------------------------------------------------------------------
// Per-pool sync protocol (v2) tests
// ---------------------------------------------------------------------------

fn makeTestPeer(ip_u32: u32, authenticated: bool, pool_hashes: []const PeerPoolHash) SyncManager.Peer {
    var peer = SyncManager.Peer{
        .addr = std.posix.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, 647),
            .addr = std.mem.nativeToBig(u32, ip_u32),
        },
        .authenticated = authenticated,
        .last_seen = std.time.timestamp(),
        .last_hello_sent = 0,
        .peer_pool_hashes = undefined,
        .peer_pool_hashes_len = @intCast(pool_hashes.len),
        .peer_ip = ip_u32,
    };
    for (pool_hashes, 0..) |ph, i| {
        peer.peer_pool_hashes[i] = ph;
    }
    return peer;
}

test "reevaluatePoolStates: all match — all enabled" {
    const alloc = std.testing.allocator;
    var cfg = makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("reeval-all-match");
    var mgr = makeTestManagerWithCfg(aes_key, &cfg, store);
    defer mgr.peers.deinit(alloc);

    // Add a peer with the same hash as us
    const our_hash = mgr.pool_states[0].local_hash;
    try mgr.peers.append(alloc, makeTestPeer(0x0A000002, true, &[_]PeerPoolHash{.{
        .subnet_ip = mgr.pool_states[0].subnet_ip,
        .prefix_len = mgr.pool_states[0].prefix_len,
        .hash = our_hash,
    }}));

    mgr.reevaluatePoolStates();

    try std.testing.expect(mgr.pool_states[0].enabled.load(.acquire));
}

test "reevaluatePoolStates: local minority — pool disabled" {
    const alloc = std.testing.allocator;
    var cfg = makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("reeval-minority");
    var mgr = makeTestManagerWithCfg(aes_key, &cfg, store);
    defer mgr.peers.deinit(alloc);

    // Two peers with a different hash
    const different_hash: [32]u8 = [_]u8{0xAB} ** 32;
    try mgr.peers.append(alloc, makeTestPeer(0x0A000002, true, &[_]PeerPoolHash{.{
        .subnet_ip = mgr.pool_states[0].subnet_ip,
        .prefix_len = mgr.pool_states[0].prefix_len,
        .hash = different_hash,
    }}));
    try mgr.peers.append(alloc, makeTestPeer(0x0A000003, true, &[_]PeerPoolHash{.{
        .subnet_ip = mgr.pool_states[0].subnet_ip,
        .prefix_len = mgr.pool_states[0].prefix_len,
        .hash = different_hash,
    }}));

    mgr.reevaluatePoolStates();

    // We are the minority (1 vs 2), so our pool should be disabled
    try std.testing.expect(!mgr.pool_states[0].enabled.load(.acquire));
}

test "reevaluatePoolStates: local majority — pool stays enabled" {
    const alloc = std.testing.allocator;
    var cfg = makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("reeval-majority");
    var mgr = makeTestManagerWithCfg(aes_key, &cfg, store);
    defer mgr.peers.deinit(alloc);
    mgr.self_ip = 0x0A000001; // 10.0.0.1

    const our_hash = mgr.pool_states[0].local_hash;
    const different_hash: [32]u8 = [_]u8{0xCD} ** 32;

    // One peer matches us, one doesn't
    try mgr.peers.append(alloc, makeTestPeer(0x0A000002, true, &[_]PeerPoolHash{.{
        .subnet_ip = mgr.pool_states[0].subnet_ip,
        .prefix_len = mgr.pool_states[0].prefix_len,
        .hash = our_hash,
    }}));
    try mgr.peers.append(alloc, makeTestPeer(0x0A000003, true, &[_]PeerPoolHash{.{
        .subnet_ip = mgr.pool_states[0].subnet_ip,
        .prefix_len = mgr.pool_states[0].prefix_len,
        .hash = different_hash,
    }}));

    mgr.reevaluatePoolStates();

    // We have 2 votes, they have 1 — we should be enabled
    try std.testing.expect(mgr.pool_states[0].enabled.load(.acquire));
}

test "reevaluatePoolStates: tie broken by lowest IP" {
    const alloc = std.testing.allocator;
    var cfg = makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("reeval-tie-break");
    var mgr = makeTestManagerWithCfg(aes_key, &cfg, store);
    defer mgr.peers.deinit(alloc);

    // Set our IP higher than the peer's
    mgr.self_ip = 0x0A000005; // 10.0.0.5

    // One peer with a different hash and lower IP
    const different_hash: [32]u8 = [_]u8{0xEF} ** 32;
    try mgr.peers.append(alloc, makeTestPeer(0x0A000001, true, &[_]PeerPoolHash{.{
        .subnet_ip = mgr.pool_states[0].subnet_ip,
        .prefix_len = mgr.pool_states[0].prefix_len,
        .hash = different_hash,
    }}));

    mgr.reevaluatePoolStates();

    // 1 vote each, peer has lower IP → peer wins → our pool disabled
    try std.testing.expect(!mgr.pool_states[0].enabled.load(.acquire));
}

test "reevaluatePoolStates: tie broken by lowest IP (we win)" {
    const alloc = std.testing.allocator;
    var cfg = makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("reeval-tie-win");
    var mgr = makeTestManagerWithCfg(aes_key, &cfg, store);
    defer mgr.peers.deinit(alloc);

    // Set our IP lower than the peer's
    mgr.self_ip = 0x0A000001; // 10.0.0.1

    // One peer with a different hash and higher IP
    const different_hash: [32]u8 = [_]u8{0xEF} ** 32;
    try mgr.peers.append(alloc, makeTestPeer(0x0A000005, true, &[_]PeerPoolHash{.{
        .subnet_ip = mgr.pool_states[0].subnet_ip,
        .prefix_len = mgr.pool_states[0].prefix_len,
        .hash = different_hash,
    }}));

    mgr.reevaluatePoolStates();

    // 1 vote each, we have lower IP → we win → our pool enabled
    try std.testing.expect(mgr.pool_states[0].enabled.load(.acquire));
}

test "reevaluatePoolStates: pool only on local — always enabled" {
    const alloc = std.testing.allocator;
    var cfg = makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("reeval-local-only");
    var mgr = makeTestManagerWithCfg(aes_key, &cfg, store);
    defer mgr.peers.deinit(alloc);

    // Add an authenticated peer that has NO pools matching ours
    try mgr.peers.append(alloc, makeTestPeer(0x0A000002, true, &[_]PeerPoolHash{}));

    mgr.reevaluatePoolStates();

    // Only we vote, so we win — pool should be enabled
    try std.testing.expect(mgr.pool_states[0].enabled.load(.acquire));
}

test "isPoolEnabled: enabled pool returns true" {
    const alloc = std.testing.allocator;
    var cfg = makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("ispe-enabled");
    var mgr = makeTestManagerWithCfg(aes_key, &cfg, store);
    defer mgr.peers.deinit(alloc);

    // Pool starts enabled
    try std.testing.expect(mgr.isPoolEnabled([4]u8{ 192, 168, 1, 0 }, 24));
}

test "isPoolEnabled: disabled pool returns false" {
    const alloc = std.testing.allocator;
    var cfg = makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("ispe-disabled");
    var mgr = makeTestManagerWithCfg(aes_key, &cfg, store);
    defer mgr.peers.deinit(alloc);

    // Manually disable the pool
    mgr.pool_states[0].enabled.store(false, .release);
    try std.testing.expect(!mgr.isPoolEnabled([4]u8{ 192, 168, 1, 0 }, 24));
}

test "isPoolEnabled: unknown pool returns true (conservative)" {
    const alloc = std.testing.allocator;
    var cfg = makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("ispe-unknown");
    var mgr = makeTestManagerWithCfg(aes_key, &cfg, store);
    defer mgr.peers.deinit(alloc);

    // Query a subnet we don't have
    try std.testing.expect(mgr.isPoolEnabled([4]u8{ 10, 0, 0, 0 }, 8));
}

test "buildHelloPayload v2: verify structure" {
    const alloc = std.testing.allocator;
    var cfg = makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    // Set up a test sync config
    var sync_cfg = config_mod.SyncConfig{
        .enable = true,
        .group_name = "test-group",
        .key_file = "",
        .port = 647,
        .peers = &.{},
        .multicast = null,
        .full_sync_interval = 300,
    };
    const aes_key = SyncManager.deriveKey("hello-v2-test");
    var mgr = makeTestManagerWithCfg(aes_key, &cfg, store);
    mgr.cfg = &sync_cfg;
    defer mgr.peers.deinit(alloc);

    var buf: [SyncManager.hello_max_payload]u8 = undefined;
    const len = mgr.buildHelloPayload(&buf);

    // Version byte
    try std.testing.expectEqual(@as(u8, HELLO_PROTOCOL_VERSION), buf[0]);

    // Group name length
    const gn_len: u8 = buf[1];
    try std.testing.expectEqual(@as(u8, 10), gn_len); // "test-group" = 10 chars

    // Group name
    try std.testing.expectEqualStrings("test-group", buf[2 .. 2 + gn_len]);

    // Pool count
    const pool_count = buf[2 + gn_len];
    try std.testing.expectEqual(@as(u8, 1), pool_count);

    // Expected length: 1 + 1 + 10 + 1 + 1*37 = 50
    try std.testing.expectEqual(@as(usize, 50), len);

    // Subnet IP should be 192.168.1.0
    const off = 2 + @as(usize, gn_len) + 1;
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 0 }, buf[off .. off + 4]);

    // Prefix len should be 24
    try std.testing.expectEqual(@as(u8, 24), buf[off + 4]);
}

test "isIpInDisabledPool: returns false when no pool states" {
    const aes_key = SyncManager.deriveKey("disabled-pool-none");
    var mgr = makeTestManager(aes_key);
    defer mgr.peers.deinit(std.testing.allocator);
    mgr.pool_states_len = 0;

    // Should not crash, and should return false
    try std.testing.expect(!mgr.isIpInDisabledPool("192.168.1.50"));
}

test "isIpInDisabledPool: returns true for IP in disabled pool" {
    const alloc = std.testing.allocator;
    var cfg = makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("disabled-pool-check");
    var mgr = makeTestManagerWithCfg(aes_key, &cfg, store);
    defer mgr.peers.deinit(alloc);

    // Disable the pool
    mgr.pool_states[0].enabled.store(false, .release);

    // IP in the 192.168.1.0/24 subnet should be in a disabled pool
    try std.testing.expect(mgr.isIpInDisabledPool("192.168.1.50"));

    // IP outside the subnet should not be in a disabled pool
    try std.testing.expect(!mgr.isIpInDisabledPool("10.0.0.1"));
}

test "computeLocalPoolStates: produces correct per-pool hashes" {
    const alloc = std.testing.allocator;
    var cfg = makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    const aes_key = SyncManager.deriveKey("pool-states-test");
    var mgr = makeTestManagerWithCfg(aes_key, &cfg, store);
    defer mgr.peers.deinit(alloc);

    try std.testing.expectEqual(@as(u8, 1), mgr.pool_states_len);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 0 }, &mgr.pool_states[0].subnet_ip);
    try std.testing.expectEqual(@as(u8, 24), mgr.pool_states[0].prefix_len);
    try std.testing.expect(mgr.pool_states[0].enabled.load(.acquire));

    // Hash should match what computePerPoolHash returns
    const expected = config_mod.computePerPoolHash(&cfg.pools[0]);
    try std.testing.expectEqualSlices(u8, &expected, &mgr.pool_states[0].local_hash);
}

fn makeTestConfig2Pool(alloc: std.mem.Allocator) config_mod.Config {
    const pools = alloc.alloc(config_mod.PoolConfig, 2) catch unreachable;
    pools[0] = config_mod.PoolConfig{
        .subnet = alloc.dupe(u8, "192.168.1.0") catch unreachable,
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = alloc.dupe(u8, "192.168.1.1") catch unreachable,
        .pool_start = alloc.dupe(u8, "192.168.1.10") catch unreachable,
        .pool_end = alloc.dupe(u8, "192.168.1.200") catch unreachable,
        .dns_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .domain_name = alloc.dupe(u8, "") catch unreachable,
        .domain_search = alloc.alloc([]const u8, 0) catch unreachable,
        .lease_time = 3600,
        .time_offset = null,
        .time_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .log_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .ntp_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .mtu = null,
        .wins_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .tftp_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .boot_filename = alloc.dupe(u8, "") catch unreachable,
        .http_boot_url = alloc.dupe(u8, "") catch unreachable,
        .dns_update = .{
            .enable = false,
            .server = alloc.dupe(u8, "") catch unreachable,
            .zone = alloc.dupe(u8, "") catch unreachable,
            .rev_zone = alloc.dupe(u8, "") catch unreachable,
            .key_name = alloc.dupe(u8, "") catch unreachable,
            .key_file = alloc.dupe(u8, "") catch unreachable,
            .lease_time = 3600,
        },
        .dhcp_options = std.StringHashMap([]const u8).init(alloc),
        .reservations = alloc.alloc(config_mod.Reservation, 0) catch unreachable,
        .static_routes = alloc.alloc(config_mod.StaticRoute, 0) catch unreachable,
    };
    pools[1] = config_mod.PoolConfig{
        .subnet = alloc.dupe(u8, "10.0.0.0") catch unreachable,
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = alloc.dupe(u8, "10.0.0.1") catch unreachable,
        .pool_start = alloc.dupe(u8, "10.0.0.10") catch unreachable,
        .pool_end = alloc.dupe(u8, "10.0.0.200") catch unreachable,
        .dns_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .domain_name = alloc.dupe(u8, "") catch unreachable,
        .domain_search = alloc.alloc([]const u8, 0) catch unreachable,
        .lease_time = 7200,
        .time_offset = null,
        .time_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .log_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .ntp_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .mtu = null,
        .wins_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .tftp_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .boot_filename = alloc.dupe(u8, "") catch unreachable,
        .http_boot_url = alloc.dupe(u8, "") catch unreachable,
        .dns_update = .{
            .enable = false,
            .server = alloc.dupe(u8, "") catch unreachable,
            .zone = alloc.dupe(u8, "") catch unreachable,
            .rev_zone = alloc.dupe(u8, "") catch unreachable,
            .key_name = alloc.dupe(u8, "") catch unreachable,
            .key_file = alloc.dupe(u8, "") catch unreachable,
            .lease_time = 7200,
        },
        .dhcp_options = std.StringHashMap([]const u8).init(alloc),
        .reservations = alloc.alloc(config_mod.Reservation, 0) catch unreachable,
        .static_routes = alloc.alloc(config_mod.StaticRoute, 0) catch unreachable,
    };
    return config_mod.Config{
        .allocator = alloc,
        .listen_address = alloc.dupe(u8, "0.0.0.0") catch unreachable,
        .state_dir = alloc.dupe(u8, "/tmp") catch unreachable,
        .log_level = .info,
        .pool_allocation_random = false,
        .sync = null,
        .pools = pools,
        .admin_ssh = .{ .enable = false, .port = 2267, .bind = alloc.dupe(u8, "0.0.0.0") catch unreachable, .read_only = false, .host_key = alloc.dupe(u8, "") catch unreachable, .authorized_keys = alloc.dupe(u8, "") catch unreachable },
        .metrics = .{ .collect = false, .http_enable = false, .http_port = 9167, .http_bind = alloc.dupe(u8, "127.0.0.1") catch unreachable },
    };
}

test "buildHelloPayload v2: two pools produce correct multi-pool structure" {
    const alloc = std.testing.allocator;
    var cfg = makeTestConfig2Pool(alloc);
    defer cfg.deinit();
    const store = try makeTestStateStore(alloc);
    defer store.deinit();

    var sync_cfg = config_mod.SyncConfig{
        .enable = true,
        .group_name = "multi",
        .key_file = "",
        .port = 647,
        .peers = &.{},
        .multicast = null,
        .full_sync_interval = 300,
    };
    const aes_key = SyncManager.deriveKey("hello-v2-2pool");
    var mgr = makeTestManagerWithCfg(aes_key, &cfg, store);
    mgr.cfg = &sync_cfg;
    defer mgr.peers.deinit(alloc);

    var buf: [SyncManager.hello_max_payload]u8 = undefined;
    const len = mgr.buildHelloPayload(&buf);

    // Version byte
    try std.testing.expectEqual(@as(u8, HELLO_PROTOCOL_VERSION), buf[0]);

    // Group name "multi" = 5 chars
    const gn_len: u8 = buf[1];
    try std.testing.expectEqual(@as(u8, 5), gn_len);
    try std.testing.expectEqualStrings("multi", buf[2 .. 2 + gn_len]);

    // Pool count must be 2
    const pool_count = buf[2 + gn_len];
    try std.testing.expectEqual(@as(u8, 2), pool_count);

    // Expected length: 1 + 1 + 5 + 1 + 2*37 = 82
    try std.testing.expectEqual(@as(usize, 82), len);

    // Pool 0 entry: subnet_ip=192.168.1.0, prefix_len=24
    const off0 = 2 + @as(usize, gn_len) + 1;
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 0 }, buf[off0 .. off0 + 4]);
    try std.testing.expectEqual(@as(u8, 24), buf[off0 + 4]);

    // Pool 1 entry: subnet_ip=10.0.0.0, prefix_len=24, starts 37 bytes after pool 0
    const off1 = off0 + 37;
    try std.testing.expectEqualSlices(u8, &[4]u8{ 10, 0, 0, 0 }, buf[off1 .. off1 + 4]);
    try std.testing.expectEqual(@as(u8, 24), buf[off1 + 4]);

    // Verify hashes match per-pool computation
    const hash0 = config_mod.computePerPoolHash(&cfg.pools[0]);
    try std.testing.expectEqualSlices(u8, &hash0, buf[off0 + 5 .. off0 + 37]);
    const hash1 = config_mod.computePerPoolHash(&cfg.pools[1]);
    try std.testing.expectEqualSlices(u8, &hash1, buf[off1 + 5 .. off1 + 37]);
}
