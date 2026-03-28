/// DHCP Lease Synchronisation (Redundant Server Group)
///
/// Implements the stardust-dhcp-sync-v1 protocol:
///   - UDP datagrams on port 647 (default)
///   - AES-256-GCM payload encryption (key derived via HKDF-SHA-256 from TSIG secret)
///   - SHA-256 pool hash for peer admission control
///   - Last-write-wins conflict resolution via last_modified timestamp on each lease
///
/// Wire format (every datagram):
///   [version:u8=1][type:u8][timestamp:i64][nonce:12][payload_len:u32] — Additional Data (AD)
///   [ciphertext: payload_len bytes]
///   [tag: 16 bytes]
///   Total overhead: 42 bytes
const std = @import("std");
const config_mod = @import("./config.zig");
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
    _,
};

const anti_replay_window: i64 = 300; // seconds

// ---------------------------------------------------------------------------
// SyncManager
// ---------------------------------------------------------------------------

pub const SyncManager = struct {
    allocator: std.mem.Allocator,
    cfg: *const config_mod.SyncConfig,
    store: *state_mod.StateStore,
    aes_key: [32]u8,
    pool_hash: [32]u8,
    sock_fd: std.posix.fd_t,
    peers: std.ArrayList(Peer),
    last_full_sync: i64,
    last_keepalive: i64,

    const max_peers = 8;
    const keepalive_interval_s: i64 = 30;
    const peer_timeout_s: i64 = 90;
    const hello_retry_interval_s: i64 = 30;

    pub const Peer = struct {
        addr: std.posix.sockaddr.in,
        authenticated: bool,
        last_seen: i64,
        last_hello_sent: i64, // for retry logic (unauthenticated peers)
    };

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        cfg: *const config_mod.SyncConfig,
        store: *state_mod.StateStore,
        pool_hash: [32]u8,
    ) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        // Parse TSIG key file and derive AES key via HKDF
        var tsig_key = try dns_mod.parseTsigKey(allocator, cfg.key_file);
        defer tsig_key.deinit();
        const aes_key = deriveKey(tsig_key.secret);

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
            .store = store,
            .aes_key = aes_key,
            .pool_hash = pool_hash,
            .sock_fd = sock_fd,
            .peers = std.ArrayList(Peer){},
            .last_full_sync = 0,
            .last_keepalive = 0,
        };

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

    /// Update pool hash (called on SIGHUP if config changed). Disconnects all
    /// peers so they re-authenticate with the new hash.
    pub fn updatePoolHash(self: *Self, new_hash: [32]u8) void {
        if (std.mem.eql(u8, &new_hash, &self.pool_hash)) return;
        self.pool_hash = new_hash;
        // Remove all authenticated peers; they need to re-handshake.
        for (self.peers.items) |*p| p.authenticated = false;
        self.sendHelloAll();
        std.log.info("sync: pool hash changed, re-authenticating all peers", .{});
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
                    i += 1;
                } else {
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
                var hello_p = self.buildHelloPayload();
                self.sendMsg(mc_addr, .hello, hello_p[0..self.helloPayloadLen()]);
            }
            self.last_keepalive = now;
        }

        // Retry HELLO to unauthenticated unicast peers
        for (self.peers.items) |*p| {
            if (!p.authenticated and now - p.last_hello_sent >= hello_retry_interval_s) {
                var retry_p = self.buildHelloPayload();
                self.sendMsg(p.addr, .hello, retry_p[0..self.helloPayloadLen()]);
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
        var sent: usize = 0;
        for (self.peers.items) |*p| {
            if (p.authenticated) {
                self.sendMsg(p.addr, .lease_update, json);
                sent += 1;
            }
        }
        if (sent > 0) log_v.debug("sync: sent lease update {s} ({s}) to {d} peer(s)", .{
            lease.ip, lease.mac, sent,
        });
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
        const payload = self.buildHelloPayload();
        if (self.cfg.multicast) |mc| {
            const mc_ip = parseIpv4Local(mc) catch return;
            const mc_addr = std.posix.sockaddr.in{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, self.cfg.port),
                .addr = @bitCast(mc_ip),
            };
            self.sendMsg(mc_addr, .hello, &payload);
        }
        for (self.peers.items) |*p| {
            if (!p.authenticated) {
                self.sendMsg(p.addr, .hello, &payload);
                p.last_hello_sent = std.time.timestamp();
            }
        }
    }

    /// Build a HELLO/HELLO_ACK payload: version(u8) group_name_len(u8) group_name pool_hash[32]
    fn buildHelloPayload(self: *Self) [2 + 255 + 32]u8 {
        var payload: [2 + 255 + 32]u8 = undefined;
        payload[0] = wire_version;
        const gn = self.cfg.group_name;
        const gn_len: u8 = @intCast(@min(gn.len, 255));
        payload[1] = gn_len;
        @memcpy(payload[2 .. 2 + gn_len], gn[0..gn_len]);
        @memcpy(payload[2 + gn_len .. 2 + gn_len + 32], &self.pool_hash);
        return payload;
    }

    fn helloPayloadLen(self: *Self) usize {
        return 2 + @min(self.cfg.group_name.len, 255) + 32;
    }

    // -----------------------------------------------------------------------
    // Internal: receive / dispatch
    // -----------------------------------------------------------------------

    fn processRawPacket(self: *Self, raw: []const u8, src: std.posix.sockaddr.in) !void {
        var plain_buf: [8192]u8 = undefined;
        const result = try self.decrypt(raw, &plain_buf);

        switch (result.msg_type) {
            .hello => self.processHello(src, result.plaintext, false),
            .hello_ack => self.processHello(src, result.plaintext, true),
            .hello_nak => self.processHelloNak(src, result.plaintext),
            .lease_update => self.applyLeaseUpdate(result.plaintext),
            .lease_delete => self.applyLeaseDelete(result.plaintext),
            .keepalive => self.updatePeerSeen(src),
            .lease_hash => self.processLeaseHash(src, result.plaintext),
            else => {},
        }
    }

    fn processHello(self: *Self, src: std.posix.sockaddr.in, plaintext: []const u8, is_ack: bool) void {
        if (plaintext.len < 2) return;
        const gn_len = plaintext[1];
        if (plaintext.len < 2 + gn_len + 32) return;
        const group_name = plaintext[2 .. 2 + gn_len];
        const peer_pool_hash = plaintext[2 + gn_len .. 2 + gn_len + 32];

        // Validate group name
        if (!std.mem.eql(u8, group_name, self.cfg.group_name)) {
            std.log.warn("sync: HELLO from wrong group '{f}', sending NAK", .{util.escapedStr(group_name)});
            var nak: [1]u8 = .{@intFromEnum(NakReason.wrong_group)};
            self.sendMsg(src, .hello_nak, &nak);
            return;
        }

        // Validate pool hash
        if (!std.mem.eql(u8, peer_pool_hash, &self.pool_hash)) {
            std.log.warn("sync: HELLO with pool hash mismatch, sending NAK", .{});
            var nak: [1]u8 = .{@intFromEnum(NakReason.pool_hash_mismatch)};
            self.sendMsg(src, .hello_nak, &nak);
            return;
        }

        // Admit or update peer
        const now = std.time.timestamp();
        const peer = self.findOrAddPeer(src) catch return;
        const was_authenticated = peer.authenticated;
        peer.authenticated = true;
        peer.last_seen = now;

        if (!is_ack) {
            // Send HELLO_ACK back
            const payload = self.buildHelloPayload();
            self.sendMsg(src, .hello_ack, payload[0..self.helloPayloadLen()]);
        }

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

        // Last-write-wins: only apply if incoming is newer
        if (self.store.leases.get(incoming.mac)) |existing| {
            if (incoming.last_modified <= existing.last_modified) return;
        }

        self.store.addLease(incoming) catch |err| {
            std.log.warn("sync: failed to apply received lease update: {s}", .{@errorName(err)});
            return;
        };
        log_v.debug("sync: received lease update {s} ({s})", .{ incoming.ip, incoming.mac });
    }

    fn applyLeaseDelete(self: *Self, plaintext: []const u8) void {
        // plaintext is the MAC string (17 bytes "xx:xx:xx:xx:xx:xx")
        if (plaintext.len == 0) return;
        self.store.removeLease(plaintext);
        log_v.debug("sync: received lease delete {s}", .{plaintext});
    }

    fn fullSyncToPeer(self: *Self, peer: *Peer) void {
        const list = self.store.listLeases() catch return;
        defer self.store.allocator.free(list);
        for (list) |lease| {
            const json = std.json.Stringify.valueAlloc(self.allocator, lease, .{}) catch continue;
            defer self.allocator.free(json);
            self.sendMsg(peer.addr, .lease_update, json);
        }
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
    alloc.free(cfg2.pool_start);
    cfg2.pool_start = try alloc.dupe(u8, "192.168.1.20");

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
        buf[ad_size + payload_len .. ad_size + payload_len + tag_size],
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
    try store.leases.put(
        try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff"),
        .{
            .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff"),
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
    try store.leases.put(
        try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff"),
        .{
            .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff"),
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
    try store1.leases.put(try alloc.dupe(u8, "aa:bb:cc:dd:ee:01"), .{
        .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:01"),
        .ip = try alloc.dupe(u8, "192.168.1.10"),
        .hostname = null,
        .expires = 9999,
        .client_id = null,
        .last_modified = 1,
    });
    try store1.leases.put(try alloc.dupe(u8, "aa:bb:cc:dd:ee:02"), .{
        .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:02"),
        .ip = try alloc.dupe(u8, "192.168.1.11"),
        .hostname = null,
        .expires = 9999,
        .client_id = null,
        .last_modified = 2,
    });

    // Insert in reverse order in store2
    try store2.leases.put(try alloc.dupe(u8, "aa:bb:cc:dd:ee:02"), .{
        .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:02"),
        .ip = try alloc.dupe(u8, "192.168.1.11"),
        .hostname = null,
        .expires = 9999,
        .client_id = null,
        .last_modified = 2,
    });
    try store2.leases.put(try alloc.dupe(u8, "aa:bb:cc:dd:ee:01"), .{
        .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:01"),
        .ip = try alloc.dupe(u8, "192.168.1.10"),
        .hostname = null,
        .expires = 9999,
        .client_id = null,
        .last_modified = 1,
    });

    const aes_key = SyncManager.deriveKey("hash-test");
    var mgr1 = makeTestManagerWithStore(aes_key, store1);
    defer mgr1.peers.deinit();
    var mgr2 = makeTestManagerWithStore(aes_key, store2);
    defer mgr2.peers.deinit();

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

    try store.leases.put(try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff"), .{
        .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff"),
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
    return config_mod.Config{
        .allocator = alloc,
        .listen_address = alloc.dupe(u8, "0.0.0.0") catch unreachable,
        .subnet = alloc.dupe(u8, "192.168.1.0") catch unreachable,
        .subnet_mask = 0xFFFFFF00,
        .router = alloc.dupe(u8, "192.168.1.1") catch unreachable,
        .dns_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .domain_name = alloc.dupe(u8, "") catch unreachable,
        .domain_search = alloc.alloc([]const u8, 0) catch unreachable,
        .time_offset = null,
        .time_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .log_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .ntp_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .tftp_server_name = alloc.dupe(u8, "") catch unreachable,
        .boot_filename = alloc.dupe(u8, "") catch unreachable,
        .lease_time = 3600,
        .state_dir = alloc.dupe(u8, "/tmp") catch unreachable,
        .pool_start = alloc.dupe(u8, "192.168.1.10") catch unreachable,
        .pool_end = alloc.dupe(u8, "192.168.1.200") catch unreachable,
        .log_level = .info,
        .dns_update = .{
            .enable = false,
            .server = alloc.dupe(u8, "") catch unreachable,
            .zone = alloc.dupe(u8, "") catch unreachable,
            .key_name = alloc.dupe(u8, "") catch unreachable,
            .key_file = alloc.dupe(u8, "") catch unreachable,
            .lease_time = 3600,
        },
        .dhcp_options = std.StringHashMap([]const u8).init(alloc),
        .reservations = alloc.alloc(config_mod.Reservation, 0) catch unreachable,
        .static_routes = alloc.alloc(config_mod.StaticRoute, 0) catch unreachable,
        .pool_allocation_random = false,
        .sync = null,
    };
}

fn makeTestManager(aes_key: [32]u8) SyncManager {
    return SyncManager{
        .allocator = std.testing.allocator,
        .cfg = undefined,
        .store = undefined,
        .aes_key = aes_key,
        .pool_hash = [_]u8{0} ** 32,
        .sock_fd = -1,
        .peers = std.ArrayList(SyncManager.Peer){},
        .last_full_sync = 0,
        .last_keepalive = 0,
    };
}

fn makeTestManagerWithStore(aes_key: [32]u8, store: *state_mod.StateStore) SyncManager {
    return SyncManager{
        .allocator = std.testing.allocator,
        .cfg = undefined,
        .store = store,
        .aes_key = aes_key,
        .pool_hash = [_]u8{0} ** 32,
        .sock_fd = -1,
        .peers = std.ArrayList(SyncManager.Peer){},
        .last_full_sync = 0,
        .last_keepalive = 0,
    };
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

    try store.leases.put(
        try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff"),
        .{
            .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff"),
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
    try store.leases.put(try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff"), .{
        .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff"),
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
    try store.leases.put(try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff"), .{
        .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff"),
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
