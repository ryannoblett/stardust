const std = @import("std");
const config_mod = @import("./config.zig");
const state_mod = @import("./state.zig");
const dns_mod = @import("./dns.zig");
const probe_mod = @import("./probe.zig");

pub const Config = config_mod.Config;
pub const StateStore = state_mod.StateStore;

pub const Error = error{
    SocketError,
    IoError,
    InvalidRequest,
    OutOfMemory,
};

// ---------------------------------------------------------------------------
// DHCP message types (RFC 2132 option 53)
// ---------------------------------------------------------------------------

pub const MessageType = enum(u8) {
    DHCPDISCOVER = 1,
    DHCPOFFER = 2,
    DHCPREQUEST = 3,
    DHCPDECLINE = 4,
    DHCPACK = 5,
    DHCPNAK = 6,
    DHCPRELEASE = 7,
    DHCPINFORM = 8,
    _,
};

// ---------------------------------------------------------------------------
// DHCP packet header (RFC 2131)
// ---------------------------------------------------------------------------

pub const DHCPHeader = extern struct {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: [4]u8,
    yiaddr: [4]u8,
    siaddr: [4]u8,
    giaddr: [4]u8,
    chaddr: [16]u8,
    sname: [64]u8,
    file: [128]u8,
    magic: [4]u8,
};

pub const dhcp_magic_cookie = [4]u8{ 99, 130, 83, 99 };
pub const dhcp_min_packet_size = @sizeOf(DHCPHeader);
pub const dhcp_options_offset = 236; // header without magic
pub const dhcp_server_port: u16 = 67;
pub const dhcp_client_port: u16 = 68;

// ---------------------------------------------------------------------------
// DHCP option codes (partial list, RFC 2132)
// ---------------------------------------------------------------------------

pub const OptionCode = enum(u8) {
    Pad = 0,
    SubnetMask = 1,
    Router = 3,
    DomainNameServer = 6,
    HostName = 12,
    DomainName = 15,
    RequestedIPAddress = 50,
    IPAddressLeaseTime = 51,
    MessageType = 53,
    ServerIdentifier = 54,
    ParameterRequestList = 55,
    RenewalTimeValue = 58,
    RebindingTimeValue = 59,
    ClientID = 61,
    RelayAgentInformation = 82,
    End = 255,
    _,
};

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

var g_running: ?*std.atomic.Value(bool) = null;

fn handleSignal(sig: c_int) callconv(.c) void {
    _ = sig;
    if (g_running) |r| r.store(false, .seq_cst);
}

/// UDP connect trick: connecting a datagram socket to an external address causes
/// the kernel to select the outbound interface; getsockname returns that local IP.
fn probeServerIp() ?[4]u8 {
    const sock = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch return null;
    defer std.posix.close(sock);
    const dst = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 53),
        .addr = @bitCast([4]u8{ 8, 8, 8, 8 }),
    };
    std.posix.connect(sock, @ptrCast(&dst), @sizeOf(std.posix.sockaddr.in)) catch return null;
    var local: std.posix.sockaddr.in = undefined;
    var local_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
    std.posix.getsockname(sock, @ptrCast(&local), &local_len) catch return null;
    const ip: [4]u8 = @bitCast(local.addr);
    if (std.mem.eql(u8, &ip, &[4]u8{ 0, 0, 0, 0 })) return null;
    return ip;
}

/// Compute the send destination for a DHCP response from the originating request.
/// RFC 2131 §4.1 routing rules, in priority order:
///   1. giaddr != 0  → relay agent at giaddr:67 (server port)
///   2. ciaddr != 0  → renewing client at ciaddr:68 (unicast)
///   3. broadcast bit (flags bit 15) set → 255.255.255.255:68
///   4. else         → 255.255.255.255:68 (broadcast fallback; ARP unicast not implemented)
fn resolveDestination(request: []const u8) std.posix.sockaddr.in {
    if (request.len >= dhcp_min_packet_size) {
        const req: *const DHCPHeader = @alignCast(@ptrCast(request.ptr));

        if (!std.mem.eql(u8, &req.giaddr, &[_]u8{ 0, 0, 0, 0 })) {
            return .{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, dhcp_server_port),
                .addr = @bitCast(req.giaddr),
            };
        }

        if (!std.mem.eql(u8, &req.ciaddr, &[_]u8{ 0, 0, 0, 0 })) {
            return .{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, dhcp_client_port),
                .addr = @bitCast(req.ciaddr),
            };
        }

        // flags is in the packet in network byte order; nativeToBig reinterprets
        // the LE u16 so bit 15 (broadcast) maps to 0x8000.
        if (std.mem.nativeToBig(u16, req.flags) & 0x8000 != 0) {
            return .{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, dhcp_client_port),
                .addr = 0xFFFFFFFF,
            };
        }
    }

    // Fallback: broadcast. ARP unicast to yiaddr is not implemented.
    return .{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, dhcp_client_port),
        .addr = 0xFFFFFFFF,
    };
}

/// Encode an option value string into DHCP wire bytes in dst.
/// Tries comma-separated IPv4 addresses first; falls back to raw string bytes.
fn encodeOptionValue(dst: []u8, s: []const u8) []u8 {
    var len: usize = 0;
    var all_valid = true;
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |tok| {
        const trimmed = std.mem.trim(u8, tok, " ");
        const ip = config_mod.parseIpv4(trimmed) catch {
            all_valid = false;
            break;
        };
        if (len + 4 > dst.len) { all_valid = false; break; }
        @memcpy(dst[len .. len + 4], &ip);
        len += 4;
    }
    if (len > 0 and all_valid) return dst[0..len]; // all tokens were valid IPs
    // Fall back to raw string bytes
    const copy_len = @min(s.len, dst.len);
    @memcpy(dst[0..copy_len], s[0..copy_len]);
    return dst[0..copy_len];
}

/// Returns true if `code` appears in the Parameter Request List, or true if no PRL was sent.
/// Per RFC 2132 §9.8, options 53 (MessageType) and 54 (ServerIdentifier) are always included.
fn isRequestedCode(prl: ?[]const u8, code: u8) bool {
    const list = prl orelse return true;
    for (list) |c| {
        if (c == code) return true;
    }
    return false;
}

fn isRequested(prl: ?[]const u8, code: OptionCode) bool {
    return isRequestedCode(prl, @intFromEnum(code));
}

// Per-MAC decline rate-limiting: after decline_threshold declines within decline_window_secs,
// the MAC is refused new allocations for decline_cooldown_secs.
const decline_threshold: u32 = 3;
const decline_window_secs: i64 = 60;
const decline_cooldown_secs: i64 = 300; // 5 minutes

// Global decline rate limit: cap the total number of DHCPDECLINEs processed
// (across all MACs) within a sliding 5-minute window. An attacker rotating
// spoofed MACs can quarantine at most this many IPs simultaneously, since the
// quarantine period is also 5 minutes. Value chosen so a relay server handling
// many pools never triggers this in normal conditions (real-world decline rates
// are single digits per day), while capping steady-state quarantine damage to
// a small fraction of even a modest pool.
const global_decline_limit: u32 = 20;
const global_decline_window_secs: i64 = 300; // 5 minutes

const DeclineRecord = struct {
    count: u32,
    window_start: i64,
    cooldown_until: i64, // 0 = not in cooldown
};

pub const DHCPServer = struct {
    allocator: std.mem.Allocator,
    cfg: *const Config,
    store: *StateStore,
    dns_updater: ?*dns_mod.DNSUpdater,
    running: std.atomic.Value(bool),
    last_prune: i64,
    server_ip: [4]u8,
    /// Keyed by MAC as a fixed [17]u8 ("xx:xx:xx:xx:xx:xx") — no heap alloc per entry.
    decline_records: std.AutoHashMap([17]u8, DeclineRecord),
    global_decline_count: u32,
    global_decline_window_start: i64,
    /// Interface info for ARP probing. Null when not detected (probe falls back to ICMP).
    if_info: ?probe_mod.IfaceInfo,

    const Self = @This();

    pub fn create(
        allocator: std.mem.Allocator,
        cfg: *const Config,
        store: *StateStore,
        dns_updater: ?*dns_mod.DNSUpdater,
    ) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .cfg = cfg,
            .store = store,
            .dns_updater = dns_updater,
            .running = std.atomic.Value(bool).init(false),
            .last_prune = 0,
            // Pre-populate from listen_address so callers that don't call run() still
            // get a useful server_ip. run() will overwrite this with the detected IP.
            .server_ip = config_mod.parseIpv4(cfg.listen_address) catch [4]u8{ 0, 0, 0, 0 },
            .decline_records = std.AutoHashMap([17]u8, DeclineRecord).init(allocator),
            .global_decline_count = 0,
            .global_decline_window_start = 0,
            .if_info = null,
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.decline_records.deinit();
        self.allocator.destroy(self);
    }

    /// Main server loop. Binds a UDP socket on port 67 and processes packets.
    pub fn run(self: *Self) !void {

        self.running.store(true, .seq_cst);
        defer self.running.store(false, .seq_cst);

        g_running = &self.running;
        defer g_running = null;

        const sig_action = std.posix.Sigaction{
            .handler = .{ .handler = handleSignal },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(std.posix.SIG.INT, &sig_action, null);
        std.posix.sigaction(std.posix.SIG.TERM, &sig_action, null);

        // Parse listen address
        const listen_ip = try config_mod.parseIpv4(self.cfg.listen_address);

        // Bind UDP socket
        const sock_fd = try std.posix.socket(
            std.posix.AF.INET,
            std.posix.SOCK.DGRAM,
            std.posix.IPPROTO.UDP,
        );
        defer std.posix.close(sock_fd);

        // SO_REUSEADDR
        try std.posix.setsockopt(
            sock_fd,
            std.posix.SOL.SOCKET,
            std.posix.SO.REUSEADDR,
            &std.mem.toBytes(@as(c_int, 1)),
        );

        // SO_BROADCAST — required to send to 255.255.255.255
        try std.posix.setsockopt(
            sock_fd,
            std.posix.SOL.SOCKET,
            std.posix.SO.BROADCAST,
            &std.mem.toBytes(@as(c_int, 1)),
        );

        // SO_RCVTIMEO — 1-second timeout so the run loop can check the running
        // flag after a signal sets it to false (Zig's posix wrapper retries
        // recvfrom on EINTR, so a signal alone would not unblock the call).
        const rcv_timeout = std.posix.timeval{ .sec = 1, .usec = 0 };
        try std.posix.setsockopt(
            sock_fd,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            &std.mem.toBytes(rcv_timeout),
        );

        const bind_addr = std.posix.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, dhcp_server_port),
            .addr = @bitCast(listen_ip),
        };
        try std.posix.bind(
            sock_fd,
            @ptrCast(&bind_addr),
            @sizeOf(std.posix.sockaddr.in),
        );

        self.server_ip = listen_ip;
        if (std.mem.eql(u8, &listen_ip, &[4]u8{ 0, 0, 0, 0 })) {
            if (probeServerIp()) |detected| {
                self.server_ip = detected;
                std.log.info("Detected server IP: {d}.{d}.{d}.{d}", .{
                    detected[0], detected[1], detected[2], detected[3],
                });
            } else {
                std.log.warn("Could not detect server IP for 0.0.0.0 listener", .{});
            }
        }

        // Detect the outbound interface for ARP conflict probing on local networks.
        self.if_info = probe_mod.findIfaceForIp(self.server_ip) catch |err| blk: {
            std.log.warn("Could not detect network interface ({s}); ARP probing disabled", .{@errorName(err)});
            break :blk null;
        };
        if (self.if_info) |info| {
            std.log.info("Interface for ARP probe: index={d}, mac={x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
                info.index,
                info.mac[0], info.mac[1], info.mac[2],
                info.mac[3], info.mac[4], info.mac[5],
            });
        }

        std.log.info("DHCP server listening on {s}:{d}", .{
            self.cfg.listen_address,
            dhcp_server_port,
        });

        var buf: [1500]u8 = undefined;
        var src_addr: std.posix.sockaddr.in = undefined;
        var src_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);

        while (self.running.load(.seq_cst)) {
            const n = std.posix.recvfrom(
                sock_fd,
                &buf,
                0,
                @ptrCast(&src_addr),
                &src_len,
            ) catch |err| {
                switch (err) {
                    error.WouldBlock => {}, // SO_RCVTIMEO expired — just re-check running flag
                    else => std.log.err("recvfrom error: {s}", .{@errorName(err)}),
                }
                continue;
            };

            const packet = buf[0..n];

            const now_ts = std.time.timestamp();
            if (now_ts - self.last_prune > 60) {
                self.pruneExpiredWithDns();
                self.last_prune = now_ts;
            }

            const response = self.processPacket(packet) catch |err| {
                std.log.err("Error processing packet: {s}", .{@errorName(err)});
                continue;
            };

            if (response) |resp| {
                defer self.allocator.free(resp);

                const dst_addr = resolveDestination(packet);
                _ = std.posix.sendto(
                    sock_fd,
                    resp,
                    0,
                    @ptrCast(&dst_addr),
                    @sizeOf(std.posix.sockaddr.in),
                ) catch |err| {
                    std.log.err("sendto error: {s}", .{@errorName(err)});
                };
            }
        }

        std.log.info("DHCP server stopped", .{});
    }

    /// Prune expired leases and send DNS delete updates for any that had hostnames.
    /// Must not be called while iterating self.store.leases.
    fn pruneExpiredWithDns(self: *Self) void {
        const now = std.time.timestamp();

        // Collect expired MACs first — cannot remove entries while iterating the map.
        var to_remove: [64][]const u8 = undefined;
        var count: usize = 0;
        var it = self.store.leases.keyIterator();
        while (it.next()) |key| {
            const lease = self.store.leases.get(key.*).?;
            if (lease.reserved) continue;
            if (lease.expires <= now and count < to_remove.len) {
                to_remove[count] = key.*;
                count += 1;
            }
        }

        // Notify DNS before removing so the lease strings are still valid.
        for (to_remove[0..count]) |mac| {
            if (self.store.leases.get(mac)) |lease| {
                if (self.dns_updater) |du| {
                    du.notifyLeaseRemoved(lease.ip, lease.hostname);
                }
            }
            self.store.removeLease(mac);
        }
    }


    fn processPacket(self: *Self, packet: []const u8) !?[]u8 {
        if (packet.len < dhcp_min_packet_size) return null;

        // Safety: packet is at least dhcp_min_packet_size bytes, and DHCPHeader
        // is an extern struct so alignment is 1.
        const header: *const DHCPHeader = @alignCast(@ptrCast(packet.ptr));

        if (!std.mem.eql(u8, &header.magic, &dhcp_magic_cookie)) return null;

        const msg_type = getMessageType(packet) orelse return null;

        return switch (msg_type) {
            .DHCPDISCOVER => self.createOffer(packet),
            .DHCPREQUEST => self.createAck(packet),
            .DHCPRELEASE => blk: {
                self.handleRelease(packet);
                break :blk null;
            },
            .DHCPDECLINE => blk: {
                self.handleDecline(packet);
                break :blk null;
            },
            .DHCPINFORM => self.handleInform(packet),
            else => null,
        };
    }

    /// Scan DHCP options for the first occurrence of `target`. Returns the value slice or null.
    fn getOption(packet: []const u8, target: OptionCode) ?[]const u8 {
        if (packet.len < dhcp_min_packet_size) return null;
        const opts = packet[dhcp_min_packet_size..];
        var i: usize = 0;
        while (i + 1 < opts.len) {
            const code = opts[i];
            if (code == @intFromEnum(OptionCode.End)) break;
            if (code == @intFromEnum(OptionCode.Pad)) {
                i += 1;
                continue;
            }
            const len = opts[i + 1];
            if (i + 2 + len > opts.len) break;
            if (code == @intFromEnum(target)) return opts[i + 2 .. i + 2 + len];
            i += 2 + len;
        }
        return null;
    }

    fn getMessageType(packet: []const u8) ?MessageType {
        const val = getOption(packet, .MessageType) orelse return null;
        if (val.len < 1) return null;
        return @enumFromInt(val[0]);
    }

    /// Scan the subnet for an unallocated host address to offer.
    ///
    /// Returns the first host address in the subnet that has no active lease,
    /// skipping the router and (if specific) the server's own address.
    /// Returns null when the pool is exhausted.
    fn allocateIp(self: *Self, mac_bytes: [6]u8, client_id: ?[]const u8) !?[4]u8 {
        var mac_buf: [17]u8 = undefined;
        const mac_str = std.fmt.bufPrint(&mac_buf, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
            mac_bytes[0], mac_bytes[1], mac_bytes[2],
            mac_bytes[3], mac_bytes[4], mac_bytes[5],
        }) catch unreachable;

        // Refuse allocation if this MAC is in a decline cooldown period.
        if (self.decline_records.get(mac_buf)) |rec| {
            if (std.time.timestamp() < rec.cooldown_until) {
                std.log.warn("Refusing allocation to {s}: in decline cooldown for {d}s", .{
                    mac_str, rec.cooldown_until - std.time.timestamp(),
                });
                return null;
            }
        }

        // Reuse an existing confirmed lease for this client.
        // Client identifier (option 61) takes precedence over chaddr per RFC 2131 §2.
        if (client_id) |cid| {
            var cid_hex_buf: [510]u8 = undefined;
            const cid_hex = std.fmt.bufPrint(&cid_hex_buf, "{x}", .{cid}) catch "";
            if (cid_hex.len > 0) {
                if (self.store.getLeaseByClientId(cid_hex)) |lease| {
                    return try config_mod.parseIpv4(lease.ip);
                }
            }
        }
        if (self.store.getLeaseByMac(mac_str)) |lease| {
            return try config_mod.parseIpv4(lease.ip);
        }

        // Check for a reservation for this client (ignores expiry).
        if (client_id) |cid| {
            var cid_hex_buf2: [510]u8 = undefined;
            const cid_hex2 = std.fmt.bufPrint(&cid_hex_buf2, "{x}", .{cid}) catch "";
            if (cid_hex2.len > 0) {
                if (self.store.getReservationByClientId(cid_hex2)) |res|
                    return try config_mod.parseIpv4(res.ip);
            }
        }
        if (self.store.getReservationByMac(mac_str)) |res|
            return try config_mod.parseIpv4(res.ip);

        const subnet_bytes = try config_mod.parseIpv4(self.cfg.subnet);
        const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
        const mask = self.cfg.subnet_mask;
        const broadcast_int = subnet_int | ~mask;

        const router_bytes = try config_mod.parseIpv4(self.cfg.router);
        const router_int = std.mem.readInt(u32, &router_bytes, .big);

        const server_bytes = try config_mod.parseIpv4(self.cfg.listen_address);
        const server_int = std.mem.readInt(u32, &server_bytes, .big);

        var pool_start_int: u32 = subnet_int + 1;
        var pool_end_int: u32 = broadcast_int - 1;
        if (self.cfg.pool_start.len > 0) {
            const b = config_mod.parseIpv4(self.cfg.pool_start) catch blk: {
                break :blk subnet_bytes;
            };
            pool_start_int = std.mem.readInt(u32, &b, .big);
        }
        if (self.cfg.pool_end.len > 0) {
            const b = config_mod.parseIpv4(self.cfg.pool_end) catch blk: {
                break :blk subnet_bytes;
            };
            pool_end_int = std.mem.readInt(u32, &b, .big);
        }

        var candidate: u32 = pool_start_int;
        while (candidate <= pool_end_int) : (candidate += 1) {
            if (candidate == router_int) continue;
            if (server_int != 0 and candidate == server_int) continue;

            var ip_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &ip_bytes, candidate, .big);
            var ip_buf: [15]u8 = undefined;
            const ip_str = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{
                ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
            }) catch unreachable;

            // Skip IPs reserved for a different client.
            if (self.store.getReservationByIp(ip_str) != null) continue;

            if (self.store.getLeaseByIp(ip_str) == null) return ip_bytes;
        }

        return null; // Pool exhausted.
    }

    /// Build a DHCPOFFER in response to a DHCPDISCOVER.
    ///
    /// Allocates and returns a packet buffer; caller is responsible for freeing.
    /// Returns null if no address is available to offer.
    /// Returns true if `ip` appears to be in use on the network.
    /// Uses ARP for locally-attached networks (giaddr==0), ICMP for relayed.
    /// On any probe error, returns false (false negatives preferred over blocking).
    fn probeConflict(self: *Self, ip: [4]u8, is_relayed: bool) bool {
        if (is_relayed) {
            return probe_mod.icmpProbe(ip) catch false;
        } else {
            const info = self.if_info orelse return false;
            return probe_mod.arpProbe(info.mac, info.index, ip) catch false;
        }
    }

    /// Quarantine a conflict-detected IP using the same sentinel-MAC mechanism
    /// as DHCPDECLINE, so allocateIp skips it on the next attempt.
    fn quarantineProbeConflict(self: *Self, ip: [4]u8) void {
        var ip_buf: [15]u8 = undefined;
        const ip_str = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{
            ip[0], ip[1], ip[2], ip[3],
        }) catch return;
        var mac_buf: [24]u8 = undefined;
        const conflict_mac = std.fmt.bufPrint(&mac_buf, "conflict:{s}", .{ip_str}) catch return;
        self.store.addLease(.{
            .mac = conflict_mac,
            .ip = ip_str,
            .hostname = null,
            .expires = std.time.timestamp() + probe_mod.probe_quarantine_secs,
            .client_id = null,
        }) catch {};
        std.log.warn("Probe conflict: {s} is already in use, quarantining for {d}s", .{
            ip_str, probe_mod.probe_quarantine_secs,
        });
    }

    fn createOffer(self: *Self, request: []const u8) !?[]u8 {
        const req_header: *const DHCPHeader = @alignCast(@ptrCast(request.ptr));

        const mac_bytes: [6]u8 = req_header.chaddr[0..6].*;
        const client_id_raw = getClientId(request);

        // giaddr != 0 means the DISCOVER came through a relay agent.
        const is_relayed = !std.mem.eql(u8, &req_header.giaddr, &[_]u8{ 0, 0, 0, 0 });

        // Probe up to probe_max_tries candidates. On conflict, quarantine the IP
        // (so allocateIp skips it next iteration) and try again.
        const offered_ip = blk: {
            for (0..probe_mod.probe_max_tries) |_| {
                const candidate = (try self.allocateIp(mac_bytes, client_id_raw)) orelse break :blk null;
                if (!self.probeConflict(candidate, is_relayed)) break :blk candidate;
                self.quarantineProbeConflict(candidate);
            }
            break :blk null;
        } orelse return null;

        logRelayAgentInfo(request);

        const prl = getOption(request, .ParameterRequestList);
        const server_ip = self.server_ip;
        const subnet_mask = std.mem.toBytes(std.mem.nativeToBig(u32, self.cfg.subnet_mask));
        const router_ip = try config_mod.parseIpv4(self.cfg.router);
        const lease_time = std.mem.toBytes(std.mem.nativeToBig(u32, self.cfg.lease_time));
        const renewal_time = std.mem.toBytes(std.mem.nativeToBig(u32, self.cfg.lease_time / 2));
        const rebind_time = std.mem.toBytes(std.mem.nativeToBig(u32, self.cfg.lease_time * 7 / 8));

        // Build options into a temporary buffer
        var opts_buf: [512]u8 = undefined;
        var opts_len: usize = 0;

        // Option 53: DHCPOFFER — always required
        opts_buf[opts_len] = @intFromEnum(OptionCode.MessageType);
        opts_buf[opts_len + 1] = 1;
        opts_buf[opts_len + 2] = @intFromEnum(MessageType.DHCPOFFER);
        opts_len += 3;

        // Option 54: Server Identifier — always required
        opts_buf[opts_len] = @intFromEnum(OptionCode.ServerIdentifier);
        opts_buf[opts_len + 1] = 4;
        @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &server_ip);
        opts_len += 6;

        // Option 51: IP Address Lease Time
        if (isRequested(prl, .IPAddressLeaseTime)) {
            opts_buf[opts_len] = @intFromEnum(OptionCode.IPAddressLeaseTime);
            opts_buf[opts_len + 1] = 4;
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &lease_time);
            opts_len += 6;
        }

        // Option 58: Renewal Time
        if (isRequested(prl, .RenewalTimeValue)) {
            opts_buf[opts_len] = @intFromEnum(OptionCode.RenewalTimeValue);
            opts_buf[opts_len + 1] = 4;
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &renewal_time);
            opts_len += 6;
        }

        // Option 59: Rebinding Time
        if (isRequested(prl, .RebindingTimeValue)) {
            opts_buf[opts_len] = @intFromEnum(OptionCode.RebindingTimeValue);
            opts_buf[opts_len + 1] = 4;
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &rebind_time);
            opts_len += 6;
        }

        // Option 1: Subnet Mask
        if (isRequested(prl, .SubnetMask)) {
            opts_buf[opts_len] = @intFromEnum(OptionCode.SubnetMask);
            opts_buf[opts_len + 1] = 4;
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &subnet_mask);
            opts_len += 6;
        }

        // Option 3: Router
        if (isRequested(prl, .Router)) {
            opts_buf[opts_len] = @intFromEnum(OptionCode.Router);
            opts_buf[opts_len + 1] = 4;
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &router_ip);
            opts_len += 6;
        }

        // Option 6: DNS Servers (up to 4)
        if (isRequested(prl, .DomainNameServer) and self.cfg.dns_servers.len > 0) {
            const count = @min(self.cfg.dns_servers.len, 4);
            opts_buf[opts_len] = @intFromEnum(OptionCode.DomainNameServer);
            opts_buf[opts_len + 1] = @intCast(count * 4);
            opts_len += 2;
            for (self.cfg.dns_servers[0..count]) |dns_str| {
                const dns_ip = config_mod.parseIpv4(dns_str) catch continue;
                @memcpy(opts_buf[opts_len .. opts_len + 4], &dns_ip);
                opts_len += 4;
            }
        }

        // Option 15: Domain Name
        if (isRequested(prl, .DomainName) and self.cfg.domain_name.len > 0) {
            const dn_len = @min(self.cfg.domain_name.len, 255);
            opts_buf[opts_len] = @intFromEnum(OptionCode.DomainName);
            opts_buf[opts_len + 1] = @intCast(dn_len);
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 2 + dn_len], self.cfg.domain_name[0..dn_len]);
            opts_len += 2 + dn_len;
        }

        // Inject operator-defined options from config (filtered by PRL)
        var opts_it = self.cfg.dhcp_options.iterator();
        while (opts_it.next()) |entry| {
            const code = std.fmt.parseInt(u8, entry.key_ptr.*, 10) catch continue;
            if (!isRequestedCode(prl, code)) continue;
            const encoded = encodeOptionValue(opts_buf[opts_len + 2 ..], entry.value_ptr.*);
            if (encoded.len > 255 or opts_len + 2 + encoded.len > opts_buf.len - 1) continue;
            opts_buf[opts_len] = code;
            opts_buf[opts_len + 1] = @intCast(encoded.len);
            opts_len += 2 + encoded.len;
        }

        // End
        opts_buf[opts_len] = @intFromEnum(OptionCode.End);
        opts_len += 1;

        // Allocate response packet
        const pkt_len = dhcp_min_packet_size + opts_len;
        const pkt = try self.allocator.alloc(u8, pkt_len);
        @memset(pkt, 0);

        // Fill header from request
        const resp_header: *DHCPHeader = @alignCast(@ptrCast(pkt.ptr));
        resp_header.op = 2; // BOOTREPLY
        resp_header.htype = req_header.htype;
        resp_header.hlen = req_header.hlen;
        resp_header.hops = req_header.hops;
        resp_header.xid = req_header.xid;
        resp_header.secs = 0;
        resp_header.flags = req_header.flags;
        resp_header.ciaddr = [_]u8{0} ** 4;
        resp_header.yiaddr = offered_ip;
        resp_header.siaddr = server_ip;
        resp_header.giaddr = req_header.giaddr;
        resp_header.chaddr = req_header.chaddr;
        resp_header.magic = dhcp_magic_cookie;

        @memcpy(pkt[dhcp_min_packet_size .. dhcp_min_packet_size + opts_len], opts_buf[0..opts_len]);

        return pkt;
    }

    /// Build a DHCPACK in response to a DHCPREQUEST.
    ///
    /// Allocates and returns a packet buffer; caller is responsible for freeing.
    /// Returns null if the request is directed at another server.
    /// Returns a DHCPNAK packet if the requested IP is invalid.
    fn createAck(self: *Self, request: []const u8) !?[]u8 {
        const req_header: *const DHCPHeader = @alignCast(@ptrCast(request.ptr));

        // Option 54: ignore requests directed at a different server.
        if (getServerIdentifier(request)) |sid| {
            if (!std.mem.eql(u8, &sid, &self.server_ip)) return null;
        }

        // The client's requested IP comes from option 50, or ciaddr for renewals.
        const client_ip = getRequestedIp(request) orelse req_header.ciaddr;

        // Format MAC string and extract client_id — both needed for IP validation.
        const mac_bytes = req_header.chaddr[0..6];
        var mac_str_buf: [17]u8 = undefined;
        const mac_str = std.fmt.bufPrint(&mac_str_buf, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
            mac_bytes[0], mac_bytes[1], mac_bytes[2],
            mac_bytes[3], mac_bytes[4], mac_bytes[5],
        }) catch unreachable;

        const client_id_raw = getClientId(request);
        var cid_hex_buf: [510]u8 = undefined;
        const client_id_hex: ?[]const u8 = if (client_id_raw) |cid|
            std.fmt.bufPrint(&cid_hex_buf, "{x}", .{cid}) catch null
        else
            null;

        // Send DHCPNAK if the requested IP is not valid for our subnet.
        if (!self.isIpValid(client_ip, mac_str, client_id_hex)) return self.createNak(request);

        const server_ip = self.server_ip;
        const subnet_mask = std.mem.toBytes(std.mem.nativeToBig(u32, self.cfg.subnet_mask));
        const router_ip = try config_mod.parseIpv4(self.cfg.router);
        const lease_time = std.mem.toBytes(std.mem.nativeToBig(u32, self.cfg.lease_time));
        const renewal_time = std.mem.toBytes(std.mem.nativeToBig(u32, self.cfg.lease_time / 2));
        const rebind_time = std.mem.toBytes(std.mem.nativeToBig(u32, self.cfg.lease_time * 7 / 8));

        var ip_str_buf: [15]u8 = undefined;
        const ip_str = std.fmt.bufPrint(&ip_str_buf, "{d}.{d}.{d}.{d}", .{
            client_ip[0], client_ip[1], client_ip[2], client_ip[3],
        }) catch unreachable;

        // Check for a reservation matching this client (by MAC, then by IP).
        const reservation: ?state_mod.Lease = self.store.getReservationByMac(mac_str) orelse
            self.store.getReservationByIp(ip_str);

        // Dupe the reservation hostname before addLease may free the old lease entry.
        var res_hostname: ?[]u8 = null;
        defer if (res_hostname) |h| self.allocator.free(h);
        if (reservation) |res| {
            if (res.hostname) |rh| res_hostname = try self.allocator.dupe(u8, rh);
        }

        // Record the lease (includes hostname from option 12 and client_id from option 61).
        const now = std.time.timestamp();
        const hostname = getHostname(request);
        const effective_hostname: ?[]const u8 = res_hostname orelse hostname;
        self.store.addLease(.{
            .mac = mac_str,
            .ip = ip_str,
            .hostname = effective_hostname,
            .expires = now + @as(i64, self.cfg.lease_time),
            .client_id = client_id_hex,
            .reserved = reservation != null,
        }) catch |err| {
            std.log.warn("Failed to store lease ({s})", .{@errorName(err)});
        };

        // Notify DNS updater
        if (self.dns_updater) |du| du.notifyLeaseAdded(ip_str, effective_hostname);

        logRelayAgentInfo(request);

        const prl = getOption(request, .ParameterRequestList);

        // Build options
        var opts_buf: [512]u8 = undefined;
        var opts_len: usize = 0;

        // Option 53: DHCPACK — always required
        opts_buf[opts_len] = @intFromEnum(OptionCode.MessageType);
        opts_buf[opts_len + 1] = 1;
        opts_buf[opts_len + 2] = @intFromEnum(MessageType.DHCPACK);
        opts_len += 3;

        // Option 54: Server Identifier — always required
        opts_buf[opts_len] = @intFromEnum(OptionCode.ServerIdentifier);
        opts_buf[opts_len + 1] = 4;
        @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &server_ip);
        opts_len += 6;

        // Option 51: IP Address Lease Time
        if (isRequested(prl, .IPAddressLeaseTime)) {
            opts_buf[opts_len] = @intFromEnum(OptionCode.IPAddressLeaseTime);
            opts_buf[opts_len + 1] = 4;
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &lease_time);
            opts_len += 6;
        }

        // Option 58: Renewal Time
        if (isRequested(prl, .RenewalTimeValue)) {
            opts_buf[opts_len] = @intFromEnum(OptionCode.RenewalTimeValue);
            opts_buf[opts_len + 1] = 4;
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &renewal_time);
            opts_len += 6;
        }

        // Option 59: Rebinding Time
        if (isRequested(prl, .RebindingTimeValue)) {
            opts_buf[opts_len] = @intFromEnum(OptionCode.RebindingTimeValue);
            opts_buf[opts_len + 1] = 4;
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &rebind_time);
            opts_len += 6;
        }

        // Option 1: Subnet Mask
        if (isRequested(prl, .SubnetMask)) {
            opts_buf[opts_len] = @intFromEnum(OptionCode.SubnetMask);
            opts_buf[opts_len + 1] = 4;
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &subnet_mask);
            opts_len += 6;
        }

        // Option 3: Router
        if (isRequested(prl, .Router)) {
            opts_buf[opts_len] = @intFromEnum(OptionCode.Router);
            opts_buf[opts_len + 1] = 4;
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &router_ip);
            opts_len += 6;
        }

        // Option 6: DNS Servers (up to 4)
        if (isRequested(prl, .DomainNameServer) and self.cfg.dns_servers.len > 0) {
            const count = @min(self.cfg.dns_servers.len, 4);
            opts_buf[opts_len] = @intFromEnum(OptionCode.DomainNameServer);
            opts_buf[opts_len + 1] = @intCast(count * 4);
            opts_len += 2;
            for (self.cfg.dns_servers[0..count]) |dns_str| {
                const dns_ip = config_mod.parseIpv4(dns_str) catch continue;
                @memcpy(opts_buf[opts_len .. opts_len + 4], &dns_ip);
                opts_len += 4;
            }
        }

        // Option 15: Domain Name
        if (isRequested(prl, .DomainName) and self.cfg.domain_name.len > 0) {
            const dn_len = @min(self.cfg.domain_name.len, 255);
            opts_buf[opts_len] = @intFromEnum(OptionCode.DomainName);
            opts_buf[opts_len + 1] = @intCast(dn_len);
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 2 + dn_len], self.cfg.domain_name[0..dn_len]);
            opts_len += 2 + dn_len;
        }

        // Option 12: Hostname override from reservation (so client adopts reservation hostname).
        if (res_hostname) |rh| {
            if (isRequested(prl, .HostName)) {
                const hn_len = @min(rh.len, 255);
                opts_buf[opts_len] = @intFromEnum(OptionCode.HostName);
                opts_buf[opts_len + 1] = @intCast(hn_len);
                @memcpy(opts_buf[opts_len + 2 .. opts_len + 2 + hn_len], rh[0..hn_len]);
                opts_len += 2 + hn_len;
            }
        }

        // Inject operator-defined options from config (filtered by PRL)
        var opts_it = self.cfg.dhcp_options.iterator();
        while (opts_it.next()) |entry| {
            const code = std.fmt.parseInt(u8, entry.key_ptr.*, 10) catch continue;
            if (!isRequestedCode(prl, code)) continue;
            const encoded = encodeOptionValue(opts_buf[opts_len + 2 ..], entry.value_ptr.*);
            if (encoded.len > 255 or opts_len + 2 + encoded.len > opts_buf.len - 1) continue;
            opts_buf[opts_len] = code;
            opts_buf[opts_len + 1] = @intCast(encoded.len);
            opts_len += 2 + encoded.len;
        }

        // End
        opts_buf[opts_len] = @intFromEnum(OptionCode.End);
        opts_len += 1;

        // Allocate response packet
        const pkt_len = dhcp_min_packet_size + opts_len;
        const pkt = try self.allocator.alloc(u8, pkt_len);
        @memset(pkt, 0);

        const resp_header: *DHCPHeader = @alignCast(@ptrCast(pkt.ptr));
        resp_header.op = 2; // BOOTREPLY
        resp_header.htype = req_header.htype;
        resp_header.hlen = req_header.hlen;
        resp_header.hops = req_header.hops;
        resp_header.xid = req_header.xid;
        resp_header.secs = 0;
        resp_header.flags = req_header.flags;
        resp_header.ciaddr = [_]u8{0} ** 4;
        resp_header.yiaddr = client_ip;
        resp_header.siaddr = server_ip;
        resp_header.giaddr = req_header.giaddr;
        resp_header.chaddr = req_header.chaddr;
        resp_header.magic = dhcp_magic_cookie;

        @memcpy(pkt[dhcp_min_packet_size .. dhcp_min_packet_size + opts_len], opts_buf[0..opts_len]);

        return pkt;
    }

    fn handleRelease(self: *Self, request: []const u8) void {
        if (request.len < dhcp_min_packet_size) return;
        const req_header: *const DHCPHeader = @alignCast(@ptrCast(request.ptr));
        const mac_bytes = req_header.chaddr[0..6];
        var mac_str_buf: [17]u8 = undefined;
        const mac_str = std.fmt.bufPrint(&mac_str_buf, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
            mac_bytes[0], mac_bytes[1], mac_bytes[2],
            mac_bytes[3], mac_bytes[4], mac_bytes[5],
        }) catch return;

        // Get IP and hostname from current lease before removing (for DNS cleanup)
        const old_lease = self.store.getLeaseByMac(mac_str);
        self.store.removeLease(mac_str);
        if (self.dns_updater) |du| {
            if (old_lease) |l| du.notifyLeaseRemoved(l.ip, l.hostname);
        }
    }

    fn handleDecline(self: *Self, request: []const u8) void {
        if (request.len < dhcp_min_packet_size) return;
        const req_header: *const DHCPHeader = @alignCast(@ptrCast(request.ptr));

        // Remove any existing offer-lease for this MAC.
        const mac_bytes = req_header.chaddr[0..6];
        var mac_buf: [17]u8 = undefined;
        const mac_str = std.fmt.bufPrint(&mac_buf, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
            mac_bytes[0], mac_bytes[1], mac_bytes[2],
            mac_bytes[3], mac_bytes[4], mac_bytes[5],
        }) catch return;
        self.store.removeLease(mac_str);

        // Global rate limit: reject excess declines that could exhaust the pool even
        // when the attacker rotates spoofed MACs to bypass the per-MAC cooldown.
        {
            const now_g = std.time.timestamp();
            if (now_g - self.global_decline_window_start > global_decline_window_secs) {
                self.global_decline_count = 0;
                self.global_decline_window_start = now_g;
            }
            if (self.global_decline_count >= global_decline_limit) {
                std.log.warn("DHCPDECLINE: global rate limit reached ({d} in {d}s), ignoring from {s}", .{
                    global_decline_limit, global_decline_window_secs, mac_str,
                });
                return;
            }
            self.global_decline_count += 1;
        }

        // Quarantine the declined IP for max(lease_time/10, 5 min) using a sentinel MAC.
        // allocateIp skips IPs where getLeaseByIp != null.
        // isIpValid rejects IPs whose stored MAC != client MAC ("conflict:..." never matches).
        // pruneExpiredWithDns removes the quarantine after the quarantine period.
        const quarantine_secs: u32 = @max(self.cfg.lease_time / 10, 300);
        const declined_ip = getRequestedIp(request) orelse return;
        var ip_buf: [15]u8 = undefined;
        const ip_str = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{
            declined_ip[0], declined_ip[1], declined_ip[2], declined_ip[3],
        }) catch return;
        var conflict_buf: [24]u8 = undefined; // "conflict:255.255.255.255" = 24 chars
        const conflict_mac = std.fmt.bufPrint(&conflict_buf, "conflict:{s}", .{ip_str}) catch return;
        self.store.addLease(.{
            .mac = conflict_mac,
            .ip = ip_str,
            .hostname = null,
            .expires = std.time.timestamp() + @as(i64, quarantine_secs),
            .client_id = null,
        }) catch |err| {
            std.log.warn("Failed to quarantine declined IP {s}: {s}", .{ ip_str, @errorName(err) });
            return;
        };
        std.log.info("DHCPDECLINE: quarantined {s} for {d}s", .{ ip_str, quarantine_secs });

        // Track declines per MAC. After decline_threshold declines within
        // decline_window_secs, refuse further allocations for decline_cooldown_secs.
        const now = std.time.timestamp();
        var rec = self.decline_records.get(mac_buf) orelse DeclineRecord{
            .count = 0,
            .window_start = now,
            .cooldown_until = 0,
        };
        if (now - rec.window_start > decline_window_secs) {
            // Window expired — start a fresh count.
            rec.count = 0;
            rec.window_start = now;
        }
        rec.count += 1;
        if (rec.count >= decline_threshold) {
            rec.cooldown_until = now + decline_cooldown_secs;
            rec.count = 0;
            std.log.warn("DHCPDECLINE: rate-limiting {s} for {d}s after {d} declines in {d}s", .{
                mac_str, decline_cooldown_secs, decline_threshold, decline_window_secs,
            });
        }
        self.decline_records.put(mac_buf, rec) catch {};
    }

    /// Scan options for option 50 (Requested IP Address).
    fn getRequestedIp(packet: []const u8) ?[4]u8 {
        const val = getOption(packet, .RequestedIPAddress) orelse return null;
        if (val.len < 4) return null;
        return val[0..4].*;
    }

    /// Scan options for option 54 (Server Identifier).
    fn getServerIdentifier(packet: []const u8) ?[4]u8 {
        const val = getOption(packet, .ServerIdentifier) orelse return null;
        if (val.len < 4) return null;
        return val[0..4].*;
    }

    /// Scan options for option 12 (Host Name).
    fn getHostname(packet: []const u8) ?[]const u8 {
        const val = getOption(packet, .HostName) orelse return null;
        if (val.len == 0) return null;
        return val;
    }

    /// Scan options for option 61 (Client Identifier). Returns raw bytes or null.
    fn getClientId(packet: []const u8) ?[]const u8 {
        const val = getOption(packet, .ClientID) orelse return null;
        if (val.len == 0) return null;
        return val;
    }

    /// Log sub-options from Relay Agent Information (option 82) at debug level.
    /// No-op if the option is absent.
    fn logRelayAgentInfo(packet: []const u8) void {
        const val = getOption(packet, .RelayAgentInformation) orelse return;
        var i: usize = 0;
        while (i + 1 < val.len) {
            const sub_code = val[i];
            const sub_len = val[i + 1];
            if (i + 2 + sub_len > val.len) break;
            const sub_data = val[i + 2 .. i + 2 + sub_len];
            switch (sub_code) {
                1 => std.log.debug("Option 82 circuit-id: {x}", .{sub_data}),
                2 => std.log.debug("Option 82 remote-id: {x}", .{sub_data}),
                else => std.log.debug("Option 82 sub-option {d}: {x} ({d}B)", .{ sub_code, sub_data, sub_len }),
            }
            i += 2 + sub_len;
        }
    }

    /// Returns true if `ip` is a valid host address in our subnet that is either
    /// unleased or already leased to this client (matched by mac_str or client_id_hex).
    fn isIpValid(self: *Self, ip: [4]u8, mac_str: []const u8, client_id_hex: ?[]const u8) bool {
        const ip_int = std.mem.readInt(u32, &ip, .big);
        const subnet_bytes = config_mod.parseIpv4(self.cfg.subnet) catch return false;
        const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
        const mask = self.cfg.subnet_mask;
        const broadcast_int = subnet_int | ~mask;

        if ((ip_int & mask) != subnet_int) return false;
        if (ip_int == subnet_int or ip_int == broadcast_int) return false;

        // Reject reserved addresses: router and server's own IP.
        const router_bytes = config_mod.parseIpv4(self.cfg.router) catch return false;
        if (ip_int == std.mem.readInt(u32, &router_bytes, .big)) return false;
        if (std.mem.eql(u8, &ip, &self.server_ip)) return false;

        if (self.cfg.pool_start.len > 0) {
            const b = config_mod.parseIpv4(self.cfg.pool_start) catch return false;
            if (ip_int < std.mem.readInt(u32, &b, .big)) return false;
        }
        if (self.cfg.pool_end.len > 0) {
            const b = config_mod.parseIpv4(self.cfg.pool_end) catch return false;
            if (ip_int > std.mem.readInt(u32, &b, .big)) return false;
        }

        var ip_buf: [15]u8 = undefined;
        const ip_str = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch return false;

        // Reject a reserved IP for a client that doesn't own the reservation.
        if (self.store.getReservationByIp(ip_str)) |res| {
            const mac_ok = std.mem.eql(u8, res.mac, mac_str);
            const cid_ok = if (client_id_hex) |cid|
                if (res.client_id) |rcid| std.mem.eql(u8, cid, rcid) else false
            else false;
            if (!mac_ok and !cid_ok) return false;
        }

        if (self.store.getLeaseByIp(ip_str)) |lease| {
            if (!std.mem.eql(u8, lease.mac, mac_str)) {
                // Accept if the stored client_id matches (client may have changed MAC).
                if (client_id_hex) |cid| {
                    if (lease.client_id) |stored_cid| {
                        if (std.mem.eql(u8, cid, stored_cid)) return true;
                    }
                }
                return false;
            }
        }
        return true;
    }

    /// Build a DHCPACK in response to a DHCPINFORM (RFC 2131 §3.4).
    /// yiaddr is 0 — no address is assigned. Returns configuration options only.
    fn handleInform(self: *Self, request: []const u8) !?[]u8 {
        const req_header: *const DHCPHeader = @alignCast(@ptrCast(request.ptr));
        const server_ip = self.server_ip;

        logRelayAgentInfo(request);

        const prl = getOption(request, .ParameterRequestList);

        var opts_buf: [512]u8 = undefined;
        var opts_len: usize = 0;

        // Option 53: DHCPACK — always required
        opts_buf[opts_len] = @intFromEnum(OptionCode.MessageType);
        opts_buf[opts_len + 1] = 1;
        opts_buf[opts_len + 2] = @intFromEnum(MessageType.DHCPACK);
        opts_len += 3;

        // Option 54: Server Identifier — always required
        opts_buf[opts_len] = @intFromEnum(OptionCode.ServerIdentifier);
        opts_buf[opts_len + 1] = 4;
        @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &server_ip);
        opts_len += 6;

        // Option 1: Subnet Mask
        if (isRequested(prl, .SubnetMask)) {
            const subnet_mask = std.mem.toBytes(std.mem.nativeToBig(u32, self.cfg.subnet_mask));
            opts_buf[opts_len] = @intFromEnum(OptionCode.SubnetMask);
            opts_buf[opts_len + 1] = 4;
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &subnet_mask);
            opts_len += 6;
        }

        // Option 3: Router
        if (isRequested(prl, .Router)) {
            const router_ip = try config_mod.parseIpv4(self.cfg.router);
            opts_buf[opts_len] = @intFromEnum(OptionCode.Router);
            opts_buf[opts_len + 1] = 4;
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &router_ip);
            opts_len += 6;
        }

        // Option 6: DNS Servers (up to 4)
        if (isRequested(prl, .DomainNameServer) and self.cfg.dns_servers.len > 0) {
            const count = @min(self.cfg.dns_servers.len, 4);
            opts_buf[opts_len] = @intFromEnum(OptionCode.DomainNameServer);
            opts_buf[opts_len + 1] = @intCast(count * 4);
            opts_len += 2;
            for (self.cfg.dns_servers[0..count]) |dns_str| {
                const dns_ip = config_mod.parseIpv4(dns_str) catch continue;
                @memcpy(opts_buf[opts_len .. opts_len + 4], &dns_ip);
                opts_len += 4;
            }
        }

        // Option 15: Domain Name
        if (isRequested(prl, .DomainName) and self.cfg.domain_name.len > 0) {
            const dn_len = @min(self.cfg.domain_name.len, 255);
            opts_buf[opts_len] = @intFromEnum(OptionCode.DomainName);
            opts_buf[opts_len + 1] = @intCast(dn_len);
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 2 + dn_len], self.cfg.domain_name[0..dn_len]);
            opts_len += 2 + dn_len;
        }

        // Inject operator-defined options from config (filtered by PRL)
        var opts_it = self.cfg.dhcp_options.iterator();
        while (opts_it.next()) |entry| {
            const code = std.fmt.parseInt(u8, entry.key_ptr.*, 10) catch continue;
            if (!isRequestedCode(prl, code)) continue;
            const encoded = encodeOptionValue(opts_buf[opts_len + 2 ..], entry.value_ptr.*);
            if (encoded.len > 255 or opts_len + 2 + encoded.len > opts_buf.len - 1) continue;
            opts_buf[opts_len] = code;
            opts_buf[opts_len + 1] = @intCast(encoded.len);
            opts_len += 2 + encoded.len;
        }

        // End
        opts_buf[opts_len] = @intFromEnum(OptionCode.End);
        opts_len += 1;

        const pkt = try self.allocator.alloc(u8, dhcp_min_packet_size + opts_len);
        @memset(pkt, 0);

        const resp_header: *DHCPHeader = @alignCast(@ptrCast(pkt.ptr));
        resp_header.op = 2; // BOOTREPLY
        resp_header.htype = req_header.htype;
        resp_header.hlen = req_header.hlen;
        resp_header.hops = req_header.hops;
        resp_header.xid = req_header.xid;
        resp_header.flags = req_header.flags;
        resp_header.ciaddr = req_header.ciaddr; // echo ciaddr; no lease assigned
        // yiaddr stays 0 (zeroed by memset) — no address is being assigned
        resp_header.siaddr = server_ip;
        resp_header.giaddr = req_header.giaddr;
        resp_header.chaddr = req_header.chaddr;
        resp_header.magic = dhcp_magic_cookie;

        @memcpy(pkt[dhcp_min_packet_size .. dhcp_min_packet_size + opts_len], opts_buf[0..opts_len]);

        return pkt;
    }

    /// Build a DHCPNAK in response to a DHCPREQUEST with an invalid IP.
    fn createNak(self: *Self, request: []const u8) !?[]u8 {
        const req_header: *const DHCPHeader = @alignCast(@ptrCast(request.ptr));
        const server_ip = self.server_ip;

        var opts_buf: [16]u8 = undefined;
        var opts_len: usize = 0;
        opts_buf[opts_len] = @intFromEnum(OptionCode.MessageType);
        opts_len += 1;
        opts_buf[opts_len] = 1;
        opts_len += 1;
        opts_buf[opts_len] = @intFromEnum(MessageType.DHCPNAK);
        opts_len += 1;
        opts_buf[opts_len] = @intFromEnum(OptionCode.ServerIdentifier);
        opts_len += 1;
        opts_buf[opts_len] = 4;
        opts_len += 1;
        @memcpy(opts_buf[opts_len .. opts_len + 4], &server_ip);
        opts_len += 4;
        opts_buf[opts_len] = @intFromEnum(OptionCode.End);
        opts_len += 1;

        const pkt = try self.allocator.alloc(u8, dhcp_min_packet_size + opts_len);
        @memset(pkt, 0);
        const resp: *DHCPHeader = @alignCast(@ptrCast(pkt.ptr));
        resp.op = 2;
        resp.htype = req_header.htype;
        resp.hlen = req_header.hlen;
        resp.hops = req_header.hops;
        resp.xid = req_header.xid;
        resp.flags = req_header.flags;
        resp.giaddr = req_header.giaddr;
        resp.chaddr = req_header.chaddr;
        resp.magic = dhcp_magic_cookie;
        @memcpy(pkt[dhcp_min_packet_size .. dhcp_min_packet_size + opts_len], opts_buf[0..opts_len]);
        return pkt;
    }
};

pub fn create_server(
    allocator: std.mem.Allocator,
    cfg: *const Config,
    store: *StateStore,
    dns_updater: ?*dns_mod.DNSUpdater,
) !*DHCPServer {
    return DHCPServer.create(allocator, cfg, store, dns_updater);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "resolveDestination: giaddr set -> relay at giaddr:67" {
    var pkt = std.mem.zeroes([dhcp_min_packet_size]u8);
    const hdr: *DHCPHeader = @alignCast(@ptrCast(&pkt));
    hdr.giaddr = [_]u8{ 10, 0, 0, 1 };
    const dst = resolveDestination(&pkt);
    try std.testing.expectEqual(std.mem.nativeToBig(u16, dhcp_server_port), dst.port);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 1 }, &@as([4]u8, @bitCast(dst.addr)));
}

test "resolveDestination: ciaddr set -> unicast to client:68" {
    var pkt = std.mem.zeroes([dhcp_min_packet_size]u8);
    const hdr: *DHCPHeader = @alignCast(@ptrCast(&pkt));
    hdr.ciaddr = [_]u8{ 192, 168, 1, 50 };
    const dst = resolveDestination(&pkt);
    try std.testing.expectEqual(std.mem.nativeToBig(u16, dhcp_client_port), dst.port);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 50 }, &@as([4]u8, @bitCast(dst.addr)));
}

test "resolveDestination: giaddr takes priority over ciaddr" {
    var pkt = std.mem.zeroes([dhcp_min_packet_size]u8);
    const hdr: *DHCPHeader = @alignCast(@ptrCast(&pkt));
    hdr.giaddr = [_]u8{ 10, 0, 0, 1 };
    hdr.ciaddr = [_]u8{ 192, 168, 1, 50 };
    const dst = resolveDestination(&pkt);
    try std.testing.expectEqual(std.mem.nativeToBig(u16, dhcp_server_port), dst.port);
}

test "resolveDestination: broadcast flag -> 255.255.255.255:68" {
    var pkt = std.mem.zeroes([dhcp_min_packet_size]u8);
    const hdr: *DHCPHeader = @alignCast(@ptrCast(&pkt));
    // Broadcast flag: bit 15 in network byte order = 0x8000 BE.
    // Stored in a LE extern struct as 0x0080.
    hdr.flags = std.mem.bigToNative(u16, 0x8000);
    const dst = resolveDestination(&pkt);
    try std.testing.expectEqual(std.mem.nativeToBig(u16, dhcp_client_port), dst.port);
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), dst.addr);
}

test "resolveDestination: no flags -> broadcast fallback" {
    var pkt = std.mem.zeroes([dhcp_min_packet_size]u8);
    const dst = resolveDestination(&pkt);
    try std.testing.expectEqual(std.mem.nativeToBig(u16, dhcp_client_port), dst.port);
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), dst.addr);
}

test "getMessageType discover" {
    var pkt = [_]u8{0} ** (dhcp_min_packet_size + 10);
    @memcpy(pkt[dhcp_min_packet_size - 4 .. dhcp_min_packet_size], &dhcp_magic_cookie);
    pkt[dhcp_min_packet_size] = @intFromEnum(OptionCode.MessageType);
    pkt[dhcp_min_packet_size + 1] = 1;
    pkt[dhcp_min_packet_size + 2] = @intFromEnum(MessageType.DHCPDISCOVER);
    pkt[dhcp_min_packet_size + 3] = @intFromEnum(OptionCode.End);

    const mt = DHCPServer.getMessageType(&pkt);
    try std.testing.expect(mt != null);
    try std.testing.expectEqual(MessageType.DHCPDISCOVER, mt.?);
}

test "getRequestedIp present" {
    var pkt = [_]u8{0} ** (dhcp_min_packet_size + 16);
    @memcpy(pkt[dhcp_min_packet_size - 4 .. dhcp_min_packet_size], &dhcp_magic_cookie);
    // Option 50: Requested IP 192.168.1.50
    pkt[dhcp_min_packet_size] = @intFromEnum(OptionCode.RequestedIPAddress);
    pkt[dhcp_min_packet_size + 1] = 4;
    pkt[dhcp_min_packet_size + 2] = 192;
    pkt[dhcp_min_packet_size + 3] = 168;
    pkt[dhcp_min_packet_size + 4] = 1;
    pkt[dhcp_min_packet_size + 5] = 50;
    pkt[dhcp_min_packet_size + 6] = @intFromEnum(OptionCode.End);

    const ip = DHCPServer.getRequestedIp(&pkt);
    try std.testing.expect(ip != null);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 50 }, &ip.?);
}

test "getRequestedIp absent" {
    var pkt = [_]u8{0} ** (dhcp_min_packet_size + 8);
    @memcpy(pkt[dhcp_min_packet_size - 4 .. dhcp_min_packet_size], &dhcp_magic_cookie);
    pkt[dhcp_min_packet_size] = @intFromEnum(OptionCode.End);

    const ip = DHCPServer.getRequestedIp(&pkt);
    try std.testing.expect(ip == null);
}

test "getOption finds target" {
    var pkt = [_]u8{0} ** (dhcp_min_packet_size + 16);
    @memcpy(pkt[dhcp_min_packet_size - 4 .. dhcp_min_packet_size], &dhcp_magic_cookie);
    pkt[dhcp_min_packet_size] = @intFromEnum(OptionCode.HostName);
    pkt[dhcp_min_packet_size + 1] = 4;
    @memcpy(pkt[dhcp_min_packet_size + 2 .. dhcp_min_packet_size + 6], "test");
    pkt[dhcp_min_packet_size + 6] = @intFromEnum(OptionCode.End);

    const val = DHCPServer.getOption(&pkt, .HostName);
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("test", val.?);
}

test "getOption skips pad bytes" {
    var pkt = [_]u8{0} ** (dhcp_min_packet_size + 16);
    @memcpy(pkt[dhcp_min_packet_size - 4 .. dhcp_min_packet_size], &dhcp_magic_cookie);
    pkt[dhcp_min_packet_size] = @intFromEnum(OptionCode.Pad); // pad
    pkt[dhcp_min_packet_size + 1] = @intFromEnum(OptionCode.HostName);
    pkt[dhcp_min_packet_size + 2] = 3;
    @memcpy(pkt[dhcp_min_packet_size + 3 .. dhcp_min_packet_size + 6], "foo");
    pkt[dhcp_min_packet_size + 6] = @intFromEnum(OptionCode.End);

    const val = DHCPServer.getOption(&pkt, .HostName);
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("foo", val.?);
}

test "getOption returns null when absent" {
    var pkt = [_]u8{0} ** (dhcp_min_packet_size + 8);
    @memcpy(pkt[dhcp_min_packet_size - 4 .. dhcp_min_packet_size], &dhcp_magic_cookie);
    pkt[dhcp_min_packet_size] = @intFromEnum(OptionCode.End);

    try std.testing.expect(DHCPServer.getOption(&pkt, .HostName) == null);
}

test "getServerIdentifier present" {
    var pkt = [_]u8{0} ** (dhcp_min_packet_size + 16);
    @memcpy(pkt[dhcp_min_packet_size - 4 .. dhcp_min_packet_size], &dhcp_magic_cookie);
    pkt[dhcp_min_packet_size] = @intFromEnum(OptionCode.ServerIdentifier);
    pkt[dhcp_min_packet_size + 1] = 4;
    pkt[dhcp_min_packet_size + 2] = 192;
    pkt[dhcp_min_packet_size + 3] = 168;
    pkt[dhcp_min_packet_size + 4] = 1;
    pkt[dhcp_min_packet_size + 5] = 1;
    pkt[dhcp_min_packet_size + 6] = @intFromEnum(OptionCode.End);

    const sid = DHCPServer.getServerIdentifier(&pkt);
    try std.testing.expect(sid != null);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 1 }, &sid.?);
}

test "getServerIdentifier absent" {
    var pkt = [_]u8{0} ** (dhcp_min_packet_size + 8);
    @memcpy(pkt[dhcp_min_packet_size - 4 .. dhcp_min_packet_size], &dhcp_magic_cookie);
    pkt[dhcp_min_packet_size] = @intFromEnum(OptionCode.End);

    try std.testing.expect(DHCPServer.getServerIdentifier(&pkt) == null);
}

test "getHostname present" {
    var pkt = [_]u8{0} ** (dhcp_min_packet_size + 16);
    @memcpy(pkt[dhcp_min_packet_size - 4 .. dhcp_min_packet_size], &dhcp_magic_cookie);
    pkt[dhcp_min_packet_size] = @intFromEnum(OptionCode.HostName);
    pkt[dhcp_min_packet_size + 1] = 6;
    @memcpy(pkt[dhcp_min_packet_size + 2 .. dhcp_min_packet_size + 8], "client");
    pkt[dhcp_min_packet_size + 8] = @intFromEnum(OptionCode.End);

    const hn = DHCPServer.getHostname(&pkt);
    try std.testing.expect(hn != null);
    try std.testing.expectEqualStrings("client", hn.?);
}

test "getHostname absent" {
    var pkt = [_]u8{0} ** (dhcp_min_packet_size + 8);
    @memcpy(pkt[dhcp_min_packet_size - 4 .. dhcp_min_packet_size], &dhcp_magic_cookie);
    pkt[dhcp_min_packet_size] = @intFromEnum(OptionCode.End);

    try std.testing.expect(DHCPServer.getHostname(&pkt) == null);
}

// ---------------------------------------------------------------------------
// Server integration tests
// ---------------------------------------------------------------------------

/// Build a minimal DHCPREQUEST into buf. Returns the total packet length.
fn makeRequest(
    buf: []u8,
    mac: [6]u8,
    requested_ip: ?[4]u8,
    server_id: ?[4]u8,
    hostname: ?[]const u8,
) usize {
    @memset(buf, 0);
    const hdr: *DHCPHeader = @alignCast(@ptrCast(buf.ptr));
    hdr.op = 1;
    hdr.htype = 1;
    hdr.hlen = 6;
    hdr.xid = 0x12345678;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &mac);

    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType);
    i += 1;
    buf[i] = 1;
    i += 1;
    buf[i] = @intFromEnum(MessageType.DHCPREQUEST);
    i += 1;
    if (requested_ip) |ip| {
        buf[i] = @intFromEnum(OptionCode.RequestedIPAddress);
        i += 1;
        buf[i] = 4;
        i += 1;
        @memcpy(buf[i..][0..4], &ip);
        i += 4;
    }
    if (server_id) |sid| {
        buf[i] = @intFromEnum(OptionCode.ServerIdentifier);
        i += 1;
        buf[i] = 4;
        i += 1;
        @memcpy(buf[i..][0..4], &sid);
        i += 4;
    }
    if (hostname) |hn| {
        buf[i] = @intFromEnum(OptionCode.HostName);
        i += 1;
        buf[i] = @intCast(hn.len);
        i += 1;
        @memcpy(buf[i..][0..hn.len], hn);
        i += hn.len;
    }
    buf[i] = @intFromEnum(OptionCode.End);
    i += 1;
    return i;
}

/// Create a fully initialized test Config. Caller must call cfg.deinit().
fn makeTestConfig(allocator: std.mem.Allocator) !config_mod.Config {
    return config_mod.Config{
        .allocator = allocator,
        .listen_address = try allocator.dupe(u8, "192.168.1.1"),
        .subnet = try allocator.dupe(u8, "192.168.1.0"),
        .subnet_mask = 0xFFFFFF00,
        .router = try allocator.dupe(u8, "192.168.1.1"),
        .dns_servers = try allocator.alloc([]const u8, 0),
        .domain_name = try allocator.dupe(u8, ""),
        .lease_time = 3600,
        .state_dir = try allocator.dupe(u8, "/tmp"),
        .pool_start = try allocator.dupe(u8, ""),
        .pool_end = try allocator.dupe(u8, ""),
        .log_level = .info,
        .dns_update = .{
            .enable = false,
            .server = try allocator.dupe(u8, ""),
            .zone = try allocator.dupe(u8, ""),
            .key_name = try allocator.dupe(u8, ""),
            .key_file = try allocator.dupe(u8, ""),
            .lease_time = 3600,
        },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = try allocator.alloc(config_mod.Reservation, 0),
    };
}

/// Create a bare StateStore (no disk I/O on construction).
fn makeTestStore(allocator: std.mem.Allocator) !*StateStore {
    const store = try allocator.create(StateStore);
    store.* = .{
        .allocator = allocator,
        .dir = "/tmp",
        .leases = std.StringHashMap(state_mod.Lease).init(allocator),
    };
    return store;
}

test "createAck returns null when option 54 does not match our IP" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    var buf = [_]u8{0} ** 512;
    const len = makeRequest(
        &buf,
        [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
        [4]u8{ 192, 168, 1, 50 },
        [4]u8{ 10, 0, 0, 1 }, // different server
        null,
    );
    const resp = try server.processPacket(buf[0..len]);
    try std.testing.expect(resp == null);
}

test "createAck sends DHCPNAK for IP outside subnet" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    var buf = [_]u8{0} ** 512;
    const len = makeRequest(
        &buf,
        [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
        [4]u8{ 10, 0, 0, 1 }, // outside 192.168.1.0/24
        [4]u8{ 192, 168, 1, 1 }, // our server
        null,
    );
    const resp = try server.processPacket(buf[0..len]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);
    try std.testing.expectEqual(MessageType.DHCPNAK, DHCPServer.getMessageType(resp.?).?);
}

test "createAck stores hostname from option 12" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    var buf = [_]u8{0} ** 512;
    const len = makeRequest(
        &buf,
        [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
        [4]u8{ 192, 168, 1, 50 },
        [4]u8{ 192, 168, 1, 1 },
        "myhost",
    );
    const resp = try server.processPacket(buf[0..len]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);
    try std.testing.expectEqual(MessageType.DHCPACK, DHCPServer.getMessageType(resp.?).?);

    const lease = store.getLeaseByMac("aa:bb:cc:dd:ee:ff");
    try std.testing.expect(lease != null);
    try std.testing.expect(lease.?.hostname != null);
    try std.testing.expectEqualStrings("myhost", lease.?.hostname.?);
}

test "createAck returns DHCPACK for valid request without option 54" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    var buf = [_]u8{0} ** 512;
    const len = makeRequest(
        &buf,
        [6]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 },
        [4]u8{ 192, 168, 1, 100 },
        null, // no server identifier — renewal style
        null,
    );
    const resp = try server.processPacket(buf[0..len]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);
    try std.testing.expectEqual(MessageType.DHCPACK, DHCPServer.getMessageType(resp.?).?);
}

/// Build a minimal DHCPDECLINE into buf. Returns total packet length.
fn makeDecline(buf: []u8, mac: [6]u8, declined_ip: [4]u8) usize {
    @memset(buf, 0);
    const hdr: *DHCPHeader = @alignCast(@ptrCast(buf.ptr));
    hdr.op = 1;
    hdr.htype = 1;
    hdr.hlen = 6;
    hdr.xid = 0xDECADECA;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &mac);

    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType);
    buf[i + 1] = 1;
    buf[i + 2] = @intFromEnum(MessageType.DHCPDECLINE);
    i += 3;
    buf[i] = @intFromEnum(OptionCode.RequestedIPAddress);
    buf[i + 1] = 4;
    @memcpy(buf[i + 2 .. i + 6], &declined_ip);
    i += 6;
    buf[i] = @intFromEnum(OptionCode.End);
    i += 1;
    return i;
}

test "allocateIp skips addresses before pool_start" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    // Override pool_start to 192.168.1.100
    alloc.free(cfg.pool_start);
    cfg.pool_start = try alloc.dupe(u8, "192.168.1.100");
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    const ip = try server.allocateIp([6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, null);
    try std.testing.expect(ip != null);
    const ip_int = std.mem.readInt(u32, &ip.?, .big);
    const start_int = std.mem.readInt(u32, &[4]u8{ 192, 168, 1, 100 }, .big);
    try std.testing.expect(ip_int >= start_int);
}

test "isIpValid rejects IP outside pool range" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    alloc.free(cfg.pool_start);
    alloc.free(cfg.pool_end);
    cfg.pool_start = try alloc.dupe(u8, "192.168.1.100");
    cfg.pool_end = try alloc.dupe(u8, "192.168.1.200");
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    // Below pool_start
    try std.testing.expect(!server.isIpValid([4]u8{ 192, 168, 1, 50 }, "aa:bb:cc:dd:ee:ff", null));
    // Above pool_end
    try std.testing.expect(!server.isIpValid([4]u8{ 192, 168, 1, 210 }, "aa:bb:cc:dd:ee:ff", null));
    // Inside pool
    try std.testing.expect(server.isIpValid([4]u8{ 192, 168, 1, 150 }, "aa:bb:cc:dd:ee:ff", null));
}

test "handleDecline quarantines declined IP" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    var buf = [_]u8{0} ** 512;
    const len = makeDecline(&buf, [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, [4]u8{ 192, 168, 1, 50 });
    const resp = try server.processPacket(buf[0..len]);
    try std.testing.expect(resp == null); // DECLINE generates no response

    // The declined IP should now have a quarantine lease.
    const lease = store.getLeaseByIp("192.168.1.50");
    try std.testing.expect(lease != null);
    // Quarantine MAC starts with "conflict:"
    try std.testing.expect(std.mem.startsWith(u8, lease.?.mac, "conflict:"));
}

test "handleDecline removes MAC lease" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    // Pre-populate a lease for the MAC.
    try store.addLease(.{
        .mac = "aa:bb:cc:dd:ee:ff",
        .ip = "192.168.1.50",
        .hostname = null,
        .expires = std.time.timestamp() + 3600,
        .client_id = null,
    });
    try std.testing.expect(store.getLeaseByMac("aa:bb:cc:dd:ee:ff") != null);

    var buf = [_]u8{0} ** 512;
    const len = makeDecline(&buf, [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, [4]u8{ 192, 168, 1, 50 });
    _ = try server.processPacket(buf[0..len]);

    // MAC lease should be gone.
    try std.testing.expect(store.getLeaseByMac("aa:bb:cc:dd:ee:ff") == null);
}

test "createOffer uses server_ip not listen_address" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    // Override server_ip to something different from listen_address
    server.server_ip = [4]u8{ 192, 168, 1, 5 };

    var buf = [_]u8{0} ** 512;
    @memset(&buf, 0);
    const hdr: *DHCPHeader = @alignCast(@ptrCast(buf.ptr));
    hdr.op = 1;
    hdr.htype = 1;
    hdr.hlen = 6;
    hdr.xid = 0x11223344;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType);
    buf[i + 1] = 1;
    buf[i + 2] = @intFromEnum(MessageType.DHCPDISCOVER);
    i += 3;
    buf[i] = @intFromEnum(OptionCode.End);
    i += 1;

    const resp = try server.processPacket(buf[0..i]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);
    try std.testing.expectEqual(MessageType.DHCPOFFER, DHCPServer.getMessageType(resp.?).?);

    // Option 54 in the response should contain server_ip, not listen_address.
    const sid = DHCPServer.getServerIdentifier(resp.?);
    try std.testing.expect(sid != null);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 5 }, &sid.?);
}

test "createAck checks server_ip for option 54" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    server.server_ip = [4]u8{ 192, 168, 1, 5 };

    var buf = [_]u8{0} ** 512;
    // Request directed at a different server — should return null.
    const len = makeRequest(
        &buf,
        [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
        [4]u8{ 192, 168, 1, 50 },
        [4]u8{ 192, 168, 1, 1 }, // different from server_ip (192.168.1.5)
        null,
    );
    const resp = try server.processPacket(buf[0..len]);
    try std.testing.expect(resp == null);

    // Request directed at our server_ip — should be processed.
    const len2 = makeRequest(
        &buf,
        [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
        [4]u8{ 192, 168, 1, 50 },
        [4]u8{ 192, 168, 1, 5 }, // matches server_ip
        null,
    );
    const resp2 = try server.processPacket(buf[0..len2]);
    try std.testing.expect(resp2 != null);
    defer alloc.free(resp2.?);
    try std.testing.expectEqual(MessageType.DHCPACK, DHCPServer.getMessageType(resp2.?).?);
}

test "dhcp_options injected into OFFER packet" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();

    // Add option 42 (NTP server) with value "192.168.1.10"
    const opt_key = try alloc.dupe(u8, "42");
    const opt_val = try alloc.dupe(u8, "192.168.1.10");
    try cfg.dhcp_options.put(opt_key, opt_val);

    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    // Send a DISCOVER
    var buf = [_]u8{0} ** 512;
    @memset(&buf, 0);
    const hdr: *DHCPHeader = @alignCast(@ptrCast(buf.ptr));
    hdr.op = 1;
    hdr.htype = 1;
    hdr.hlen = 6;
    hdr.xid = 0xDEADBEEF;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01 });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType);
    buf[i + 1] = 1;
    buf[i + 2] = @intFromEnum(MessageType.DHCPDISCOVER);
    i += 3;
    buf[i] = @intFromEnum(OptionCode.End);
    i += 1;

    const resp = try server.processPacket(buf[0..i]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);
    try std.testing.expectEqual(MessageType.DHCPOFFER, DHCPServer.getMessageType(resp.?).?);

    // Scan the response options for option code 42
    const opts = resp.?[dhcp_min_packet_size..];
    var j: usize = 0;
    var found_42 = false;
    while (j + 1 < opts.len) {
        const code = opts[j];
        if (code == @intFromEnum(OptionCode.End)) break;
        if (code == @intFromEnum(OptionCode.Pad)) { j += 1; continue; }
        const opt_len = opts[j + 1];
        if (j + 2 + opt_len > opts.len) break;
        if (code == 42 and opt_len == 4) {
            // NTP server should be 192.168.1.10
            try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 10 }, opts[j + 2 .. j + 6]);
            found_42 = true;
        }
        j += 2 + opt_len;
    }
    try std.testing.expect(found_42);
}

test "handleDecline rate-limits MAC after threshold declines" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    const mac = [6]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 };

    // Send decline_threshold DHCPDECLINE packets for different IPs.
    // Each one should be processed without blocking.
    var i: u32 = 0;
    while (i < decline_threshold) : (i += 1) {
        var buf = [_]u8{0} ** 512;
        const declined_ip = [4]u8{ 192, 168, 1, @intCast(10 + i) };

        // First ACK the IP so handleDecline has a lease to remove.
        const req_len = makeRequest(&buf, mac, declined_ip, [4]u8{ 192, 168, 1, 1 }, null);
        const ack = try server.processPacket(buf[0..req_len]);
        if (ack) |a| alloc.free(a);

        const dec_len = makeDecline(&buf, mac, declined_ip);
        const resp = try server.processPacket(buf[0..dec_len]);
        try std.testing.expect(resp == null); // DECLINE generates no response
    }

    // After threshold declines, allocateIp should return null for this MAC.
    const ip = try server.allocateIp(mac, null);
    try std.testing.expect(ip == null);
}

test "quarantine period is max(lease_time/10, 300)" {
    const alloc = std.testing.allocator;

    // lease_time = 3600 → quarantine = 360s
    {
        var cfg = try makeTestConfig(alloc);
        defer cfg.deinit();
        cfg.lease_time = 3600;
        const store = try makeTestStore(alloc);
        defer store.deinit();
        const server = try DHCPServer.create(alloc, &cfg, store, null);
        defer server.deinit();

        var buf = [_]u8{0} ** 512;
        const len = makeDecline(&buf, [6]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, [4]u8{ 192, 168, 1, 50 });
        _ = try server.processPacket(buf[0..len]);

        const lease = store.getLeaseByIp("192.168.1.50");
        try std.testing.expect(lease != null);
        const remaining = lease.?.expires - std.time.timestamp();
        // Should be ~360s (lease_time/10), not 3600s
        try std.testing.expect(remaining <= 360 + 2);
        try std.testing.expect(remaining >= 300);
    }

    // lease_time = 600 → quarantine = 300s (minimum floor)
    {
        var cfg = try makeTestConfig(alloc);
        defer cfg.deinit();
        cfg.lease_time = 600;
        const store = try makeTestStore(alloc);
        defer store.deinit();
        const server = try DHCPServer.create(alloc, &cfg, store, null);
        defer server.deinit();

        var buf = [_]u8{0} ** 512;
        const len = makeDecline(&buf, [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, [4]u8{ 192, 168, 1, 60 });
        _ = try server.processPacket(buf[0..len]);

        const lease = store.getLeaseByIp("192.168.1.60");
        try std.testing.expect(lease != null);
        const remaining = lease.?.expires - std.time.timestamp();
        // Should be ~300s (floor), not 60s (600/10)
        try std.testing.expect(remaining <= 300 + 2);
        try std.testing.expect(remaining >= 298);
    }
}

test "global decline rate limit drops excess declines" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    // Force the window to be current so counts don't reset.
    server.global_decline_window_start = std.time.timestamp();

    // Send global_decline_limit declines from distinct MACs — all should quarantine.
    var i: u32 = 0;
    while (i < global_decline_limit) : (i += 1) {
        var buf = [_]u8{0} ** 512;
        const mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0x00, 0x00, @intCast(i) };
        const ip = [4]u8{ 192, 168, 1, @intCast(10 + i) };
        const len = makeDecline(&buf, mac, ip);
        _ = try server.processPacket(buf[0..len]);
    }
    try std.testing.expectEqual(global_decline_limit, server.global_decline_count);

    // One more decline (new MAC, new IP) should be dropped — no quarantine lease added.
    {
        var buf = [_]u8{0} ** 512;
        const mac = [6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        const ip = [4]u8{ 192, 168, 1, @intCast(10 + global_decline_limit) };
        const len = makeDecline(&buf, mac, ip);
        _ = try server.processPacket(buf[0..len]);

        // No quarantine lease should exist for the dropped IP.
        var ip_buf: [15]u8 = undefined;
        const ip_str = try std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
        try std.testing.expect(store.getLeaseByIp(ip_str) == null);
    }
}

test "hops is echoed in OFFER and ACK responses" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    // Build a DISCOVER with hops=3
    var buf = [_]u8{0} ** 512;
    @memset(&buf, 0);
    {
        const hdr: *DHCPHeader = @alignCast(@ptrCast(buf.ptr));
        hdr.op = 1; hdr.htype = 1; hdr.hlen = 6; hdr.hops = 3; hdr.xid = 0x11111111;
        hdr.magic = dhcp_magic_cookie;
        @memcpy(hdr.chaddr[0..6], &[6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01 });
        var i: usize = dhcp_min_packet_size;
        buf[i] = @intFromEnum(OptionCode.MessageType); buf[i+1] = 1; buf[i+2] = @intFromEnum(MessageType.DHCPDISCOVER); i += 3;
        buf[i] = @intFromEnum(OptionCode.End); i += 1;
        const resp = try server.processPacket(buf[0..i]);
        try std.testing.expect(resp != null);
        defer alloc.free(resp.?);
        const resp_hdr: *const DHCPHeader = @alignCast(@ptrCast(resp.?.ptr));
        try std.testing.expectEqual(@as(u8, 3), resp_hdr.hops);
    }

    // Build a REQUEST with hops=2
    {
        const len = makeRequest(&buf, [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01 }, [4]u8{ 192, 168, 1, 2 }, [4]u8{ 192, 168, 1, 1 }, null);
        const hdr: *DHCPHeader = @alignCast(@ptrCast(buf.ptr));
        hdr.hops = 2;
        const resp = try server.processPacket(buf[0..len]);
        try std.testing.expect(resp != null);
        defer alloc.free(resp.?);
        const resp_hdr: *const DHCPHeader = @alignCast(@ptrCast(resp.?.ptr));
        try std.testing.expectEqual(@as(u8, 2), resp_hdr.hops);
    }
}

test "createAck stores client_id from option 61" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    const mac = [6]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    const client_id_bytes = [_]u8{ 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }; // type=Ethernet + MAC

    var buf = [_]u8{0} ** 512;
    const len = makeRequest(&buf, mac, [4]u8{ 192, 168, 1, 50 }, [4]u8{ 192, 168, 1, 1 }, null);
    // Append option 61 before the End byte
    var pkt = buf[0..len];
    const end_pos = len - 1; // position of End option
    var new_buf = [_]u8{0} ** 512;
    @memcpy(new_buf[0..end_pos], pkt[0..end_pos]);
    var i: usize = end_pos;
    new_buf[i] = @intFromEnum(OptionCode.ClientID); i += 1;
    new_buf[i] = @intCast(client_id_bytes.len); i += 1;
    @memcpy(new_buf[i..][0..client_id_bytes.len], &client_id_bytes); i += client_id_bytes.len;
    new_buf[i] = @intFromEnum(OptionCode.End); i += 1;

    const resp = try server.processPacket(new_buf[0..i]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);
    try std.testing.expectEqual(MessageType.DHCPACK, DHCPServer.getMessageType(resp.?).?);

    const lease = store.getLeaseByMac("11:22:33:44:55:66");
    try std.testing.expect(lease != null);
    try std.testing.expect(lease.?.client_id != null);
    // Stored client_id should be hex of client_id_bytes
    try std.testing.expectEqualStrings("01112233445566", lease.?.client_id.?);
}

test "allocateIp reuses lease when client_id matches different MAC" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    // Pre-populate a lease with a client_id for one MAC.
    try store.addLease(.{
        .mac = "aa:bb:cc:dd:ee:ff",
        .ip = "192.168.1.42",
        .hostname = null,
        .expires = std.time.timestamp() + 3600,
        .client_id = "01aabbccddeeff",
    });

    // Allocate with a different MAC but same client_id raw bytes.
    const client_id_bytes = [_]u8{ 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const different_mac = [6]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    const ip = try server.allocateIp(different_mac, &client_id_bytes);
    try std.testing.expect(ip != null);
    // Should reuse the existing lease IP, not allocate a new one.
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 42 }, &ip.?);
}

test "isRequestedCode returns true when no PRL" {
    try std.testing.expect(isRequestedCode(null, 1));
    try std.testing.expect(isRequestedCode(null, 255));
}

test "isRequestedCode filters correctly" {
    const prl = [_]u8{ 1, 3, 6, 15 };
    try std.testing.expect(isRequestedCode(&prl, 1));
    try std.testing.expect(isRequestedCode(&prl, 6));
    try std.testing.expect(!isRequestedCode(&prl, 51)); // lease time not in PRL
    try std.testing.expect(!isRequestedCode(&prl, 42)); // NTP not in PRL
}

test "createOffer omits options not in PRL" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    var buf = [_]u8{0} ** 512;
    const hdr: *DHCPHeader = @alignCast(@ptrCast(buf.ptr));
    hdr.op = 1; hdr.htype = 1; hdr.hlen = 6; hdr.xid = 0x11223344;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01 });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType); buf[i+1] = 1; buf[i+2] = @intFromEnum(MessageType.DHCPDISCOVER); i += 3;
    // PRL with only subnet mask (1) and router (3) — no DNS (6), no lease time (51)
    buf[i] = @intFromEnum(OptionCode.ParameterRequestList); buf[i+1] = 2; buf[i+2] = 1; buf[i+3] = 3; i += 4;
    buf[i] = @intFromEnum(OptionCode.End); i += 1;

    const resp = try server.processPacket(buf[0..i]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);

    try std.testing.expectEqual(MessageType.DHCPOFFER, DHCPServer.getMessageType(resp.?).?);
    // Subnet mask and router should be present (requested)
    try std.testing.expect(DHCPServer.getOption(resp.?, .SubnetMask) != null);
    try std.testing.expect(DHCPServer.getOption(resp.?, .Router) != null);
    // DNS and lease time should be absent (not requested)
    try std.testing.expect(DHCPServer.getOption(resp.?, .DnsServer) == null);
    try std.testing.expect(DHCPServer.getOption(resp.?, .LeaseTime) == null);
    // MessageType and ServerIdentifier always present
    try std.testing.expect(DHCPServer.getOption(resp.?, .MessageType) != null);
    try std.testing.expect(DHCPServer.getOption(resp.?, .ServerIdentifier) != null);
}

test "handleInform returns DHCPACK with yiaddr=0" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    var buf = [_]u8{0} ** 512;
    @memset(&buf, 0);
    const hdr: *DHCPHeader = @alignCast(@ptrCast(buf.ptr));
    hdr.op = 1; hdr.htype = 1; hdr.hlen = 6; hdr.xid = 0xAABBCCDD;
    hdr.magic = dhcp_magic_cookie;
    hdr.ciaddr = [4]u8{ 192, 168, 1, 55 }; // client already has an IP
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType); buf[i+1] = 1; buf[i+2] = @intFromEnum(MessageType.DHCPINFORM); i += 3;
    buf[i] = @intFromEnum(OptionCode.End); i += 1;

    const resp = try server.processPacket(buf[0..i]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);

    // Must be DHCPACK
    try std.testing.expectEqual(MessageType.DHCPACK, DHCPServer.getMessageType(resp.?).?);

    // yiaddr must be 0 (no address assigned)
    const resp_hdr: *const DHCPHeader = @alignCast(@ptrCast(resp.?.ptr));
    try std.testing.expectEqualSlices(u8, &[4]u8{ 0, 0, 0, 0 }, &resp_hdr.yiaddr);

    // ciaddr should be echoed
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 55 }, &resp_hdr.ciaddr);

    // Should include subnet mask (option 1)
    try std.testing.expect(DHCPServer.getOption(resp.?, .SubnetMask) != null);

    // No lease should have been created
    try std.testing.expectEqual(@as(usize, 0), store.leases.count());
}

test "encodeOptionValue: single valid IP" {
    var buf: [16]u8 = undefined;
    const result = encodeOptionValue(&buf, "192.168.1.1");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 1 }, result);
}

test "encodeOptionValue: two valid IPs" {
    var buf: [16]u8 = undefined;
    const result = encodeOptionValue(&buf, "192.168.1.1,192.168.1.2");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 1, 192, 168, 1, 2 }, result);
}

test "encodeOptionValue: raw string fallback" {
    var buf: [32]u8 = undefined;
    const result = encodeOptionValue(&buf, "example.com");
    try std.testing.expectEqualSlices(u8, "example.com", result);
}

test "encodeOptionValue: partial parse falls back to raw string" {
    var buf: [32]u8 = undefined;
    // First token is valid IP, second is not — must fall back to raw string
    const result = encodeOptionValue(&buf, "192.168.1.1,bad");
    try std.testing.expectEqualSlices(u8, "192.168.1.1,bad", result);
}

test "isIpValid rejects router IP" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    // makeTestConfig sets router = "192.168.1.1"
    const router_ip = [4]u8{ 192, 168, 1, 1 };
    try std.testing.expect(!server.isIpValid(router_ip, "aa:bb:cc:dd:ee:ff", null));
}

test "DHCPREQUEST for router IP results in DHCPNAK" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    var buf = [_]u8{0} ** 512;
    const hdr: *DHCPHeader = @alignCast(@ptrCast(buf.ptr));
    hdr.op = 1; hdr.htype = 1; hdr.hlen = 6; hdr.xid = 0xDEAD;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType); buf[i+1] = 1; buf[i+2] = @intFromEnum(MessageType.DHCPREQUEST); i += 3;
    // Request the router's IP address (192.168.1.1)
    buf[i] = @intFromEnum(OptionCode.RequestedIpAddress); buf[i+1] = 4;
    buf[i+2] = 192; buf[i+3] = 168; buf[i+4] = 1; buf[i+5] = 1; i += 6;
    buf[i] = @intFromEnum(OptionCode.End); i += 1;

    const resp = try server.processPacket(buf[0..i]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);
    try std.testing.expectEqual(MessageType.DHCPNAK, DHCPServer.getMessageType(resp.?).?);
}

// ---------------------------------------------------------------------------
// Reservation tests
// ---------------------------------------------------------------------------

/// Helper: insert a reserved lease directly into the store (bypasses save).
fn putReservationInStore(store: *StateStore, mac: []const u8, ip: []const u8, hostname: ?[]const u8) !void {
    const mac_owned = try store.allocator.dupe(u8, mac);
    errdefer store.allocator.free(mac_owned);
    const ip_owned = try store.allocator.dupe(u8, ip);
    errdefer store.allocator.free(ip_owned);
    const hn_owned: ?[]const u8 = if (hostname) |h| try store.allocator.dupe(u8, h) else null;
    errdefer if (hn_owned) |h| store.allocator.free(h);
    try store.leases.put(mac_owned, .{
        .mac = mac_owned,
        .ip = ip_owned,
        .hostname = hn_owned,
        .expires = 0,
        .client_id = null,
        .reserved = true,
    });
}

test "allocateIp returns reserved IP for matching MAC" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    try putReservationInStore(store, "aa:bb:cc:dd:ee:ff", "192.168.1.50", null);

    const ip = try server.allocateIp([6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, null);
    try std.testing.expect(ip != null);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 50 }, &ip.?);
}

test "allocateIp skips reserved IP for non-matching client" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    // Set tight pool so only .50 is available; if skipped, nothing else exists.
    alloc.free(cfg.pool_start);
    alloc.free(cfg.pool_end);
    cfg.pool_start = try alloc.dupe(u8, "192.168.1.50");
    cfg.pool_end = try alloc.dupe(u8, "192.168.1.50");
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    // Reserve .50 for a specific MAC.
    try putReservationInStore(store, "aa:bb:cc:dd:ee:ff", "192.168.1.50", null);

    // A different MAC should get null (pool only has .50, which is reserved).
    const ip = try server.allocateIp([6]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, null);
    try std.testing.expect(ip == null);
}

test "isIpValid rejects reserved IP for non-matching MAC" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    try putReservationInStore(store, "aa:bb:cc:dd:ee:ff", "192.168.1.50", null);

    // Non-matching MAC requesting the reserved IP — should be rejected.
    try std.testing.expect(!server.isIpValid([4]u8{ 192, 168, 1, 50 }, "11:22:33:44:55:66", null));
    // Matching MAC — should be accepted.
    try std.testing.expect(server.isIpValid([4]u8{ 192, 168, 1, 50 }, "aa:bb:cc:dd:ee:ff", null));
}

test "createAck: reserved client gets reserved IP and option 12 hostname" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    try putReservationInStore(store, "aa:bb:cc:dd:ee:ff", "192.168.1.50", "printer");

    // Build REQUEST with PRL requesting hostname (12).
    var buf = [_]u8{0} ** 512;
    @memset(&buf, 0);
    const hdr: *DHCPHeader = @alignCast(@ptrCast(buf.ptr));
    hdr.op = 1; hdr.htype = 1; hdr.hlen = 6; hdr.xid = 0xAABBCCDD;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType); buf[i+1] = 1; buf[i+2] = @intFromEnum(MessageType.DHCPREQUEST); i += 3;
    buf[i] = @intFromEnum(OptionCode.RequestedIPAddress); buf[i+1] = 4;
    buf[i+2] = 192; buf[i+3] = 168; buf[i+4] = 1; buf[i+5] = 50; i += 6;
    buf[i] = @intFromEnum(OptionCode.ServerIdentifier); buf[i+1] = 4;
    buf[i+2] = 192; buf[i+3] = 168; buf[i+4] = 1; buf[i+5] = 1; i += 6;
    buf[i] = @intFromEnum(OptionCode.ParameterRequestList); buf[i+1] = 1; buf[i+2] = 12; i += 3; // request hostname
    buf[i] = @intFromEnum(OptionCode.End); i += 1;

    const resp = try server.processPacket(buf[0..i]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);

    try std.testing.expectEqual(MessageType.DHCPACK, DHCPServer.getMessageType(resp.?).?);

    // Option 12 should contain "printer".
    const hn_opt = DHCPServer.getOption(resp.?, .HostName);
    try std.testing.expect(hn_opt != null);
    try std.testing.expectEqualStrings("printer", hn_opt.?);

    // Stored lease should be reserved and have the hostname.
    const lease = store.getLeaseByMac("aa:bb:cc:dd:ee:ff");
    try std.testing.expect(lease != null);
    try std.testing.expect(lease.?.reserved);
    try std.testing.expect(lease.?.hostname != null);
    try std.testing.expectEqualStrings("printer", lease.?.hostname.?);
}

test "DHCPNAK: non-matching client denied reserved IP" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    try putReservationInStore(store, "aa:bb:cc:dd:ee:ff", "192.168.1.50", null);

    var buf = [_]u8{0} ** 512;
    const len = makeRequest(
        &buf,
        [6]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, // different MAC
        [4]u8{ 192, 168, 1, 50 }, // reserved IP
        [4]u8{ 192, 168, 1, 1 },
        null,
    );
    const resp = try server.processPacket(buf[0..len]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);
    try std.testing.expectEqual(MessageType.DHCPNAK, DHCPServer.getMessageType(resp.?).?);
}

test "removeLease on reserved lease keeps entry with expires=0 (RELEASE)" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, store, null);
    defer server.deinit();

    // Seed an active reservation.
    try store.addReservation("aa:bb:cc:dd:ee:ff", "192.168.1.50", "printer", null);
    // Set expiry to simulate an active lease.
    store.leases.getPtr("aa:bb:cc:dd:ee:ff").?.expires = std.time.timestamp() + 3600;

    // Build a RELEASE.
    var buf = [_]u8{0} ** 512;
    @memset(&buf, 0);
    const hdr: *DHCPHeader = @alignCast(@ptrCast(buf.ptr));
    hdr.op = 1; hdr.htype = 1; hdr.hlen = 6; hdr.xid = 0x11223344;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType); buf[i+1] = 1; buf[i+2] = @intFromEnum(MessageType.DHCPRELEASE); i += 3;
    buf[i] = @intFromEnum(OptionCode.End); i += 1;

    const resp = try server.processPacket(buf[0..i]);
    try std.testing.expect(resp == null); // RELEASE has no response

    // Entry must still exist with expires=0.
    const entry = store.leases.get("aa:bb:cc:dd:ee:ff");
    try std.testing.expect(entry != null);
    try std.testing.expectEqual(@as(i64, 0), entry.?.expires);
    try std.testing.expect(entry.?.reserved);
}
