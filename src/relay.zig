/// DHCP relay agent (RFC 2131 §4.1, RFC 3046).
///
/// Listens on downstream interfaces for client DHCP broadcasts, sets giaddr,
/// optionally stamps Option 82, and forwards to upstream server(s). Receives
/// server replies and routes them back to the correct downstream interface.
const std = @import("std");
const dhcp = @import("./dhcp_common.zig");
const relay_config = @import("./relay_config.zig");

const IFNAMSIZ: usize = 16;
const SIOCGIFADDR: u32 = 0x8915;
const SIOCGIFFLAGS: u32 = 0x8913;
const SIOCGIFINDEX: u32 = 0x8933;

const IFF_UP: u16 = 0x1;
const IFF_LOOPBACK: u16 = 0x8;

const IFReq = extern struct {
    name: [IFNAMSIZ]u8,
    data: [16]u8,
};

/// A downstream interface with its own bound socket.
const DownstreamIface = struct {
    name: [IFNAMSIZ]u8,
    name_len: usize,
    ip: [4]u8,
    sock_fd: std.posix.fd_t,
    if_index: u32,

    fn nameSlice(self: *const DownstreamIface) []const u8 {
        return self.name[0..self.name_len];
    }
};

/// Atomic counters for relay statistics.
pub const Counters = struct {
    requests_relayed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    replies_relayed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    packets_dropped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

pub const RelayAgent = struct {
    allocator: std.mem.Allocator,
    cfg: relay_config.RelayConfig,
    cfg_path: []const u8,
    downstream: []DownstreamIface,
    upstream_addrs: []std.posix.sockaddr.in,
    /// Dedicated socket for sending to upstream (not bound to any downstream interface).
    upstream_sock: std.posix.fd_t,
    counters: Counters,
    log_level: *std.log.Level,

    pub fn init(allocator: std.mem.Allocator, cfg: relay_config.RelayConfig, cfg_path: []const u8, log_level: *std.log.Level) !RelayAgent {
        // Parse upstream server addresses.
        var addrs = std.ArrayList(std.posix.sockaddr.in){};
        errdefer addrs.deinit(allocator);
        for (cfg.upstream_servers) |server_str| {
            const ip = dhcp.parseIpv4(server_str) catch {
                std.log.err("invalid upstream server IP: {s}", .{server_str});
                return error.InvalidConfig;
            };
            try addrs.append(allocator, .{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, dhcp.dhcp_server_port),
                .addr = @bitCast(ip),
            });
        }

        // Detect upstream interface (used for both downstream exclusion and
        // binding the upstream socket to avoid stealing client broadcasts).
        const upstream_iface = detectUpstreamIface(addrs.items) catch |err| blk: {
            std.log.warn("could not detect upstream interface: {s}", .{@errorName(err)});
            break :blk null;
        };

        // Detect or configure downstream interfaces.
        var ifaces = std.ArrayList(DownstreamIface){};
        errdefer {
            for (ifaces.items) |*iface| closeSock(iface.sock_fd);
            ifaces.deinit(allocator);
        }

        if (cfg.downstream_ip.len > 0) {
            // Simple mode: single downstream IP, find its interface.
            const ip = dhcp.parseIpv4(cfg.downstream_ip) catch {
                std.log.err("invalid downstream_ip: {s}", .{cfg.downstream_ip});
                return error.InvalidConfig;
            };
            const iface = try findIfaceByIp(ip) orelse {
                std.log.err("no interface found with IP {s}", .{cfg.downstream_ip});
                return error.InterfaceNotFound;
            };
            const sock = try bindDownstreamSocket(&iface.name);
            try ifaces.append(allocator, .{
                .name = iface.name,
                .name_len = iface.name_len,
                .ip = ip,
                .sock_fd = sock,
                .if_index = iface.if_index,
            });
        } else if (cfg.downstream_interfaces.len > 0) {
            // Manual mode: bind to explicitly listed interfaces.
            for (cfg.downstream_interfaces) |iface_name| {
                const info = try findIfaceByName(iface_name) orelse {
                    std.log.err("interface not found: {s}", .{iface_name});
                    return error.InterfaceNotFound;
                };
                const sock = try bindDownstreamSocket(&info.name);
                try ifaces.append(allocator, .{
                    .name = info.name,
                    .name_len = info.name_len,
                    .ip = info.ip,
                    .sock_fd = sock,
                    .if_index = info.if_index,
                });
            }
        } else {
            // Auto-detect: find all suitable interfaces, excluding the upstream route.
            const exclude_ip = if (upstream_iface) |ui| ui.ip else [4]u8{ 0, 0, 0, 0 };
            try autoDetectDownstream(allocator, exclude_ip, &ifaces);
        }

        if (ifaces.items.len == 0) {
            std.log.err("no downstream interfaces found — specify downstream_interfaces or downstream_ip in config", .{});
            return error.InterfaceNotFound;
        }

        for (ifaces.items) |iface| {
            std.log.info("downstream: {s} ({d}.{d}.{d}.{d})", .{
                iface.nameSlice(),
                iface.ip[0],
                iface.ip[1],
                iface.ip[2],
                iface.ip[3],
            });
        }
        for (cfg.upstream_servers) |s| {
            std.log.info("upstream: {s}", .{s});
        }

        // Create the upstream socket for receiving server replies. Bound to
        // port 67 with SO_BINDTODEVICE on the upstream interface so it only
        // receives packets arriving on that interface — prevents the kernel
        // from delivering client broadcasts (on downstream interfaces) to
        // this socket instead of the downstream sockets.
        const upstream_sock = try createUdpSocket();
        errdefer closeSock(upstream_sock);
        try std.posix.setsockopt(upstream_sock, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
        try setBroadcast(upstream_sock);
        if (upstream_iface) |ui| {
            try std.posix.setsockopt(upstream_sock, std.posix.SOL.SOCKET, std.posix.SO.BINDTODEVICE, &ui.name);
            std.log.info("upstream socket bound to {s} ({d}.{d}.{d}.{d})", .{
                ui.name[0..ui.name_len],
                ui.ip[0],
                ui.ip[1],
                ui.ip[2],
                ui.ip[3],
            });
        } else {
            std.log.err("upstream socket bound to all interfaces (could not detect upstream interface) — client broadcasts may be dropped; set downstream_interfaces in config to avoid this", .{});
        }
        const upstream_bind = std.posix.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, dhcp.dhcp_server_port),
            .addr = 0, // INADDR_ANY
        };
        try std.posix.bind(upstream_sock, @ptrCast(&upstream_bind), @sizeOf(std.posix.sockaddr.in));

        return .{
            .allocator = allocator,
            .cfg = cfg,
            .cfg_path = cfg_path,
            .downstream = try ifaces.toOwnedSlice(allocator),
            .upstream_addrs = try addrs.toOwnedSlice(allocator),
            .upstream_sock = upstream_sock,
            .counters = .{},
            .log_level = log_level,
        };
    }

    pub fn deinit(self: *RelayAgent) void {
        for (self.downstream) |*iface| closeSock(iface.sock_fd);
        closeSock(self.upstream_sock);
        self.allocator.free(self.downstream);
        self.allocator.free(self.upstream_addrs);
        self.cfg.deinit(self.allocator);
    }

    /// Reload config from disk. Updates upstream servers, option82, max_hops,
    /// and log level. Downstream sockets are not touched (rebinding would drop traffic).
    fn reloadConfig(self: *RelayAgent) void {
        std.log.info("reloading configuration from {s}...", .{self.cfg_path});
        var new_cfg = relay_config.load(self.allocator, self.cfg_path) catch |err| {
            std.log.err("config reload failed ({s}), keeping existing config", .{@errorName(err)});
            return;
        };

        // Rebuild upstream server addresses.
        var addrs = std.ArrayList(std.posix.sockaddr.in){};
        for (new_cfg.upstream_servers) |server_str| {
            const ip = dhcp.parseIpv4(server_str) catch {
                std.log.err("config reload: invalid upstream server IP: {s}, keeping existing config", .{server_str});
                addrs.deinit(self.allocator);
                new_cfg.deinit(self.allocator);
                return;
            };
            addrs.append(self.allocator, .{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, dhcp.dhcp_server_port),
                .addr = @bitCast(ip),
            }) catch {
                std.log.err("config reload: out of memory, keeping existing config", .{});
                addrs.deinit(self.allocator);
                new_cfg.deinit(self.allocator);
                return;
            };
        }
        if (addrs.items.len == 0) {
            std.log.err("config reload: upstream_servers is empty, keeping existing config", .{});
            addrs.deinit(self.allocator);
            new_cfg.deinit(self.allocator);
            return;
        }

        // Finalise new addrs before freeing old ones — if this fails we keep old state.
        const new_addrs = addrs.toOwnedSlice(self.allocator) catch {
            std.log.err("config reload: out of memory finalising upstream addrs", .{});
            addrs.deinit(self.allocator);
            new_cfg.deinit(self.allocator);
            return;
        };

        // Swap in the new config — free old resources.
        self.allocator.free(self.upstream_addrs);
        self.upstream_addrs = new_addrs;
        self.cfg.deinit(self.allocator);
        self.cfg = new_cfg;
        self.log_level.* = self.cfg.log_level;

        std.log.info("configuration reloaded ({d} upstream server(s), max_hops={d}, option82={s})", .{
            self.upstream_addrs.len,
            self.cfg.max_hops,
            if (self.cfg.option82.enable) "on" else "off",
        });
    }

    /// Main relay loop. Blocks until `running` is set to false.
    pub fn run(self: *RelayAgent, running: *std.atomic.Value(bool), reload: *std.atomic.Value(bool)) void {
        std.log.info("relay started, {d} downstream interface(s), {d} upstream server(s)", .{
            self.downstream.len, self.upstream_addrs.len,
        });

        // Build poll fds: downstream sockets + upstream socket for server replies.
        var poll_fds_buf: [65]std.posix.pollfd = undefined; // 64 downstream + 1 upstream
        const n_downstream = @min(self.downstream.len, 64);
        for (self.downstream[0..n_downstream], 0..) |iface, i| {
            poll_fds_buf[i] = .{
                .fd = iface.sock_fd,
                .events = std.posix.POLL.IN,
                .revents = 0,
            };
        }
        // Upstream socket is the last entry in the poll set.
        poll_fds_buf[n_downstream] = .{
            .fd = self.upstream_sock,
            .events = std.posix.POLL.IN,
            .revents = 0,
        };
        const poll_fds = poll_fds_buf[0 .. n_downstream + 1];

        var buf: [1500]u8 = undefined;
        var src_addr: std.posix.sockaddr.in = undefined;
        var src_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);

        while (running.load(.monotonic)) {
            if (reload.load(.monotonic)) {
                reload.store(false, .monotonic);
                self.reloadConfig();
            }

            const ready = std.posix.poll(poll_fds, 500) catch |err| {
                std.log.err("poll error: {s}", .{@errorName(err)});
                continue;
            };
            if (ready == 0) continue;

            for (poll_fds, 0..) |pfd, idx| {
                if (pfd.revents & std.posix.POLL.IN == 0) continue;

                src_len = @sizeOf(std.posix.sockaddr.in);
                const n = std.posix.recvfrom(
                    pfd.fd,
                    &buf,
                    0,
                    @ptrCast(&src_addr),
                    &src_len,
                ) catch |err| {
                    std.log.debug("recvfrom error: {s}", .{@errorName(err)});
                    continue;
                };

                if (n < dhcp.dhcp_min_packet_size) continue;
                const packet = buf[0..n];

                // Validate magic cookie.
                const hdr: *dhcp.DHCPHeader = @ptrCast(@alignCast(packet.ptr));
                if (!std.mem.eql(u8, &hdr.magic, &dhcp.dhcp_magic_cookie)) continue;

                const is_upstream = (idx == n_downstream);

                if (hdr.op == 1 and !is_upstream) {
                    // BOOTREQUEST on a downstream socket: client → server
                    self.relayClientToServer(packet, &self.downstream[idx]);
                } else if (hdr.op == 1 and is_upstream) {
                    // BOOTREQUEST on the upstream socket — shouldn't happen when
                    // SO_BINDTODEVICE is set correctly. Log for troubleshooting.
                    std.log.debug("dropping BOOTREQUEST received on upstream socket", .{});
                } else if (hdr.op == 2) {
                    // BOOTREPLY (typically on upstream socket): server → client
                    self.relayServerToClient(packet);
                }
            }
        }

        std.log.info("relay stopped (relayed {d} requests, {d} replies, dropped {d})", .{
            self.counters.requests_relayed.load(.monotonic),
            self.counters.replies_relayed.load(.monotonic),
            self.counters.packets_dropped.load(.monotonic),
        });
    }

    /// Forward a client BOOTREQUEST to all upstream servers.
    fn relayClientToServer(self: *RelayAgent, packet: []u8, iface: *const DownstreamIface) void {
        const hdr: *dhcp.DHCPHeader = @ptrCast(@alignCast(packet.ptr));

        // Loop prevention: drop if hops too high.
        if (hdr.hops >= self.cfg.max_hops) {
            std.log.debug("dropping packet: hops {d} >= max {d}", .{ hdr.hops, self.cfg.max_hops });
            _ = self.counters.packets_dropped.fetchAdd(1, .monotonic);
            return;
        }
        hdr.hops += 1;

        // Set giaddr to this downstream interface's IP (only if not already set by another relay).
        if (std.mem.eql(u8, &hdr.giaddr, &[_]u8{ 0, 0, 0, 0 })) {
            hdr.giaddr = iface.ip;
        }

        // Option 82 handling.
        var out_buf: [1500]u8 = undefined;
        const send_pkt = self.applyOption82(packet, iface, &out_buf) orelse packet;

        // Forward to all upstream servers.
        for (self.upstream_addrs) |addr| {
            _ = std.posix.sendto(
                self.upstream_sock,
                send_pkt,
                0,
                @ptrCast(&addr),
                @sizeOf(std.posix.sockaddr.in),
            ) catch |err| {
                std.log.warn("sendto upstream failed: {s}", .{@errorName(err)});
                continue;
            };
        }

        if (std.log.defaultLogEnabled(.debug)) {
            const mt = dhcp.getMessageType(send_pkt);
            var mac_buf: [17]u8 = undefined;
            const mac = dhcp.formatMac(hdr.chaddr[0..6].*, &mac_buf);
            if (mt) |t| {
                std.log.debug("relayed {s} from {s} via {s}", .{
                    @tagName(t), mac, iface.nameSlice(),
                });
            }
        }

        _ = self.counters.requests_relayed.fetchAdd(1, .monotonic);
    }

    /// Forward a server BOOTREPLY to the appropriate downstream client.
    fn relayServerToClient(self: *RelayAgent, packet: []u8) void {
        const hdr: *dhcp.DHCPHeader = @ptrCast(@alignCast(packet.ptr));

        // Find the downstream interface matching giaddr.
        var target_iface: ?*const DownstreamIface = null;
        for (self.downstream) |*iface| {
            if (std.mem.eql(u8, &hdr.giaddr, &iface.ip)) {
                target_iface = iface;
                break;
            }
        }
        if (target_iface == null) {
            std.log.debug("dropping reply: giaddr {d}.{d}.{d}.{d} doesn't match any downstream interface", .{
                hdr.giaddr[0], hdr.giaddr[1], hdr.giaddr[2], hdr.giaddr[3],
            });
            _ = self.counters.packets_dropped.fetchAdd(1, .monotonic);
            return;
        }
        const iface = target_iface.?;

        // Strip Option 82 if we added it.
        var out_buf: [1500]u8 = undefined;
        const send_pkt = self.stripOption82(packet, &out_buf) orelse packet;

        // Determine client destination.
        const dst_addr = clientDestination(send_pkt);

        _ = std.posix.sendto(
            iface.sock_fd,
            send_pkt,
            0,
            @ptrCast(&dst_addr),
            @sizeOf(std.posix.sockaddr.in),
        ) catch |err| {
            std.log.warn("sendto client failed: {s}", .{@errorName(err)});
            return;
        };

        if (std.log.defaultLogEnabled(.debug)) {
            const mt = dhcp.getMessageType(send_pkt);
            var mac_buf: [17]u8 = undefined;
            const mac = dhcp.formatMac(hdr.chaddr[0..6].*, &mac_buf);
            if (mt) |t| {
                std.log.debug("relayed {s} to {s} via {s}", .{
                    @tagName(t), mac, iface.nameSlice(),
                });
            }
        }

        _ = self.counters.replies_relayed.fetchAdd(1, .monotonic);
    }

    // -----------------------------------------------------------------
    // Option 82 manipulation
    // -----------------------------------------------------------------

    /// Apply Option 82 to a client→server packet per the configured policy.
    /// Returns a slice into out_buf with the modified packet, or null if no change.
    fn applyOption82(self: *const RelayAgent, packet: []const u8, iface: *const DownstreamIface, out_buf: []u8) ?[]u8 {
        if (!self.cfg.option82.enable) return null;

        const policy = self.cfg.option82.policy;
        if (policy == .drop) {
            // Strip existing, don't add.
            return stripOption82Raw(packet, out_buf);
        }

        // Build our Option 82 payload.
        var opt82_payload: [255]u8 = undefined;
        var opt82_len: usize = 0;

        // Sub-option 1: Circuit ID
        const circuit_id = if (std.mem.eql(u8, self.cfg.option82.circuit_id, "auto"))
            iface.nameSlice()
        else
            self.cfg.option82.circuit_id;

        if (circuit_id.len > 0 and circuit_id.len <= 251) {
            opt82_payload[opt82_len] = 1; // sub-option type
            opt82_payload[opt82_len + 1] = @intCast(circuit_id.len);
            @memcpy(opt82_payload[opt82_len + 2 ..][0..circuit_id.len], circuit_id);
            opt82_len += 2 + circuit_id.len;
        }

        // Sub-option 2: Remote ID
        const remote_id = self.cfg.option82.remote_id;
        if (remote_id.len > 0 and remote_id.len <= 251 and opt82_len + 2 + remote_id.len <= 255) {
            opt82_payload[opt82_len] = 2; // sub-option type
            opt82_payload[opt82_len + 1] = @intCast(remote_id.len);
            @memcpy(opt82_payload[opt82_len + 2 ..][0..remote_id.len], remote_id);
            opt82_len += 2 + remote_id.len;
        }

        if (opt82_len == 0) return null;

        switch (policy) {
            .replace => {
                // Strip existing, then append ours.
                const stripped = stripOption82Raw(packet, out_buf) orelse blk: {
                    // No existing option 82 — copy packet as-is.
                    if (packet.len > out_buf.len) return null;
                    @memcpy(out_buf[0..packet.len], packet);
                    break :blk out_buf[0..packet.len];
                };
                return appendOption82(stripped, out_buf, opt82_payload[0..opt82_len]);
            },
            .append => {
                // Keep existing, append ours.
                if (packet.len > out_buf.len) return null;
                @memcpy(out_buf[0..packet.len], packet);
                return appendOption82(out_buf[0..packet.len], out_buf, opt82_payload[0..opt82_len]);
            },
            .keep => {
                // Only add if no existing option 82.
                if (dhcp.getOption(packet, .RelayAgentInformation) != null) return null;
                if (packet.len > out_buf.len) return null;
                @memcpy(out_buf[0..packet.len], packet);
                return appendOption82(out_buf[0..packet.len], out_buf, opt82_payload[0..opt82_len]);
            },
            .drop => unreachable, // handled above
        }
    }

    /// Strip Option 82 from a server→client reply. Returns modified packet or null.
    fn stripOption82(self: *const RelayAgent, packet: []const u8, out_buf: []u8) ?[]u8 {
        if (!self.cfg.option82.enable) return null;
        if (self.cfg.option82.policy == .drop) return null;
        return stripOption82Raw(packet, out_buf);
    }
};

// ---------------------------------------------------------------------------
// Option 82 helpers (free functions for testability)
// ---------------------------------------------------------------------------

/// Strip all Option 82 entries from a DHCP packet. Returns the new packet
/// in out_buf, or null if no Option 82 was found.
fn stripOption82Raw(packet: []const u8, out_buf: []u8) ?[]u8 {
    if (packet.len < dhcp.dhcp_min_packet_size) return null;
    const hdr_size = dhcp.dhcp_min_packet_size;

    // Copy the header.
    if (hdr_size > out_buf.len) return null;
    @memcpy(out_buf[0..hdr_size], packet[0..hdr_size]);

    const opts = packet[hdr_size..];
    var out_pos: usize = hdr_size;
    var i: usize = 0;
    var found = false;

    while (i < opts.len) {
        const code = opts[i];
        if (code == @intFromEnum(dhcp.OptionCode.End)) break;
        if (code == @intFromEnum(dhcp.OptionCode.Pad)) {
            if (out_pos + 1 < out_buf.len) { // reserve 1 byte for End marker
                out_buf[out_pos] = 0;
                out_pos += 1;
            }
            i += 1;
            continue;
        }
        if (i + 1 >= opts.len) break;
        const len = opts[i + 1];
        if (i + 2 + len > opts.len) break;

        if (code == @intFromEnum(dhcp.OptionCode.RelayAgentInformation)) {
            found = true;
            i += 2 + len;
            continue; // skip this option
        }

        // Copy option (reserve 1 byte for End marker).
        const opt_total = 2 + @as(usize, len);
        if (out_pos + opt_total + 1 > out_buf.len) break;
        @memcpy(out_buf[out_pos..][0..opt_total], opts[i..][0..opt_total]);
        out_pos += opt_total;
        i += opt_total;
    }

    if (!found) return null;

    // Write End marker.
    out_buf[out_pos] = @intFromEnum(dhcp.OptionCode.End);
    out_pos += 1;

    return out_buf[0..out_pos];
}

/// Append an Option 82 TLV to a DHCP packet (already in out_buf).
/// Finds the End marker, writes option 82 before it, then re-writes End.
/// Returns the extended slice, or null if there's no room.
fn appendOption82(packet: []u8, out_buf: []u8, payload: []const u8) ?[]u8 {
    if (packet.len < dhcp.dhcp_min_packet_size) return null;

    // Find the End marker in the options.
    const opts_start = dhcp.dhcp_min_packet_size;
    var end_pos: ?usize = null;
    var i: usize = 0;
    const opts = packet[opts_start..];
    while (i < opts.len) {
        const code = opts[i];
        if (code == @intFromEnum(dhcp.OptionCode.End)) {
            end_pos = opts_start + i;
            break;
        }
        if (code == @intFromEnum(dhcp.OptionCode.Pad)) {
            i += 1;
            continue;
        }
        if (i + 1 >= opts.len) break;
        i += 2 + @as(usize, opts[i + 1]);
    }

    const pos = end_pos orelse return null;
    if (payload.len > 255) return null; // DHCP option length field is a single byte
    const needed = 2 + payload.len + 1; // code + len + payload + End
    if (pos + needed > out_buf.len) return null;

    // Write Option 82 TLV.
    out_buf[pos] = @intFromEnum(dhcp.OptionCode.RelayAgentInformation);
    out_buf[pos + 1] = @intCast(payload.len);
    @memcpy(out_buf[pos + 2 ..][0..payload.len], payload);

    // Write new End marker.
    out_buf[pos + 2 + payload.len] = @intFromEnum(dhcp.OptionCode.End);

    return out_buf[0 .. pos + 2 + payload.len + 1];
}

// ---------------------------------------------------------------------------
// Client destination routing (for server→client replies)
// ---------------------------------------------------------------------------

/// Determine where to forward a BOOTREPLY to the client.
/// Unlike resolveDestination (which is for server responses), the relay
/// forwards replies to the client — so giaddr routing doesn't apply here.
fn clientDestination(packet: []const u8) std.posix.sockaddr.in {
    if (packet.len >= dhcp.dhcp_min_packet_size) {
        const hdr: *const dhcp.DHCPHeader = @ptrCast(@alignCast(packet.ptr));

        // If client has an IP, unicast to it.
        if (!std.mem.eql(u8, &hdr.ciaddr, &[_]u8{ 0, 0, 0, 0 })) {
            return .{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, dhcp.dhcp_client_port),
                .addr = @bitCast(hdr.ciaddr),
            };
        }

        // Broadcast flag set — broadcast.
        if (std.mem.nativeToBig(u16, hdr.flags) & 0x8000 != 0) {
            return .{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, dhcp.dhcp_client_port),
                .addr = 0xFFFFFFFF,
            };
        }
    }

    // Fallback: broadcast.
    return .{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, dhcp.dhcp_client_port),
        .addr = 0xFFFFFFFF,
    };
}

// ---------------------------------------------------------------------------
// Interface detection helpers
// ---------------------------------------------------------------------------

const IfaceDetectInfo = struct {
    name: [IFNAMSIZ]u8,
    name_len: usize,
    ip: [4]u8,
    if_index: u32,
};

fn findIfaceByIp(target_ip: [4]u8) !?IfaceDetectInfo {
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(sock);

    var dir = try std.fs.openDirAbsolute("/sys/class/net", .{ .iterate = true });
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.name.len == 0 or entry.name.len >= IFNAMSIZ) continue;

        var req = std.mem.zeroes(IFReq);
        @memcpy(req.name[0..entry.name.len], entry.name);

        // Get IP address.
        var rc = std.os.linux.ioctl(sock, SIOCGIFADDR, @intFromPtr(&req));
        if (@as(isize, @bitCast(rc)) < 0) continue;
        if (!std.mem.eql(u8, req.data[4..8], &target_ip)) continue;

        // Get interface index.
        @memset(&req.data, 0);
        rc = std.os.linux.ioctl(sock, SIOCGIFINDEX, @intFromPtr(&req));
        if (@as(isize, @bitCast(rc)) < 0) continue;
        const if_index: u32 = @bitCast(std.mem.readInt(i32, req.data[0..4], @import("builtin").cpu.arch.endian()));

        var result: IfaceDetectInfo = undefined;
        result.name = std.mem.zeroes([IFNAMSIZ]u8);
        @memcpy(result.name[0..entry.name.len], entry.name);
        result.name_len = entry.name.len;
        result.ip = target_ip;
        result.if_index = if_index;
        return result;
    }
    return null;
}

fn findIfaceByName(name: []const u8) !?IfaceDetectInfo {
    if (name.len == 0 or name.len >= IFNAMSIZ) return null;

    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(sock);

    var req = std.mem.zeroes(IFReq);
    @memcpy(req.name[0..name.len], name);

    // Get IP address.
    var rc = std.os.linux.ioctl(sock, SIOCGIFADDR, @intFromPtr(&req));
    if (@as(isize, @bitCast(rc)) < 0) return null;
    const ip: [4]u8 = req.data[4..8].*;

    // Get interface index.
    @memset(&req.data, 0);
    rc = std.os.linux.ioctl(sock, SIOCGIFINDEX, @intFromPtr(&req));
    if (@as(isize, @bitCast(rc)) < 0) return null;
    const if_index: u32 = @bitCast(std.mem.readInt(i32, req.data[0..4], @import("builtin").cpu.arch.endian()));

    var result: IfaceDetectInfo = undefined;
    result.name = std.mem.zeroes([IFNAMSIZ]u8);
    @memcpy(result.name[0..name.len], name);
    result.name_len = name.len;
    result.ip = ip;
    result.if_index = if_index;
    return result;
}

/// Detect which local interface routes to the upstream servers (by connecting a
/// UDP socket and calling getsockname). Returns the interface info, which
/// identifies the upstream-facing interface for SO_BINDTODEVICE on the upstream
/// socket and to exclude from downstream auto-detection.
fn detectUpstreamIface(upstream_addrs: []const std.posix.sockaddr.in) !IfaceDetectInfo {
    if (upstream_addrs.len == 0) return error.NoUpstream;

    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    defer std.posix.close(sock);

    // Connect to the first upstream server (UDP connect doesn't send packets,
    // just sets the default destination so getsockname reveals the source IP).
    try std.posix.connect(sock, @ptrCast(&upstream_addrs[0]), @sizeOf(std.posix.sockaddr.in));

    var local: std.posix.sockaddr.in = undefined;
    var local_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
    try std.posix.getsockname(sock, @ptrCast(&local), &local_len);

    const ip: [4]u8 = @bitCast(local.addr);
    return (try findIfaceByIp(ip)) orelse error.InterfaceNotFound;
}

/// Auto-detect downstream interfaces: all UP, non-loopback interfaces with an
/// IPv4 address, excluding the one whose IP matches the upstream route.
fn autoDetectDownstream(
    allocator: std.mem.Allocator,
    upstream_ip: [4]u8,
    ifaces: *std.ArrayList(DownstreamIface),
) !void {
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(sock);

    var dir = try std.fs.openDirAbsolute("/sys/class/net", .{ .iterate = true });
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.name.len == 0 or entry.name.len >= IFNAMSIZ) continue;

        var req = std.mem.zeroes(IFReq);
        @memcpy(req.name[0..entry.name.len], entry.name);

        // Check flags: must be UP and not LOOPBACK.
        var rc = std.os.linux.ioctl(sock, SIOCGIFFLAGS, @intFromPtr(&req));
        if (@as(isize, @bitCast(rc)) < 0) continue;
        const flags = std.mem.readInt(u16, req.data[0..2], @import("builtin").cpu.arch.endian());
        if (flags & IFF_UP == 0) continue;
        if (flags & IFF_LOOPBACK != 0) continue;

        // Get IP address.
        @memset(&req.data, 0);
        rc = std.os.linux.ioctl(sock, SIOCGIFADDR, @intFromPtr(&req));
        if (@as(isize, @bitCast(rc)) < 0) continue;
        const ip: [4]u8 = req.data[4..8].*;

        // Skip the upstream interface.
        if (std.mem.eql(u8, &ip, &upstream_ip) and !std.mem.eql(u8, &upstream_ip, &[_]u8{ 0, 0, 0, 0 })) continue;

        // Get interface index.
        @memset(&req.data, 0);
        rc = std.os.linux.ioctl(sock, SIOCGIFINDEX, @intFromPtr(&req));
        if (@as(isize, @bitCast(rc)) < 0) continue;
        const if_index: u32 = @bitCast(std.mem.readInt(i32, req.data[0..4], @import("builtin").cpu.arch.endian()));

        var name_buf = std.mem.zeroes([IFNAMSIZ]u8);
        @memcpy(name_buf[0..entry.name.len], entry.name);

        const ds_sock = bindDownstreamSocket(&name_buf) catch |err| {
            std.log.warn("skipping {s}: failed to bind socket: {s}", .{ entry.name, @errorName(err) });
            continue;
        };

        try ifaces.append(allocator, .{
            .name = name_buf,
            .name_len = entry.name.len,
            .ip = ip,
            .sock_fd = ds_sock,
            .if_index = if_index,
        });
    }
}

// ---------------------------------------------------------------------------
// Socket helpers
// ---------------------------------------------------------------------------

fn createUdpSocket() !std.posix.fd_t {
    return std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
}

fn setBroadcast(fd: std.posix.fd_t) !void {
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.BROADCAST, &std.mem.toBytes(@as(c_int, 1)));
}

fn bindDownstreamSocket(iface_name: *const [IFNAMSIZ]u8) !std.posix.fd_t {
    const fd = try createUdpSocket();
    errdefer std.posix.close(fd);

    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    try setBroadcast(fd);

    // Bind to specific interface.
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.BINDTODEVICE, iface_name);

    // Bind to 0.0.0.0:67.
    const bind_addr = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, dhcp.dhcp_server_port),
        .addr = 0, // INADDR_ANY
    };
    try std.posix.bind(fd, @ptrCast(&bind_addr), @sizeOf(std.posix.sockaddr.in));

    return fd;
}

fn closeSock(fd: std.posix.fd_t) void {
    if (fd >= 0) std.posix.close(fd);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "stripOption82Raw removes option 82" {
    // Build a minimal packet: header + option 53 (message type) + option 82 + option 255 (end)
    var pkt: [dhcp.dhcp_min_packet_size + 20]u8 = undefined;
    @memset(&pkt, 0);
    // Set magic cookie.
    pkt[236 - 4] = 99;
    pkt[236 - 3] = 130;
    pkt[236 - 2] = 83;
    pkt[236 - 1] = 99;
    var pos: usize = dhcp.dhcp_min_packet_size;

    // Option 53: DHCPDISCOVER
    pkt[pos] = 53;
    pkt[pos + 1] = 1;
    pkt[pos + 2] = 1;
    pos += 3;

    // Option 82: circuit-id "eth0"
    pkt[pos] = 82;
    pkt[pos + 1] = 6; // total sub-option length
    pkt[pos + 2] = 1; // sub-option 1
    pkt[pos + 3] = 4; // length
    pkt[pos + 4] = 'e';
    pkt[pos + 5] = 't';
    pkt[pos + 6] = 'h';
    pkt[pos + 7] = '0';
    pos += 8;

    // End
    pkt[pos] = 255;
    pos += 1;

    var out: [1500]u8 = undefined;
    const result = stripOption82Raw(pkt[0..pos], &out);
    try std.testing.expect(result != null);
    const stripped = result.?;

    // Should have header + option 53 + end, no option 82.
    try std.testing.expect(dhcp.getOption(stripped, .RelayAgentInformation) == null);
    try std.testing.expect(dhcp.getOption(stripped, .MessageType) != null);
    try std.testing.expectEqual(@as(u8, 1), dhcp.getOption(stripped, .MessageType).?[0]);
}

test "stripOption82Raw returns null when no option 82" {
    var pkt: [dhcp.dhcp_min_packet_size + 5]u8 = undefined;
    @memset(&pkt, 0);
    pkt[236 - 4] = 99;
    pkt[236 - 3] = 130;
    pkt[236 - 2] = 83;
    pkt[236 - 1] = 99;
    var pos: usize = dhcp.dhcp_min_packet_size;
    pkt[pos] = 53;
    pkt[pos + 1] = 1;
    pkt[pos + 2] = 1;
    pos += 3;
    pkt[pos] = 255;
    pos += 1;

    var out: [1500]u8 = undefined;
    try std.testing.expect(stripOption82Raw(pkt[0..pos], &out) == null);
}

test "appendOption82 adds option before End" {
    var pkt: [1500]u8 = undefined;
    @memset(&pkt, 0);
    pkt[236 - 4] = 99;
    pkt[236 - 3] = 130;
    pkt[236 - 2] = 83;
    pkt[236 - 1] = 99;
    var pos: usize = dhcp.dhcp_min_packet_size;
    pkt[pos] = 53;
    pkt[pos + 1] = 1;
    pkt[pos + 2] = 1;
    pos += 3;
    pkt[pos] = 255;
    pos += 1;

    // Sub-option payload: circuit-id "eth1"
    const payload = [_]u8{ 1, 4, 'e', 't', 'h', '1' };
    const result = appendOption82(pkt[0..pos], &pkt, &payload);
    try std.testing.expect(result != null);
    const extended = result.?;

    const opt82 = dhcp.getOption(extended, .RelayAgentInformation);
    try std.testing.expect(opt82 != null);
    try std.testing.expectEqual(@as(usize, 6), opt82.?.len);
    try std.testing.expectEqualSlices(u8, &payload, opt82.?);
}

test "clientDestination broadcast flag" {
    var pkt: [dhcp.dhcp_min_packet_size]u8 = undefined;
    @memset(&pkt, 0);
    const hdr: *dhcp.DHCPHeader = @ptrCast(@alignCast(&pkt));
    hdr.magic = dhcp.dhcp_magic_cookie;
    hdr.flags = std.mem.nativeToBig(u16, 0x8000); // broadcast bit
    const dst = clientDestination(&pkt);
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), dst.addr);
}

test "clientDestination ciaddr unicast" {
    var pkt: [dhcp.dhcp_min_packet_size]u8 = undefined;
    @memset(&pkt, 0);
    const hdr: *dhcp.DHCPHeader = @ptrCast(@alignCast(&pkt));
    hdr.magic = dhcp.dhcp_magic_cookie;
    hdr.ciaddr = [_]u8{ 192, 168, 1, 100 };
    const dst = clientDestination(&pkt);
    const ip: [4]u8 = @bitCast(dst.addr);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 100 }, &ip);
}
