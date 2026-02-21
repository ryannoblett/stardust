const std = @import("std");
const config_mod = @import("./config.zig");
const state_mod = @import("./state.zig");

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
    End = 255,
    _,
};

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

pub const DHCPServer = struct {
    allocator: std.mem.Allocator,
    cfg: *const Config,
    store: *StateStore,
    running: std.atomic.Value(bool),

    const Self = @This();

    pub fn create(allocator: std.mem.Allocator, cfg: *const Config, store: *StateStore) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .cfg = cfg,
            .store = store,
            .running = std.atomic.Value(bool).init(false),
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self);
    }

    /// Main server loop. Binds a UDP socket on port 67 and processes packets.
    pub fn run(self: *Self) !void {
        const stdout = td.fs.File.stdout().writeAll();

        self.running.store(true, .seq_cst);
        defer self.running.store(false, .seq_cst);

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

        try stdout.print("DHCP server listening on {s}:{d}\n", .{
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
                try stdout.print("recvfrom error: {s}\n", .{@errorName(err)});
                continue;
            };

            const packet = buf[0..n];

            const response = self.processPacket(packet) catch |err| {
                try stdout.print("Error processing packet: {s}\n", .{@errorName(err)});
                continue;
            };

            if (response) |resp| {
                defer self.allocator.free(resp);

                // Broadcast response to 255.255.255.255:68
                const dst_addr = std.posix.sockaddr.in{
                    .family = std.posix.AF.INET,
                    .port = std.mem.nativeToBig(u16, dhcp_client_port),
                    .addr = 0xFFFFFFFF,
                };
                _ = std.posix.sendto(
                    sock_fd,
                    resp,
                    0,
                    @ptrCast(&dst_addr),
                    @sizeOf(std.posix.sockaddr.in),
                ) catch |err| {
                    try stdout.print("sendto error: {s}\n", .{@errorName(err)});
                };
            }
        }

        try stdout.print("DHCP server stopped\n", .{});
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
            else => null,
        };
    }

    fn getMessageType(packet: []const u8) ?MessageType {
        if (packet.len < dhcp_min_packet_size + 4) return null;
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
            if (code == @intFromEnum(OptionCode.MessageType) and len >= 1) {
                return @enumFromInt(opts[i + 2]);
            }
            i += 2 + len;
        }
        return null;
    }

    /// Build a DHCPOFFER in response to a DHCPDISCOVER.
    ///
    /// Allocates and returns a packet buffer; caller is responsible for freeing.
    /// Returns null if no address is available to offer.
    fn createOffer(self: *Self, request: []const u8) !?[]u8 {
        const req_header: *const DHCPHeader = @alignCast(@ptrCast(request.ptr));

        // TODO: implement proper IP pool allocation. For now, derive a candidate
        // address from the subnet + a simple offset so the stub is exercisable.
        const offered_ip = try config_mod.parseIpv4(self.cfg.router); // placeholder

        const server_ip = try config_mod.parseIpv4(self.cfg.listen_address);
        const subnet_mask = std.mem.toBytes(std.mem.nativeToBig(u32, self.cfg.subnet_mask));
        const router_ip = try config_mod.parseIpv4(self.cfg.router);
        const lease_time = std.mem.toBytes(std.mem.nativeToBig(u32, self.cfg.lease_time));
        const renewal_time = std.mem.toBytes(std.mem.nativeToBig(u32, self.cfg.lease_time / 2));
        const rebind_time = std.mem.toBytes(std.mem.nativeToBig(u32, self.cfg.lease_time * 7 / 8));

        // Build options into a temporary buffer
        var opts_buf: [256]u8 = undefined;
        var opts_len: usize = 0;

        // Option 53: DHCPOFFER
        opts_buf[opts_len] = @intFromEnum(OptionCode.MessageType);
        opts_buf[opts_len + 1] = 1;
        opts_buf[opts_len + 2] = @intFromEnum(MessageType.DHCPOFFER);
        opts_len += 3;

        // Option 54: Server Identifier
        opts_buf[opts_len] = @intFromEnum(OptionCode.ServerIdentifier);
        opts_buf[opts_len + 1] = 4;
        @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &server_ip);
        opts_len += 6;

        // Option 51: IP Address Lease Time
        opts_buf[opts_len] = @intFromEnum(OptionCode.IPAddressLeaseTime);
        opts_buf[opts_len + 1] = 4;
        @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &lease_time);
        opts_len += 6;

        // Option 58: Renewal Time
        opts_buf[opts_len] = @intFromEnum(OptionCode.RenewalTimeValue);
        opts_buf[opts_len + 1] = 4;
        @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &renewal_time);
        opts_len += 6;

        // Option 59: Rebinding Time
        opts_buf[opts_len] = @intFromEnum(OptionCode.RebindingTimeValue);
        opts_buf[opts_len + 1] = 4;
        @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &rebind_time);
        opts_len += 6;

        // Option 1: Subnet Mask
        opts_buf[opts_len] = @intFromEnum(OptionCode.SubnetMask);
        opts_buf[opts_len + 1] = 4;
        @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &subnet_mask);
        opts_len += 6;

        // Option 3: Router
        opts_buf[opts_len] = @intFromEnum(OptionCode.Router);
        opts_buf[opts_len + 1] = 4;
        @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &router_ip);
        opts_len += 6;

        // Option 6: DNS Servers (up to 4)
        if (self.cfg.dns_servers.len > 0) {
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
        if (self.cfg.domain_name.len > 0) {
            const dn_len = @min(self.cfg.domain_name.len, 255);
            opts_buf[opts_len] = @intFromEnum(OptionCode.DomainName);
            opts_buf[opts_len + 1] = @intCast(dn_len);
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 2 + dn_len], self.cfg.domain_name[0..dn_len]);
            opts_len += 2 + dn_len;
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
        resp_header.hops = 0;
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
    fn createAck(self: *Self, request: []const u8) !?[]u8 {
        const req_header: *const DHCPHeader = @alignCast(@ptrCast(request.ptr));

        // The client's requested IP comes from option 50, or ciaddr for renewals.
        const client_ip = getRequestedIp(request) orelse req_header.ciaddr;
        const server_ip = try config_mod.parseIpv4(self.cfg.listen_address);
        const subnet_mask = std.mem.toBytes(std.mem.nativeToBig(u32, self.cfg.subnet_mask));
        const router_ip = try config_mod.parseIpv4(self.cfg.router);
        const lease_time = std.mem.toBytes(std.mem.nativeToBig(u32, self.cfg.lease_time));
        const renewal_time = std.mem.toBytes(std.mem.nativeToBig(u32, self.cfg.lease_time / 2));
        const rebind_time = std.mem.toBytes(std.mem.nativeToBig(u32, self.cfg.lease_time * 7 / 8));

        // Record the lease
        const mac_bytes = req_header.chaddr[0..6];
        var mac_str_buf: [17]u8 = undefined;
        const mac_str = std.fmt.bufPrint(&mac_str_buf, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
            mac_bytes[0], mac_bytes[1], mac_bytes[2],
            mac_bytes[3], mac_bytes[4], mac_bytes[5],
        }) catch unreachable;

        var ip_str_buf: [15]u8 = undefined;
        const ip_str = std.fmt.bufPrint(&ip_str_buf, "{d}.{d}.{d}.{d}", .{
            client_ip[0], client_ip[1], client_ip[2], client_ip[3],
        }) catch unreachable;

        const now = std.time.timestamp();
        self.store.addLease(.{
            .mac = try self.allocator.dupe(u8, mac_str),
            .ip = try self.allocator.dupe(u8, ip_str),
            .hostname = null,
            .expires = now + self.cfg.lease_time,
            .client_id = null,
        }) catch {};

        // Build options
        var opts_buf: [256]u8 = undefined;
        var opts_len: usize = 0;

        // Option 53: DHCPACK
        opts_buf[opts_len] = @intFromEnum(OptionCode.MessageType);
        opts_buf[opts_len + 1] = 1;
        opts_buf[opts_len + 2] = @intFromEnum(MessageType.DHCPACK);
        opts_len += 3;

        // Option 54: Server Identifier
        opts_buf[opts_len] = @intFromEnum(OptionCode.ServerIdentifier);
        opts_buf[opts_len + 1] = 4;
        @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &server_ip);
        opts_len += 6;

        // Option 51: IP Address Lease Time
        opts_buf[opts_len] = @intFromEnum(OptionCode.IPAddressLeaseTime);
        opts_buf[opts_len + 1] = 4;
        @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &lease_time);
        opts_len += 6;

        // Option 58: Renewal Time
        opts_buf[opts_len] = @intFromEnum(OptionCode.RenewalTimeValue);
        opts_buf[opts_len + 1] = 4;
        @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &renewal_time);
        opts_len += 6;

        // Option 59: Rebinding Time
        opts_buf[opts_len] = @intFromEnum(OptionCode.RebindingTimeValue);
        opts_buf[opts_len + 1] = 4;
        @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &rebind_time);
        opts_len += 6;

        // Option 1: Subnet Mask
        opts_buf[opts_len] = @intFromEnum(OptionCode.SubnetMask);
        opts_buf[opts_len + 1] = 4;
        @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &subnet_mask);
        opts_len += 6;

        // Option 3: Router
        opts_buf[opts_len] = @intFromEnum(OptionCode.Router);
        opts_buf[opts_len + 1] = 4;
        @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &router_ip);
        opts_len += 6;

        // Option 6: DNS Servers (up to 4)
        if (self.cfg.dns_servers.len > 0) {
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
        if (self.cfg.domain_name.len > 0) {
            const dn_len = @min(self.cfg.domain_name.len, 255);
            opts_buf[opts_len] = @intFromEnum(OptionCode.DomainName);
            opts_buf[opts_len + 1] = @intCast(dn_len);
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 2 + dn_len], self.cfg.domain_name[0..dn_len]);
            opts_len += 2 + dn_len;
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
        resp_header.hops = 0;
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
        self.store.removeLease(mac_str) catch {};
    }

    /// Scan options for option 50 (Requested IP Address).
    fn getRequestedIp(packet: []const u8) ?[4]u8 {
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
            if (code == @intFromEnum(OptionCode.RequestedIPAddress) and len == 4) {
                return opts[i + 2 ..][0..4].*;
            }
            i += 2 + len;
        }
        return null;
    }
};

pub fn create_server(allocator: std.mem.Allocator, cfg: *const Config, store: *StateStore) !*DHCPServer {
    return DHCPServer.create(allocator, cfg, store);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
