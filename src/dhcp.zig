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
        const stdout = std.io.getStdOut().writer();

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

        const bind_addr = std.posix.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, dhcp_server_port),
            .addr = @bitCast(listen_ip),
            .zero = [_]u8{0} ** 8,
        };
        try std.posix.bind(sock_fd, @ptrCast(&bind_addr), @sizeOf(std.posix.sockaddr.in));

        try stdout.print("DHCP server listening on {s}:{d}\n", .{ self.cfg.listen_address, dhcp_server_port });

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
                // Broadcast response to 255.255.255.255:68
                const dst_addr = std.posix.sockaddr.in{
                    .family = std.posix.AF.INET,
                    .port = std.mem.nativeToBig(u16, dhcp_client_port),
                    .addr = 0xFFFFFFFF,
                    .zero = [_]u8{0} ** 8,
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

    fn processPacket(self: *Self, packet: []const u8) !?[]const u8 {
        if (packet.len < dhcp_min_packet_size) return null;

        const header: *const DHCPHeader = @ptrCast(@alignCast(packet.ptr));

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

    fn createOffer(self: *Self, request: []const u8) ?[]const u8 {
        // TODO: implement IP allocation and full DHCPOFFER construction
        _ = self;
        _ = request;
        return null;
    }

    fn createAck(self: *Self, request: []const u8) ?[]const u8 {
        // TODO: implement DHCPACK creation and lease recording
        _ = self;
        _ = request;
        return null;
    }

    fn handleRelease(self: *Self, request: []const u8) void {
        // TODO: parse client MAC and remove lease from store
        _ = self;
        _ = request;
    }
};

pub fn create_server(allocator: std.mem.Allocator, cfg: *const Config, store: *StateStore) !*DHCPServer {
    return DHCPServer.create(allocator, cfg, store);
}

test "getMessageType discover" {
    // Build a minimal DHCP DISCOVER packet
    var pkt = [_]u8{0} ** (dhcp_min_packet_size + 10);
    // Magic cookie
    @memcpy(pkt[dhcp_min_packet_size - 4 .. dhcp_min_packet_size], &dhcp_magic_cookie);
    // Option 53 (MessageType), len 1, DHCPDISCOVER
    pkt[dhcp_min_packet_size] = @intFromEnum(OptionCode.MessageType);
    pkt[dhcp_min_packet_size + 1] = 1;
    pkt[dhcp_min_packet_size + 2] = @intFromEnum(MessageType.DHCPDISCOVER);
    pkt[dhcp_min_packet_size + 3] = @intFromEnum(OptionCode.End);

    const mt = DHCPServer.getMessageType(&pkt);
    try std.testing.expect(mt != null);
    try std.testing.expectEqual(MessageType.DHCPDISCOVER, mt.?);
}
