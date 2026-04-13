/// Shared DHCP packet definitions, constants, and pure utility functions.
///
/// Used by both the DHCP server (dhcp.zig) and the relay agent (relay.zig).
/// Everything in this module is stateless — no allocators, no side effects.
const std = @import("std");

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
    DHCPFORCERENEW = 9,
    DHCPLEASEQUERY = 10,
    DHCPLEASEUNASSIGNED = 11,
    DHCPLEASEUNKNOWN = 12,
    DHCPLEASEACTIVE = 13,
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
    TimeOffset = 2,
    Router = 3,
    TimeServer = 4,
    DomainNameServer = 6,
    LogServer = 7,
    HostName = 12,
    DomainName = 15,
    InterfaceMTU = 26,
    BroadcastAddress = 28,
    StaticRoutes = 33, // RFC 2132 §3.3
    NtpServers = 42,
    NetBIOSNameServers = 44,
    RequestedIPAddress = 50,
    IPAddressLeaseTime = 51,
    MessageType = 53,
    ServerIdentifier = 54,
    ParameterRequestList = 55,
    RenewalTimeValue = 58,
    RebindingTimeValue = 59,
    VendorClassIdentifier = 60,
    ClientID = 61,
    TftpServerName = 66,
    BootFileName = 67,
    Authentication = 90, // RFC 3118 / RFC 6704
    ClientLastTransactionTime = 91, // RFC 4388
    RelayAgentInformation = 82,
    DomainSearch = 119,
    ClasslessStaticRoutes = 121, // RFC 3442
    ForcerenewNonce = 145, // RFC 6704
    CiscoTftp = 150, // Cisco TFTP server address
    End = 255,
    _,
};

// ---------------------------------------------------------------------------
// Pure packet-parsing utilities
// ---------------------------------------------------------------------------

/// Scan DHCP options for the first occurrence of `target`. Returns the value slice or null.
pub fn getOption(packet: []const u8, target: OptionCode) ?[]const u8 {
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

/// Extract the DHCP message type (option 53) from a packet.
pub fn getMessageType(packet: []const u8) ?MessageType {
    const val = getOption(packet, .MessageType) orelse return null;
    if (val.len < 1) return null;
    return @enumFromInt(val[0]);
}

// ---------------------------------------------------------------------------
// Response routing (RFC 2131 §4.1)
// ---------------------------------------------------------------------------

/// Compute the send destination for a DHCP response from the originating request.
/// RFC 2131 §4.1 routing rules, in priority order:
///   1. giaddr != 0  -> relay agent at giaddr:67 (server port)
///   2. ciaddr != 0  -> renewing client at ciaddr:68 (unicast)
///   3. broadcast bit (flags bit 15) set -> 255.255.255.255:68
///   4. else         -> 255.255.255.255:68 (broadcast fallback; ARP unicast not implemented)
pub fn resolveDestination(request: []const u8) std.posix.sockaddr.in {
    if (request.len >= dhcp_min_packet_size) {
        const req: *const DHCPHeader = @ptrCast(@alignCast(request.ptr));

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

// ---------------------------------------------------------------------------
// IPv4 parsing
// ---------------------------------------------------------------------------

/// Parse a dotted-decimal IPv4 string (e.g. "192.168.1.1") into a 4-byte array.
pub fn parseIpv4(s: []const u8) ![4]u8 {
    var result: [4]u8 = undefined;
    var octet: u16 = 0;
    var idx: u8 = 0;
    for (s) |c| {
        if (c == '.') {
            if (idx >= 3) return error.InvalidConfig;
            result[idx] = @intCast(octet);
            octet = 0;
            idx += 1;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
            if (octet > 255) return error.InvalidConfig;
        } else {
            return error.InvalidConfig;
        }
    }
    if (idx != 3) return error.InvalidConfig;
    // Reject trailing dot (e.g. "192.168.1.") — the last octet would be implicitly 0.
    if (s.len > 0 and s[s.len - 1] == '.') return error.InvalidConfig;
    result[idx] = @intCast(octet);
    return result;
}

// ---------------------------------------------------------------------------
// MAC address formatting
// ---------------------------------------------------------------------------

/// Format a 6-byte MAC address as "xx:xx:xx:xx:xx:xx" into the provided buffer.
/// Returns the 17-byte formatted slice.
pub fn formatMac(mac: [6]u8, buf: *[17]u8) []const u8 {
    const hex = "0123456789abcdef";
    var i: usize = 0;
    for (mac, 0..) |byte, idx| {
        buf[i] = hex[byte >> 4];
        buf[i + 1] = hex[byte & 0x0f];
        i += 2;
        if (idx < 5) {
            buf[i] = ':';
            i += 1;
        }
    }
    return buf[0..17];
}
