const std = @import("std");
const builtin = @import("builtin");

const IFNAMSIZ: usize = 16;
const SIOCGIFADDR: u32 = 0x8915;
const SIOCGIFHWADDR: u32 = 0x8927;
const SIOCGIFINDEX: u32 = 0x8933;
const ETH_P_ARP: u16 = 0x0806;

/// Milliseconds to wait for an ARP reply before assuming the IP is free.
pub const arp_timeout_ms: i64 = 300;
/// Milliseconds to wait for an ICMP echo reply before assuming the IP is free.
pub const icmp_timeout_ms: i64 = 500;
/// Seconds to quarantine a conflict-confirmed IP before re-probing.
pub const probe_quarantine_secs: i64 = 300;
/// Maximum candidates to probe per DISCOVER before giving up.
pub const probe_max_tries: u32 = 3;

/// Arbitrary ICMP identifier used to filter echo replies to our probes.
const probe_icmp_id: u16 = 0xDC11;

/// Linux link-layer socket address (sockaddr_ll).
const SockaddrLL = extern struct {
    family: u16,
    protocol: u16,
    ifindex: i32,
    hatype: u16,
    pkttype: u8,
    halen: u8,
    addr: [8]u8,
};

/// ifreq: 16-byte name union 16-byte data (covers ifr_addr, ifr_hwaddr, ifr_ifindex).
const IFReq = extern struct {
    name: [IFNAMSIZ]u8,
    data: [16]u8,
};

/// Network interface index and hardware (MAC) address.
pub const IfaceInfo = struct {
    index: u32,
    mac: [6]u8,
};

/// Find the network interface whose IPv4 address matches server_ip.
/// Iterates /sys/class/net and uses SIOCGIFADDR / SIOCGIFHWADDR / SIOCGIFINDEX.
pub fn findIfaceForIp(server_ip: [4]u8) !IfaceInfo {
    const tmp_sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(tmp_sock);

    var dir = try std.fs.openDirAbsolute("/sys/class/net", .{ .iterate = true });
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.name.len == 0 or entry.name.len >= IFNAMSIZ) continue;

        var req = std.mem.zeroes(IFReq);
        @memcpy(req.name[0..entry.name.len], entry.name);

        // SIOCGIFADDR: data layout is sockaddr_in — data[4..8] is the IPv4 address.
        var rc = std.os.linux.ioctl(tmp_sock, SIOCGIFADDR, @intFromPtr(&req));
        if (@as(isize, @bitCast(rc)) < 0) continue;
        if (!std.mem.eql(u8, req.data[4..8], &server_ip)) continue;

        // SIOCGIFHWADDR: data layout is sockaddr — data[2..8] is the MAC.
        @memset(&req.data, 0);
        rc = std.os.linux.ioctl(tmp_sock, SIOCGIFHWADDR, @intFromPtr(&req));
        if (@as(isize, @bitCast(rc)) < 0) continue;
        const mac = req.data[2..8].*;

        // SIOCGIFINDEX: data[0..4] is the interface index (native-endian i32).
        @memset(&req.data, 0);
        rc = std.os.linux.ioctl(tmp_sock, SIOCGIFINDEX, @intFromPtr(&req));
        if (@as(isize, @bitCast(rc)) < 0) continue;
        const if_index: u32 = @bitCast(std.mem.readInt(i32, req.data[0..4], builtin.cpu.arch.endian()));

        return .{ .index = if_index, .mac = mac };
    }

    return error.InterfaceNotFound;
}

/// Send an ARP request for target_ip and return true if any host replies.
/// Uses SPA=0.0.0.0 (RFC 5227 probe style) to avoid polluting ARP caches.
/// Returns false on timeout or error.
pub fn arpProbe(src_mac: [6]u8, if_index: u32, target_ip: [4]u8) !bool {
    const sock = try std.posix.socket(
        std.os.linux.AF.PACKET,
        std.posix.SOCK.RAW,
        @as(u32, std.mem.nativeToBig(u16, ETH_P_ARP)),
    );
    defer std.posix.close(sock);

    const bind_addr = SockaddrLL{
        .family = std.os.linux.AF.PACKET,
        .protocol = std.mem.nativeToBig(u16, ETH_P_ARP),
        .ifindex = @intCast(if_index),
        .hatype = 0,
        .pkttype = 0,
        .halen = 0,
        .addr = .{0} ** 8,
    };
    try std.posix.bind(sock, @ptrCast(&bind_addr), @sizeOf(SockaddrLL));

    // 42-byte ARP request: 14 Ethernet header + 28 ARP payload.
    var pkt: [42]u8 = undefined;
    @memset(pkt[0..6], 0xFF);         // dst: broadcast
    @memcpy(pkt[6..12], &src_mac);   // src: our MAC
    pkt[12] = 0x08; pkt[13] = 0x06;  // EtherType: ARP
    pkt[14] = 0x00; pkt[15] = 0x01;  // HTYPE: Ethernet
    pkt[16] = 0x08; pkt[17] = 0x00;  // PTYPE: IPv4
    pkt[18] = 6;                       // HLEN
    pkt[19] = 4;                       // PLEN
    pkt[20] = 0x00; pkt[21] = 0x01;  // OPER: request
    @memcpy(pkt[22..28], &src_mac);   // SHA: our MAC
    @memset(pkt[28..32], 0);          // SPA: 0.0.0.0 (RFC 5227 probe — no ARP cache pollution)
    @memset(pkt[32..38], 0);          // THA: unknown
    @memcpy(pkt[38..42], &target_ip); // TPA: address we're probing

    const dst_addr = SockaddrLL{
        .family = std.os.linux.AF.PACKET,
        .protocol = std.mem.nativeToBig(u16, ETH_P_ARP),
        .ifindex = @intCast(if_index),
        .hatype = 1,   // ARPHRD_ETHER
        .pkttype = 0,
        .halen = 6,
        .addr = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0 },
    };
    _ = try std.posix.sendto(sock, &pkt, 0, @ptrCast(&dst_addr), @sizeOf(SockaddrLL));

    const deadline = std.time.milliTimestamp() + arp_timeout_ms;
    while (true) {
        const remaining = deadline - std.time.milliTimestamp();
        if (remaining <= 0) return false;

        var fds = [_]std.posix.pollfd{.{ .fd = sock, .events = std.posix.POLL.IN, .revents = 0 }};
        const ready = std.posix.poll(&fds, @intCast(remaining)) catch return false;
        if (ready == 0) return false;

        var buf: [60]u8 = undefined;
        const n = std.posix.recv(sock, &buf, 0) catch return false;
        if (n < 42) continue;
        // ARP reply (oper=2) where the sender (SPA, buf[28..32]) is our target.
        if (buf[12] == 0x08 and buf[13] == 0x06 and
            buf[20] == 0x00 and buf[21] == 0x02 and
            std.mem.eql(u8, buf[28..32], &target_ip))
        {
            return true;
        }
    }
}

/// Send an ICMP echo to target_ip and return true if it replies.
/// Returns false on timeout or error (including permission errors).
pub fn icmpProbe(target_ip: [4]u8) !bool {
    const sock = try std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.RAW,
        std.posix.IPPROTO.ICMP,
    );
    defer std.posix.close(sock);

    // ICMP echo request: type=8, code=0, checksum, identifier, sequence=1.
    var pkt: [8]u8 = .{ 8, 0, 0, 0, 0, 0, 0, 1 };
    std.mem.writeInt(u16, pkt[4..6], probe_icmp_id, .big);
    const ck = icmpChecksum(&pkt);
    std.mem.writeInt(u16, pkt[2..4], ck, .big);

    const dst = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = 0,
        .addr = @bitCast(target_ip),
    };
    _ = try std.posix.sendto(sock, &pkt, 0, @ptrCast(&dst), @sizeOf(std.posix.sockaddr.in));

    const deadline = std.time.milliTimestamp() + icmp_timeout_ms;
    while (true) {
        const remaining = deadline - std.time.milliTimestamp();
        if (remaining <= 0) return false;

        var fds = [_]std.posix.pollfd{.{ .fd = sock, .events = std.posix.POLL.IN, .revents = 0 }};
        const ready = std.posix.poll(&fds, @intCast(remaining)) catch return false;
        if (ready == 0) return false;

        // Raw ICMP recv includes the IP header (20 bytes) before the ICMP payload.
        var buf: [100]u8 = undefined;
        const n = std.posix.recv(sock, &buf, 0) catch return false;
        if (n < 28) continue;
        // Echo reply: ICMP type=0, our identifier, from target_ip.
        if (buf[20] == 0 and
            std.mem.readInt(u16, buf[24..26], .big) == probe_icmp_id and
            std.mem.eql(u8, buf[12..16], &target_ip))
        {
            return true;
        }
    }
}

/// One's complement checksum used by ICMP.
fn icmpChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += (@as(u32, data[i]) << 8) | data[i + 1];
    }
    if (i < data.len) sum += @as(u32, data[i]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~@as(u16, @truncate(sum));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "icmpChecksum: all-zeros gives 0xFFFF" {
    const data = [_]u8{0} ** 8;
    try std.testing.expectEqual(@as(u16, 0xFFFF), icmpChecksum(&data));
}

test "icmpChecksum: valid packet re-checksums to zero" {
    var pkt: [8]u8 = .{ 8, 0, 0, 0, 0, 0, 0, 1 };
    std.mem.writeInt(u16, pkt[4..6], probe_icmp_id, .big);
    const ck = icmpChecksum(&pkt);
    std.mem.writeInt(u16, pkt[2..4], ck, .big);
    // After embedding the checksum, re-computing must give 0.
    try std.testing.expectEqual(@as(u16, 0), icmpChecksum(&pkt));
}
