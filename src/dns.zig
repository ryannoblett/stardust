const std = @import("std");
const state_mod = @import("./state.zig");
const config_mod = @import("./config.zig");
const util = @import("./util.zig");

const log_v = std.log.scoped(.verbose);

pub const Error = error{
    InvalidConfig,
    InvalidKey,
};

pub const Config = struct {
    enable: bool,
    server: []const u8,
    zone: []const u8,
    /// Reverse zone derived from pool subnet (e.g. "111.168.192.in-addr.arpa" for 192.168.111.0/24).
    /// Computed automatically; not user-configured.
    rev_zone: []const u8,
    key_name: []const u8,
    key_file: []const u8,
    /// TTL applied to DNS A/PTR records; set from DHCP lease_time in config.zig.
    lease_time: u32,
};

pub const Algorithm = enum { hmac_sha256, hmac_md5 };

pub const TsigKey = struct {
    algorithm: Algorithm,
    secret: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *TsigKey) void {
        self.allocator.free(self.secret);
    }
};

pub const DNSUpdater = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    tsig_key: ?TsigKey,

    const Self = @This();

    pub fn create(allocator: std.mem.Allocator, config: *const Config) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        var tsig_key: ?TsigKey = null;
        if (config.enable and config.key_file.len > 0) {
            tsig_key = parseTsigKey(allocator, config.key_file) catch |err| blk: {
                std.log.warn("DNS: failed to parse TSIG key from '{s}': {s}", .{ config.key_file, @errorName(err) });
                break :blk null;
            };
        }

        self.* = .{
            .allocator = allocator,
            .config = config,
            .tsig_key = tsig_key,
        };
        return self;
    }

    pub fn cleanup(self: *Self) void {
        if (self.tsig_key) |*k| k.deinit();
        self.allocator.destroy(self);
    }

    /// Call after a lease is confirmed (DHCPACK). No-op if DNS disabled or no hostname.
    pub fn notifyLeaseAdded(self: *Self, ip: []const u8, hostname: ?[]const u8) void {
        if (!self.config.enable) return;
        const hn = hostname orelse return;
        self.doUpdate(ip, hn, true) catch |err| {
            std.log.warn("DNS: failed to add A/PTR for {s}: {s}", .{ ip, @errorName(err) });
        };
    }

    /// Call after a lease is released (DHCPRELEASE). No-op if DNS disabled or no hostname.
    pub fn notifyLeaseRemoved(self: *Self, ip: []const u8, hostname: ?[]const u8) void {
        if (!self.config.enable) return;
        const hn = hostname orelse return;
        self.doUpdate(ip, hn, false) catch |err| {
            std.log.warn("DNS: failed to remove A/PTR for {s}: {s}", .{ ip, @errorName(err) });
        };
    }

    fn doUpdate(self: *Self, ip_str: []const u8, hostname: []const u8, add: bool) !void {
        const ip = parseIpv4Local(ip_str) catch {
            std.log.warn("DNS: invalid IP address '{s}'", .{ip_str});
            return;
        };

        // Forward UPDATE: A record → forward zone (e.g. "test.lab")
        var fwd_buf: [1024]u8 = undefined;
        var fwd_len = try buildForwardUpdate(&fwd_buf, self.config.zone, hostname, ip, self.config.lease_time, add);
        if (self.tsig_key) |key| fwd_len = try signTsig(&fwd_buf, fwd_len, &key, self.config.key_name);
        try sendUpdate(self.config.server, fwd_buf[0..fwd_len]);

        // Reverse UPDATE: PTR record → reverse zone (e.g. "111.168.192.in-addr.arpa")
        var rev_buf: [1024]u8 = undefined;
        var rev_len = try buildReverseUpdate(&rev_buf, self.config.rev_zone, self.config.zone, hostname, ip, self.config.lease_time, add);
        if (self.tsig_key) |key| rev_len = try signTsig(&rev_buf, rev_len, &key, self.config.key_name);
        try sendUpdate(self.config.server, rev_buf[0..rev_len]);

        log_v.debug("DNS: {s} A+PTR {s} {f} → {s}", .{
            if (add) "added" else "removed",
            ip_str,
            util.escapedStr(hostname),
            self.config.server,
        });
    }
};

pub fn create_updater(allocator: std.mem.Allocator, config: *const Config) !*DNSUpdater {
    return DNSUpdater.create(allocator, config);
}

// ---------------------------------------------------------------------------
// Wire format helpers
// ---------------------------------------------------------------------------

fn writeU16(buf: []u8, v: u16) void {
    buf[0] = @intCast((v >> 8) & 0xFF);
    buf[1] = @intCast(v & 0xFF);
}

fn writeU32(buf: []u8, v: u32) void {
    buf[0] = @intCast((v >> 24) & 0xFF);
    buf[1] = @intCast((v >> 16) & 0xFF);
    buf[2] = @intCast((v >> 8) & 0xFF);
    buf[3] = @intCast(v & 0xFF);
}

/// Encode a dotted domain name into DNS wire format. Returns bytes written.
/// Returns error.NameTooLong if any label does not fit in buf (including the
/// root terminator), so the caller can skip the update rather than send a
/// silently-truncated name.
fn encodeDnsName(buf: []u8, name: []const u8) error{NameTooLong}!usize {
    var pos: usize = 0;
    // Strip trailing dot (root indicator) if present.
    const n = if (name.len > 0 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
    var it = std.mem.splitScalar(u8, n, '.');
    while (it.next()) |label| {
        if (label.len == 0) continue;
        // Need 1 (length byte) + label.len + 1 (root terminator) bytes.
        if (pos + 1 + label.len + 1 > buf.len) return error.NameTooLong;
        buf[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(buf[pos .. pos + label.len], label);
        pos += label.len;
    }
    if (pos >= buf.len) return error.NameTooLong;
    buf[pos] = 0; // root label terminator
    pos += 1;
    return pos;
}

// ---------------------------------------------------------------------------
// DNS UPDATE message builders (RFC 2136)
// ---------------------------------------------------------------------------

/// Build a forward DNS UPDATE (A record only) against the forward zone.
/// Zone section declares `zone`; the update section contains one A record
/// for `hostname.zone`. Returns bytes written to buf.
fn buildForwardUpdate(
    buf: []u8,
    zone: []const u8,
    hostname: []const u8,
    ip: [4]u8,
    lease_time: u32,
    add: bool,
) error{NameTooLong}!usize {
    var pos: usize = 0;

    writeU16(buf[pos..], std.crypto.random.int(u16)); // random ID
    pos += 2;
    writeU16(buf[pos..], 0x2800); // Flags: OPCODE=UPDATE
    pos += 2;
    writeU16(buf[pos..], 1); // ZOCOUNT = 1
    pos += 2;
    writeU16(buf[pos..], 0); // PRCOUNT = 0
    pos += 2;
    writeU16(buf[pos..], 1); // UPCOUNT = 1 (A record only)
    pos += 2;
    writeU16(buf[pos..], 0); // ADCOUNT = 0 (TSIG appended by signTsig)
    pos += 2;

    // Zone section: forward zone, SOA, IN
    pos += try encodeDnsName(buf[pos..], zone);
    writeU16(buf[pos..], 6); // SOA
    pos += 2;
    writeU16(buf[pos..], 1); // IN
    pos += 2;

    // Build fully-qualified forward name: hostname.zone (strip trailing dot if any)
    var fqdn_buf: [512]u8 = undefined;
    const fqdn_raw = std.fmt.bufPrint(&fqdn_buf, "{s}.{s}", .{ hostname, zone }) catch hostname;
    const fqdn = if (fqdn_raw.len > 0 and fqdn_raw[fqdn_raw.len - 1] == '.') fqdn_raw[0 .. fqdn_raw.len - 1] else fqdn_raw;
    var fwd_wire: [256]u8 = undefined;
    const fwd_wire_len = try encodeDnsName(&fwd_wire, fqdn);

    if (add) {
        // A record: hostname.zone IN A TTL ip
        @memcpy(buf[pos .. pos + fwd_wire_len], fwd_wire[0..fwd_wire_len]);
        pos += fwd_wire_len;
        writeU16(buf[pos..], 1); // A
        pos += 2;
        writeU16(buf[pos..], 1); // IN
        pos += 2;
        writeU32(buf[pos..], lease_time);
        pos += 4;
        writeU16(buf[pos..], 4); // RDLENGTH
        pos += 2;
        @memcpy(buf[pos .. pos + 4], &ip);
        pos += 4;
    } else {
        // Delete all A records for hostname.zone
        @memcpy(buf[pos .. pos + fwd_wire_len], fwd_wire[0..fwd_wire_len]);
        pos += fwd_wire_len;
        writeU16(buf[pos..], 1); // A
        pos += 2;
        writeU16(buf[pos..], 255); // ANY
        pos += 2;
        writeU32(buf[pos..], 0); // TTL = 0
        pos += 4;
        writeU16(buf[pos..], 0); // RDLENGTH = 0
        pos += 2;
    }

    return pos;
}

/// Build a reverse DNS UPDATE (PTR record only) against the reverse zone.
/// Zone section declares `rev_zone` (e.g. "111.168.192.in-addr.arpa");
/// the update section contains one PTR record for the individual host IP.
/// Returns bytes written to buf.
fn buildReverseUpdate(
    buf: []u8,
    rev_zone: []const u8,
    zone: []const u8,
    hostname: []const u8,
    ip: [4]u8,
    lease_time: u32,
    add: bool,
) error{NameTooLong}!usize {
    var pos: usize = 0;

    writeU16(buf[pos..], std.crypto.random.int(u16)); // random ID
    pos += 2;
    writeU16(buf[pos..], 0x2800); // Flags: OPCODE=UPDATE
    pos += 2;
    writeU16(buf[pos..], 1); // ZOCOUNT = 1
    pos += 2;
    writeU16(buf[pos..], 0); // PRCOUNT = 0
    pos += 2;
    writeU16(buf[pos..], 1); // UPCOUNT = 1 (PTR record only)
    pos += 2;
    writeU16(buf[pos..], 0); // ADCOUNT = 0 (TSIG appended by signTsig)
    pos += 2;

    // Zone section: reverse zone, SOA, IN
    pos += try encodeDnsName(buf[pos..], rev_zone);
    writeU16(buf[pos..], 6); // SOA
    pos += 2;
    writeU16(buf[pos..], 1); // IN
    pos += 2;

    // Build PTR owner name: d.c.b.a.in-addr.arpa (individual host IP, reversed)
    var ptr_str_buf: [40]u8 = undefined;
    const ptr_str = std.fmt.bufPrint(&ptr_str_buf, "{d}.{d}.{d}.{d}.in-addr.arpa", .{
        ip[3], ip[2], ip[1], ip[0],
    }) catch unreachable;
    var ptr_wire: [64]u8 = undefined;
    const ptr_wire_len = try encodeDnsName(&ptr_wire, ptr_str);

    // Build forward FQDN wire format for PTR RDATA
    var fqdn_buf: [512]u8 = undefined;
    const fqdn_raw = std.fmt.bufPrint(&fqdn_buf, "{s}.{s}", .{ hostname, zone }) catch hostname;
    const fqdn = if (fqdn_raw.len > 0 and fqdn_raw[fqdn_raw.len - 1] == '.') fqdn_raw[0 .. fqdn_raw.len - 1] else fqdn_raw;
    var fwd_wire: [256]u8 = undefined;
    const fwd_wire_len = try encodeDnsName(&fwd_wire, fqdn);

    if (add) {
        // PTR record: d.c.b.a.in-addr.arpa IN PTR TTL hostname.zone
        @memcpy(buf[pos .. pos + ptr_wire_len], ptr_wire[0..ptr_wire_len]);
        pos += ptr_wire_len;
        writeU16(buf[pos..], 12); // PTR
        pos += 2;
        writeU16(buf[pos..], 1); // IN
        pos += 2;
        writeU32(buf[pos..], lease_time);
        pos += 4;
        writeU16(buf[pos..], @intCast(fwd_wire_len)); // RDLENGTH
        pos += 2;
        @memcpy(buf[pos .. pos + fwd_wire_len], fwd_wire[0..fwd_wire_len]);
        pos += fwd_wire_len;
    } else {
        // Delete all records for d.c.b.a.in-addr.arpa
        @memcpy(buf[pos .. pos + ptr_wire_len], ptr_wire[0..ptr_wire_len]);
        pos += ptr_wire_len;
        writeU16(buf[pos..], 255); // ANY
        pos += 2;
        writeU16(buf[pos..], 255); // ANY
        pos += 2;
        writeU32(buf[pos..], 0); // TTL = 0
        pos += 4;
        writeU16(buf[pos..], 0); // RDLENGTH = 0
        pos += 2;
    }

    return pos;
}

// ---------------------------------------------------------------------------
// TSIG signing (RFC 2845)
// ---------------------------------------------------------------------------

/// Append a TSIG additional record to the message and update ADCOUNT.
/// Returns the new message length.
fn signTsig(msg_buf: []u8, msg_len: usize, key: *const TsigKey, key_name: []const u8) error{NameTooLong}!usize {
    const algo_name = switch (key.algorithm) {
        .hmac_sha256 => "hmac-sha256",
        .hmac_md5 => "hmac-md5.sig-alg.reg.int",
    };

    // Build tsig_variables for HMAC input
    var tsig_vars: [512]u8 = undefined;
    var tv_pos: usize = 0;

    // wire(key_name)
    tv_pos += try encodeDnsName(tsig_vars[tv_pos..], key_name);

    // wire(algorithm_name)
    tv_pos += try encodeDnsName(tsig_vars[tv_pos..], algo_name);

    // time_signed[6] — big-endian 48-bit Unix seconds
    const now_signed: i64 = std.time.timestamp();
    const now: u64 = @intCast(@max(now_signed, 0));
    tsig_vars[tv_pos + 0] = @intCast((now >> 40) & 0xFF);
    tsig_vars[tv_pos + 1] = @intCast((now >> 32) & 0xFF);
    tsig_vars[tv_pos + 2] = @intCast((now >> 24) & 0xFF);
    tsig_vars[tv_pos + 3] = @intCast((now >> 16) & 0xFF);
    tsig_vars[tv_pos + 4] = @intCast((now >> 8) & 0xFF);
    tsig_vars[tv_pos + 5] = @intCast(now & 0xFF);
    tv_pos += 6;

    // fudge[2] = 300
    writeU16(tsig_vars[tv_pos..], 300);
    tv_pos += 2;

    // error[2] = 0
    writeU16(tsig_vars[tv_pos..], 0);
    tv_pos += 2;

    // other_len[2] = 0
    writeU16(tsig_vars[tv_pos..], 0);
    tv_pos += 2;

    // Compute HMAC over base message + tsig_variables
    var mac_buf: [32]u8 = undefined; // large enough for SHA-256
    var mac_len: usize = 0;

    switch (key.algorithm) {
        .hmac_sha256 => {
            const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
            var ctx = Hmac.init(key.secret);
            ctx.update(msg_buf[0..msg_len]);
            ctx.update(tsig_vars[0..tv_pos]);
            var mac: [Hmac.mac_length]u8 = undefined;
            ctx.final(&mac);
            @memcpy(mac_buf[0..Hmac.mac_length], &mac);
            mac_len = Hmac.mac_length;
        },
        .hmac_md5 => {
            const Hmac = std.crypto.auth.hmac.Hmac(std.crypto.hash.Md5);
            var ctx = Hmac.init(key.secret);
            ctx.update(msg_buf[0..msg_len]);
            ctx.update(tsig_vars[0..tv_pos]);
            var mac: [Hmac.mac_length]u8 = undefined;
            ctx.final(&mac);
            @memcpy(mac_buf[0..Hmac.mac_length], &mac);
            mac_len = Hmac.mac_length;
        },
    }

    // Append TSIG RR to the message
    var pos = msg_len;

    // Name: wire(key_name)
    pos += try encodeDnsName(msg_buf[pos..], key_name);

    // Type: TSIG (250)
    writeU16(msg_buf[pos..], 250);
    pos += 2;

    // Class: ANY (255)
    writeU16(msg_buf[pos..], 255);
    pos += 2;

    // TTL: 0
    writeU32(msg_buf[pos..], 0);
    pos += 4;

    // Build RDATA: wire(algo) + time[6] + fudge[2] + mac_size[2] + mac + orig_id[2] + error[2] + other_len[2]
    var rdata: [256]u8 = undefined;
    var rd: usize = 0;

    rd += try encodeDnsName(rdata[rd..], algo_name);

    // time[6] — same timestamp used for signing
    rdata[rd + 0] = @intCast((now >> 40) & 0xFF);
    rdata[rd + 1] = @intCast((now >> 32) & 0xFF);
    rdata[rd + 2] = @intCast((now >> 24) & 0xFF);
    rdata[rd + 3] = @intCast((now >> 16) & 0xFF);
    rdata[rd + 4] = @intCast((now >> 8) & 0xFF);
    rdata[rd + 5] = @intCast(now & 0xFF);
    rd += 6;

    // fudge[2] = 300
    writeU16(rdata[rd..], 300);
    rd += 2;

    // mac_size[2]
    writeU16(rdata[rd..], @intCast(mac_len));
    rd += 2;

    // mac bytes
    @memcpy(rdata[rd .. rd + mac_len], mac_buf[0..mac_len]);
    rd += mac_len;

    // orig_id[2] — copy from message header (first 2 bytes)
    rdata[rd] = msg_buf[0];
    rdata[rd + 1] = msg_buf[1];
    rd += 2;

    // error[2] = 0
    writeU16(rdata[rd..], 0);
    rd += 2;

    // other_len[2] = 0
    writeU16(rdata[rd..], 0);
    rd += 2;

    // Write RDLENGTH + RDATA into message
    writeU16(msg_buf[pos..], @intCast(rd));
    pos += 2;
    @memcpy(msg_buf[pos .. pos + rd], rdata[0..rd]);
    pos += rd;

    // Update ADCOUNT in header (bytes 10–11) to 1
    writeU16(msg_buf[10..], 1);

    return pos;
}

// ---------------------------------------------------------------------------
// DNS transport (UDP, port 53)
// ---------------------------------------------------------------------------

fn sendUpdate(server: []const u8, msg: []const u8) !void {
    const server_ip = parseIpv4Local(server) catch {
        std.log.warn("DNS: cannot parse server address '{s}'", .{server});
        return error.InvalidConfig;
    };

    const sock = try std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.DGRAM,
        std.posix.IPPROTO.UDP,
    );
    defer std.posix.close(sock);

    // 2-second receive timeout
    const tv = std.posix.timeval{ .sec = 2, .usec = 0 };
    try std.posix.setsockopt(
        sock,
        std.posix.SOL.SOCKET,
        std.posix.SO.RCVTIMEO,
        std.mem.asBytes(&tv),
    );

    const dst = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 53),
        .addr = @bitCast(server_ip),
    };
    _ = try std.posix.sendto(sock, msg, 0, @ptrCast(&dst), @sizeOf(std.posix.sockaddr.in));

    // Read response and check RCODE
    var resp: [512]u8 = undefined;
    var src: std.posix.sockaddr.in = undefined;
    var src_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
    const n = std.posix.recvfrom(sock, &resp, 0, @ptrCast(&src), &src_len) catch |err| {
        if (err == error.WouldBlock) {
            std.log.warn("DNS: update timed out (no response from {s})", .{server});
            return;
        }
        return err;
    };

    if (n >= 4) {
        const rcode = resp[3] & 0x0F;
        if (rcode != 0) {
            std.log.warn("DNS: server returned RCODE={d} for update", .{rcode});
        }
    }
}

// ---------------------------------------------------------------------------
// TSIG key parser (BIND key file format)
// ---------------------------------------------------------------------------

pub fn parseTsigKey(allocator: std.mem.Allocator, path: []const u8) !TsigKey {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 64 * 1024);
    defer allocator.free(content);

    var algorithm: ?Algorithm = null;
    var secret_b64: ?[]const u8 = null;

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (std.mem.startsWith(u8, trimmed, "algorithm")) {
            if (std.mem.indexOf(u8, trimmed, "sha256") != null) {
                algorithm = .hmac_sha256;
            } else if (std.mem.indexOf(u8, trimmed, "md5") != null) {
                algorithm = .hmac_md5;
            }
        } else if (std.mem.startsWith(u8, trimmed, "secret")) {
            // Extract base64 from:  secret "base64==";
            const q1 = std.mem.indexOf(u8, trimmed, "\"") orelse continue;
            const q2 = std.mem.lastIndexOf(u8, trimmed, "\"") orelse continue;
            if (q1 >= q2) continue;
            secret_b64 = trimmed[q1 + 1 .. q2];
        }
    }

    const alg = algorithm orelse return error.InvalidKey;
    const b64 = secret_b64 orelse return error.InvalidKey;

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(b64) catch return error.InvalidKey;
    const secret = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(secret);
    std.base64.standard.Decoder.decode(secret, b64) catch return error.InvalidKey;

    return TsigKey{
        .algorithm = alg,
        .secret = secret,
        .allocator = allocator,
    };
}

// ---------------------------------------------------------------------------
// IPv4 helper — avoids circular dependency with config.zig
// ---------------------------------------------------------------------------

fn parseIpv4Local(s: []const u8) ![4]u8 {
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
    result[idx] = @intCast(octet);
    return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "encodeDnsName: normal domain encoding" {
    var buf: [64]u8 = undefined;
    const n = try encodeDnsName(&buf, "example.com");
    // \x07example\x03com\x00 = 13 bytes
    try std.testing.expectEqual(@as(usize, 13), n);
    try std.testing.expectEqualSlices(u8, &.{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 }, buf[0..n]);
}

test "encodeDnsName: trailing dot stripped" {
    var buf: [64]u8 = undefined;
    const n = try encodeDnsName(&buf, "example.com.");
    try std.testing.expectEqual(@as(usize, 13), n);
    try std.testing.expectEqualSlices(u8, &.{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 }, buf[0..n]);
}

test "encodeDnsName: name too long for buffer returns error" {
    // 8-byte buffer cannot hold "example.com" (needs 13 bytes).
    var buf: [8]u8 = undefined;
    try std.testing.expectError(error.NameTooLong, encodeDnsName(&buf, "example.com"));
}

test "buildForwardUpdate: add=true has correct header fields and record class" {
    var buf: [1024]u8 = undefined;
    const n = try buildForwardUpdate(&buf, "example.com", "host1", .{ 192, 168, 1, 50 }, 3600, true);
    // Header(12) + zone "example.com"(13) + SOA+IN(4) + fqdn "host1.example.com"(19) + A+IN+TTL+RDLEN+ip(14) = 62 bytes.
    try std.testing.expectEqual(@as(usize, 62), n);
    // FLAGS = 0x2800 (QR=0, OPCODE=UPDATE=5)
    try std.testing.expectEqual(@as(u8, 0x28), buf[2]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[3]);
    // ZOCOUNT = 1
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x01 }, buf[4..6]);
    // PRCOUNT = 0
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, buf[6..8]);
    // UPCOUNT = 1 (A record only)
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x01 }, buf[8..10]);
    // ADCOUNT = 0 (TSIG not yet appended)
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, buf[10..12]);
    // A record: type=A(1), class=IN(1) at bytes 48..52
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x01 }, buf[48..50]); // A type
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x01 }, buf[50..52]); // IN class
}

test "buildForwardUpdate: add=false uses CLASS=ANY and TTL=0" {
    var buf: [1024]u8 = undefined;
    const n = try buildForwardUpdate(&buf, "example.com", "host1", .{ 192, 168, 1, 50 }, 3600, false);
    // Header(12) + zone(13) + SOA+IN(4) + fqdn(19) + A+ANY+TTL=0+RDLEN=0(10) = 58 bytes.
    try std.testing.expectEqual(@as(usize, 58), n);
    // UPCOUNT = 1
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x01 }, buf[8..10]);
    // A delete record: type=A(1), class=ANY(255) at bytes 48..52
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x01 }, buf[48..50]); // A type
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0xFF }, buf[50..52]); // ANY class
    // TTL = 0 at bytes 52..56
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x00, 0x00 }, buf[52..56]);
    // RDLENGTH = 0 at bytes 56..58
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, buf[56..58]);
}

test "parseTsigKey: missing algorithm returns InvalidKey" {
    const alloc = std.testing.allocator;
    const path = "/tmp/stardust-tsig-test-noalgo.conf";
    {
        const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer f.close();
        try f.writeAll("key test {\n    secret \"dGVzdA==\";\n};\n");
    }
    defer std.fs.cwd().deleteFile(path) catch {};
    try std.testing.expectError(error.InvalidKey, parseTsigKey(alloc, path));
}

test "parseTsigKey: missing secret returns InvalidKey" {
    const alloc = std.testing.allocator;
    const path = "/tmp/stardust-tsig-test-nosecret.conf";
    {
        const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer f.close();
        try f.writeAll("key test {\n    algorithm hmac-sha256;\n};\n");
    }
    defer std.fs.cwd().deleteFile(path) catch {};
    try std.testing.expectError(error.InvalidKey, parseTsigKey(alloc, path));
}

test "parseTsigKey: valid hmac-sha256 key file" {
    const alloc = std.testing.allocator;
    const path = "/tmp/stardust-tsig-test-valid.conf";
    {
        const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer f.close();
        // "test" (0x74 0x65 0x73 0x74) base64-encodes to "dGVzdA=="
        try f.writeAll("key ddns-key {\n    algorithm hmac-sha256;\n    secret \"dGVzdA==\";\n};\n");
    }
    defer std.fs.cwd().deleteFile(path) catch {};
    var key = try parseTsigKey(alloc, path);
    defer key.deinit();
    try std.testing.expectEqual(Algorithm.hmac_sha256, key.algorithm);
    try std.testing.expectEqualSlices(u8, "test", key.secret);
}
