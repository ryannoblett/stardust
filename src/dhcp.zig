const std = @import("std");
const config_mod = @import("./config.zig");
const state_mod = @import("./state.zig");
const dns_mod = @import("./dns.zig");
const probe_mod = @import("./probe.zig");
const sync_mod = @import("./sync.zig");
const util = @import("./util.zig");

pub const Config = config_mod.Config;
pub const StateStore = state_mod.StateStore;

// Scoped logger for verbose DHCP event summaries (one line per lease/release/NAK).
// Emitted at std.log.debug level; logFn in main.zig routes .verbose scope to the
// "verbose" log level, which sits between info and debug in the runtime filter.
const log_v = std.log.scoped(.verbose);

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
// Server
// ---------------------------------------------------------------------------

var g_running: ?*std.atomic.Value(bool) = null;
var g_reload: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn handleSignal(sig: c_int) callconv(.c) void {
    if (sig == std.posix.SIG.HUP) {
        g_reload.store(true, .seq_cst);
    } else {
        if (g_running) |r| r.store(false, .seq_cst);
    }
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

/// Encode an option value string into DHCP wire bytes in dst.
/// Tries comma-separated IPv4 addresses first; falls back to raw string bytes.
/// Check if a MAC address matches a MAC class pattern.
/// Pattern is a prefix — trailing `:*` or `*` is stripped, then the MAC
/// is compared case-insensitively against the prefix.
fn matchMacClass(mac: []const u8, pattern: []const u8) bool {
    // Strip trailing wildcards.
    var pat = pattern;
    while (pat.len > 0 and (pat[pat.len - 1] == '*' or pat[pat.len - 1] == ':')) {
        pat = pat[0 .. pat.len - 1];
    }
    if (pat.len == 0) return true; // "*" matches everything
    if (mac.len < pat.len) return false;
    // Prefix match, case-insensitive.
    for (pat, 0..) |pc, i| {
        const mc = mac[i];
        if (toLowerAscii(pc) != toLowerAscii(mc)) return false;
    }
    // Ensure we matched at an octet boundary (followed by ':' or end of string).
    if (pat.len == mac.len) return true;
    return mac[pat.len] == ':';
}

fn toLowerAscii(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

/// Result of merging DHCP option overrides from all layers (pool, mac_classes,
/// reservation). The `dhcp_options` map contains raw option-code→value strings
/// that go through `encodeOptionValue`. The first-class field overrides carry
/// typed data from the winning MAC class and are applied directly by the packet
/// builder using the correct encoding for each option type.
/// All slice/pointer values reference config-owned memory — no duplication.
const OverrideResult = struct {
    dhcp_options: std.StringHashMap([]const u8),
    // First-class field overrides from the winning MAC class layer.
    // null / empty = use pool default.
    router: ?[]const u8 = null,
    dns_servers: ?[]const []const u8 = null,
    domain_name: ?[]const u8 = null,
    domain_search: ?[]const []const u8 = null,
    ntp_servers: ?[]const []const u8 = null,
    log_servers: ?[]const []const u8 = null,
    wins_servers: ?[]const []const u8 = null,
    time_offset: ?i32 = null,
    tftp_servers: ?[]const []const u8 = null,
    boot_filename: ?[]const u8 = null,
    http_boot_url: ?[]const u8 = null,
    static_routes: ?[]const config_mod.StaticRoute = null,
};

/// Collect merged DHCP option overrides from all layers:
///   1. pool.dhcp_options (lowest priority)
///   2. Matching mac_classes (least-specific match first, then more specific)
///      — both dhcp_options and first-class structured fields
///   3. Per-reservation dhcp_options (highest priority)
/// Returns an OverrideResult; caller must deinit `.dhcp_options`.
/// Values point into config-owned strings (no duplication needed).
fn collectOverrides(
    allocator: std.mem.Allocator,
    pool: *const config_mod.PoolConfig,
    mac: []const u8,
    reservation: ?*const config_mod.Reservation,
    mac_classes: []const config_mod.MacClass,
) OverrideResult {
    var result = OverrideResult{
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
    };

    // Layer 1: pool custom options.
    var pool_it = pool.dhcp_options.iterator();
    while (pool_it.next()) |entry| {
        result.dhcp_options.put(entry.key_ptr.*, entry.value_ptr.*) catch {};
    }

    // Layer 2: MAC class matches, sorted by specificity (shortest match first).
    // Collect matching classes with their pattern length, sort, then apply.
    var matches: [64]struct { idx: usize, specificity: usize } = undefined;
    var match_count: usize = 0;
    for (mac_classes, 0..) |*mc, i| {
        if (matchMacClass(mac, mc.match)) {
            if (match_count < matches.len) {
                // Specificity = length of pattern after stripping wildcards.
                var pat = mc.match;
                while (pat.len > 0 and (pat[pat.len - 1] == '*' or pat[pat.len - 1] == ':')) {
                    pat = pat[0 .. pat.len - 1];
                }
                matches[match_count] = .{ .idx = i, .specificity = pat.len };
                match_count += 1;
            }
        }
    }
    // Sort by specificity ascending (least specific first → most specific last wins).
    if (match_count > 1) {
        for (1..match_count) |i| {
            const key = matches[i];
            var j = i;
            while (j > 0 and matches[j - 1].specificity > key.specificity) {
                matches[j] = matches[j - 1];
                j -= 1;
            }
            matches[j] = key;
        }
    }
    for (matches[0..match_count]) |m| {
        const mc = &mac_classes[m.idx];

        // Apply first-class structured field overrides (last match wins).
        if (mc.router != null) result.router = mc.router;
        if (mc.dns_servers.len > 0) result.dns_servers = mc.dns_servers;
        if (mc.domain_name != null) result.domain_name = mc.domain_name;
        if (mc.domain_search.len > 0) result.domain_search = mc.domain_search;
        if (mc.ntp_servers.len > 0) result.ntp_servers = mc.ntp_servers;
        if (mc.log_servers.len > 0) result.log_servers = mc.log_servers;
        if (mc.wins_servers.len > 0) result.wins_servers = mc.wins_servers;
        if (mc.time_offset != null) result.time_offset = mc.time_offset;
        if (mc.tftp_servers.len > 0) result.tftp_servers = mc.tftp_servers;
        if (mc.boot_filename != null) result.boot_filename = mc.boot_filename;
        if (mc.http_boot_url != null) result.http_boot_url = mc.http_boot_url;
        if (mc.static_routes.len > 0) result.static_routes = mc.static_routes;

        // Apply dhcp_options (overwrites pool layer).
        var mc_it = mc.dhcp_options.iterator();
        while (mc_it.next()) |entry| {
            result.dhcp_options.put(entry.key_ptr.*, entry.value_ptr.*) catch {};
        }
    }

    // Layer 3: per-reservation options (highest priority).
    if (reservation) |res| {
        if (res.dhcp_options) |res_opts| {
            var res_it = res_opts.iterator();
            while (res_it.next()) |entry| {
                result.dhcp_options.put(entry.key_ptr.*, entry.value_ptr.*) catch {};
            }
        }
    }

    return result;
}

/// Check if an option code (as integer) is present in the override map.
fn isOverridden(overrides: *const std.StringHashMap([]const u8), code: u8) bool {
    var buf: [3]u8 = undefined;
    const key = std.fmt.bufPrint(&buf, "{d}", .{code}) catch return false;
    return overrides.contains(key);
}

/// Find a config Reservation by MAC in a pool's reservation list.
fn findConfigReservation(pool: *const config_mod.PoolConfig, mac: []const u8) ?*const config_mod.Reservation {
    for (pool.reservations) |*r| {
        if (std.mem.eql(u8, r.mac, mac)) return r;
    }
    return null;
}

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
        if (len + 4 > dst.len) {
            all_valid = false;
            break;
        }
        @memcpy(dst[len .. len + 4], &ip);
        len += 4;
    }
    if (len > 0 and all_valid) return dst[0..len]; // all tokens were valid IPs
    // Fall back to raw string bytes
    const copy_len = @min(s.len, dst.len);
    @memcpy(dst[0..copy_len], s[0..copy_len]);
    return dst[0..copy_len];
}

/// Encode a list of domain names in DNS wire format (RFC 1035 §3.1) as required
/// by DHCP option 119 (RFC 3397). Each name is encoded as length-prefixed labels
/// terminated by a zero byte; names are concatenated. No compression is applied.
/// Returns the number of bytes written into buf.
fn encodeDnsSearchList(buf: []u8, domains: []const []const u8) usize {
    var pos: usize = 0;
    for (domains) |domain| {
        // Strip optional trailing dot.
        var rem = if (domain.len > 0 and domain[domain.len - 1] == '.') domain[0 .. domain.len - 1] else domain;
        const domain_start = pos;
        var valid = true;
        while (rem.len > 0) {
            const dot = std.mem.indexOfScalar(u8, rem, '.') orelse rem.len;
            const label = rem[0..dot];
            if (label.len == 0 or label.len > 63 or pos + 1 + label.len >= buf.len) {
                valid = false;
                break;
            }
            buf[pos] = @intCast(label.len);
            pos += 1;
            @memcpy(buf[pos .. pos + label.len], label);
            pos += label.len;
            rem = if (dot < rem.len) rem[dot + 1 ..] else "";
        }
        if (!valid or pos >= buf.len) {
            pos = domain_start; // rewind — skip malformed or overflowing domain
            continue;
        }
        buf[pos] = 0; // root label terminator
        pos += 1;
    }
    return pos;
}

/// Encode DHCP option 33 (Static Routes, RFC 2132 §3.3).
/// Each route: 4-byte destination + 4-byte router = 8 bytes.
/// Returns bytes written; stops early if dst is full.
fn encodeStaticRoutes(dst: []u8, routes: []const config_mod.StaticRoute) usize {
    var pos: usize = 0;
    for (routes) |r| {
        if (pos + 8 > dst.len) break;
        @memcpy(dst[pos..][0..4], &r.destination);
        pos += 4;
        @memcpy(dst[pos..][0..4], &r.router);
        pos += 4;
    }
    return pos;
}

/// Encode DHCP option 121 (Classless Static Routes, RFC 3442 §3).
/// Each route: 1-byte prefix_len + ceil(prefix_len/8) destination bytes + 4-byte router.
/// Returns bytes written; stops early if dst is full.
fn encodeClasslessStaticRoutes(dst: []u8, routes: []const config_mod.StaticRoute) usize {
    var pos: usize = 0;
    for (routes) |r| {
        const sig: usize = (r.prefix_len + 7) / 8; // ceil(prefix_len/8)
        if (pos + 1 + sig + 4 > dst.len) break;
        dst[pos] = r.prefix_len;
        pos += 1;
        @memcpy(dst[pos..][0..sig], r.destination[0..sig]);
        pos += sig;
        @memcpy(dst[pos..][0..4], &r.router);
        pos += 4;
    }
    return pos;
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

/// Append a list-of-IPv4 option. Skips the whole option if the list is empty or
/// none of the IP strings parse, and does nothing if the PRL does not request it.
fn appendIpListOpt(
    opts_buf: []u8,
    opts_len: *usize,
    prl: ?[]const u8,
    code: OptionCode,
    servers: []const []const u8,
) void {
    if (!isRequested(prl, code) or servers.len == 0) return;
    const count = @min(servers.len, 63); // max 252 bytes of data
    const header = opts_len.*;
    if (header + 2 + count * 4 > opts_buf.len) return;
    opts_buf[header] = @intFromEnum(code);
    opts_len.* += 2;
    var n: u8 = 0;
    for (servers[0..count]) |s| {
        const ip = config_mod.parseIpv4(s) catch continue;
        @memcpy(opts_buf[opts_len.*..][0..4], &ip);
        opts_len.* += 4;
        n += 1;
    }
    if (n > 0) {
        opts_buf[header + 1] = n * 4;
    } else {
        opts_len.* = header; // rewind -- no valid IPs
    }
}

/// Append a string option. Does nothing if value is empty or PRL does not request it.
fn appendStringOpt(
    opts_buf: []u8,
    opts_len: *usize,
    prl: ?[]const u8,
    code: OptionCode,
    value: []const u8,
) void {
    if (!isRequested(prl, code) or value.len == 0) return;
    const len = @min(value.len, 255);
    if (opts_len.* + 2 + len > opts_buf.len) return;
    opts_buf[opts_len.*] = @intFromEnum(code);
    opts_buf[opts_len.* + 1] = @intCast(len);
    @memcpy(opts_buf[opts_len.* + 2 ..][0..len], value[0..len]);
    opts_len.* += 2 + len;
}

/// Unconditionally append a string option (no PRL check). Used for options
/// that must be included regardless of what the client requested — specifically
/// option 60 (VCI echo) and option 67 (boot URL) in UEFI HTTP boot responses.
fn appendRawStringOpt(opts_buf: []u8, opts_len: *usize, code: OptionCode, value: []const u8) void {
    if (value.len == 0) return;
    const len = @min(value.len, 255);
    if (opts_len.* + 2 + len > opts_buf.len) return;
    opts_buf[opts_len.*] = @intFromEnum(code);
    opts_buf[opts_len.* + 1] = @intCast(len);
    @memcpy(opts_buf[opts_len.* + 2 ..][0..len], value[0..len]);
    opts_len.* += 2 + len;
}

// ---------------------------------------------------------------------------
// DNS resolution cache for hostname-based server entries
// ---------------------------------------------------------------------------

const ResolveCacheEntry = struct {
    name_hash: u64,
    name_buf: [64]u8 = [_]u8{0} ** 64,
    name_len: u8 = 0,
    ip: [4]u8,
    timestamp: i64, // epoch seconds
};
const RESOLVE_CACHE_SIZE = 32;
const RESOLVE_CACHE_TTL = 60; // seconds

/// Try to resolve a hostname (or dotted-quad IP string) to an IPv4 address.
/// Uses a small fixed-size cache to avoid DNS lookups on every DHCP packet.
fn resolveHostToIpv4(name: []const u8, cache: *[RESOLVE_CACHE_SIZE]ResolveCacheEntry) ?[4]u8 {
    // Fast path: direct IPv4 parse.
    if (config_mod.parseIpv4(name)) |ip| return ip else |_| {}

    // Cache lookup by name hash + actual name comparison to avoid collisions.
    const name_hash = std.hash.Wyhash.hash(0, name);
    const now = std.time.timestamp();
    const slot = @as(usize, @intCast(name_hash % RESOLVE_CACHE_SIZE));
    if (cache[slot].name_hash == name_hash and
        cache[slot].name_len == @as(u8, @intCast(@min(name.len, 64))) and
        std.mem.eql(u8, cache[slot].name_buf[0..cache[slot].name_len], name[0..@min(name.len, 64)]) and
        (now - cache[slot].timestamp) < RESOLVE_CACHE_TTL)
    {
        return cache[slot].ip;
    }

    // DNS resolution via libc getaddrinfo (project links libc).
    // Null-terminate the name into a stack buffer.
    var name_buf: [253:0]u8 = undefined;
    if (name.len > 253) return null;
    @memcpy(name_buf[0..name.len], name);
    name_buf[name.len] = 0;
    const name_z: [*:0]const u8 = name_buf[0..name.len :0];

    const hints = std.posix.addrinfo{
        .flags = .{},
        .family = std.posix.AF.INET,
        .socktype = std.posix.SOCK.DGRAM,
        .protocol = 0,
        .addrlen = 0,
        .addr = null,
        .canonname = null,
        .next = null,
    };
    var res: ?*std.posix.addrinfo = null;
    const rc = std.c.getaddrinfo(name_z, null, &hints, &res);
    if (rc != @as(std.c.EAI, @enumFromInt(0))) {
        std.log.debug("DNS resolve failed for '{s}': {s}", .{
            name,
            std.mem.span(std.c.gai_strerror(rc)),
        });
        return null;
    }
    defer if (res) |r| std.c.freeaddrinfo(r);

    const info = res orelse return null;
    const sa = info.addr orelse return null;
    if (sa.family != std.posix.AF.INET) return null;
    const sin: *const std.posix.sockaddr.in = @ptrCast(@alignCast(sa));
    const ip: [4]u8 = @bitCast(sin.addr);

    // Store in cache (hostnames > 64 chars skip caching to avoid truncation mismatches).
    if (name.len <= 64) {
        var nbuf: [64]u8 = [_]u8{0} ** 64;
        @memcpy(nbuf[0..name.len], name);
        cache[slot] = .{
            .name_hash = name_hash,
            .name_buf = nbuf,
            .name_len = @intCast(name.len),
            .ip = ip,
            .timestamp = now,
        };
    }
    return ip;
}

/// Fisher-Yates shuffle with a fast LCG seeded from the DHCP xid.
fn shuffleIps(items: [][4]u8, seed: u32) void {
    if (items.len <= 1) return;
    var s = seed;
    var i: usize = items.len - 1;
    while (i > 0) : (i -= 1) {
        s = s *% 1103515245 +% 12345;
        const j = s % @as(u32, @intCast(i + 1));
        const tmp = items[i];
        items[i] = items[j];
        items[j] = tmp;
    }
}

/// Append a list-of-IPv4 option, resolving hostnames via DNS when needed.
/// If `shuffle_seed` is non-null the resolved IP list is shuffled before encoding.
fn appendResolvedIpListOpt(
    opts_buf: []u8,
    opts_len: *usize,
    prl: ?[]const u8,
    code: OptionCode,
    servers: []const []const u8,
    cache: *[RESOLVE_CACHE_SIZE]ResolveCacheEntry,
    shuffle_seed: ?u32,
) void {
    if (!isRequested(prl, code) or servers.len == 0) return;
    const count = @min(servers.len, 63); // max 252 bytes of data

    // Resolve all entries into a stack buffer.
    var ips: [63][4]u8 = undefined;
    var n: usize = 0;
    for (servers[0..count]) |s| {
        if (resolveHostToIpv4(s, cache)) |ip| {
            ips[n] = ip;
            n += 1;
        }
    }
    if (n == 0) return;

    // Optional shuffle for load distribution.
    if (shuffle_seed) |seed| shuffleIps(ips[0..n], seed);

    const header = opts_len.*;
    if (header + 2 + n * 4 > opts_buf.len) return;
    opts_buf[header] = @intFromEnum(code);
    opts_buf[header + 1] = @intCast(n * 4);
    opts_len.* = header + 2;
    for (ips[0..n]) |ip| {
        @memcpy(opts_buf[opts_len.*..][0..4], &ip);
        opts_len.* += 4;
    }
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

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Atomic counters for DHCP message types. Incremented from the main loop;
/// read by the metrics/SSH threads. Counters reset to zero at server start.
pub const Counters = struct {
    // DHCP message counters
    discover: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    offer: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    request: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    ack: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    nak: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    release: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    decline: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    inform: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    forcerenew: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    leasequery: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    // Defense / security event counters
    probe_conflict: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    decline_ip_quarantined: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    decline_mac_blocked: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    decline_global_limited: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    decline_refused: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    // SSH backend counters
    ssh_attempts: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    ssh_logins: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    ssh_failures: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

pub const DHCPServer = struct {
    allocator: std.mem.Allocator,
    cfg: *Config,
    cfg_path: []const u8,
    store: *StateStore,
    /// One DNS updater per pool (indexed parallel to cfg.pools). Null if pool has DNS disabled.
    dns_updaters: []?*dns_mod.DNSUpdater,
    log_level: *config_mod.LogLevel,
    running: std.atomic.Value(bool),
    last_prune: i64,
    server_ip: [4]u8,
    /// DHCP socket file descriptor. Set in run() after binding; -1 before run().
    sock_fd: std.atomic.Value(i32) = std.atomic.Value(i32).init(-1),
    /// Keyed by MAC as a fixed [17]u8 ("xx:xx:xx:xx:xx:xx") — no heap alloc per entry.
    decline_records: std.AutoHashMap([17]u8, DeclineRecord),
    global_decline_count: u32,
    global_decline_window_start: i64,
    /// Interface info for ARP probing. Null when not detected (probe falls back to ICMP).
    if_info: ?probe_mod.IfaceInfo,
    /// Lease synchronisation manager. Null when sync is disabled.
    sync_mgr: ?*sync_mod.SyncManager,
    /// DHCP message counters. Populated only when cfg.metrics.collect is true.
    counters: Counters,
    /// Fixed-size DNS resolution cache for hostname-based server entries.
    resolve_cache: [RESOLVE_CACHE_SIZE]ResolveCacheEntry,

    const Self = @This();

    pub fn create(
        allocator: std.mem.Allocator,
        cfg: *Config,
        cfg_path: []const u8,
        store: *StateStore,
        log_level: *config_mod.LogLevel,
        sync_mgr: ?*sync_mod.SyncManager,
    ) !*Self {
        const dns_updaters = try createDnsUpdaters(allocator, cfg);
        errdefer freeDnsUpdaters(allocator, dns_updaters);

        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);
        const cfg_path_owned = try allocator.dupe(u8, cfg_path);
        errdefer allocator.free(cfg_path_owned);

        self.* = .{
            .allocator = allocator,
            .cfg = cfg,
            .cfg_path = cfg_path_owned,
            .store = store,
            .dns_updaters = dns_updaters,
            .log_level = log_level,
            .running = std.atomic.Value(bool).init(false),
            .last_prune = 0,
            // Pre-populate from listen_address so callers that don't call run() still
            // get a useful server_ip. run() will overwrite this with the detected IP.
            .server_ip = config_mod.parseIpv4(cfg.listen_address) catch [4]u8{ 0, 0, 0, 0 },
            .decline_records = std.AutoHashMap([17]u8, DeclineRecord).init(allocator),
            .global_decline_count = 0,
            .global_decline_window_start = 0,
            .if_info = null,
            .sync_mgr = sync_mgr,
            .counters = .{},
            .resolve_cache = [_]ResolveCacheEntry{.{ .name_hash = 0, .name_buf = [_]u8{0} ** 64, .name_len = 0, .ip = .{ 0, 0, 0, 0 }, .timestamp = 0 }} ** RESOLVE_CACHE_SIZE,
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        freeDnsUpdaters(self.allocator, self.dns_updaters);
        self.decline_records.deinit();
        self.allocator.free(self.cfg_path);
        self.allocator.destroy(self);
    }

    // -----------------------------------------------------------------------
    // FORCERENEW (RFC 3203)
    // -----------------------------------------------------------------------

    /// Send a DHCPFORCERENEW message to a specific client IP, causing it to
    /// initiate a renew cycle. Thread-safe: uses the atomic sock_fd.
    /// Includes RFC 6704 Forcerenew Nonce Authentication (option 90) when
    /// the lease has a stored nonce from the original DHCPACK.
    pub fn sendForceRenew(self: *Self, client_ip: [4]u8) void {
        const fd_i32 = self.sock_fd.load(.acquire);
        if (fd_i32 < 0) return; // socket not yet open
        const fd: std.posix.fd_t = @intCast(fd_i32);

        // Look up the lease by IP to retrieve the forcerenew nonce and client MAC.
        var ip_str_buf: [15]u8 = undefined;
        const ip_str = std.fmt.bufPrint(&ip_str_buf, "{d}.{d}.{d}.{d}", .{
            client_ip[0], client_ip[1], client_ip[2], client_ip[3],
        }) catch unreachable;
        const lease = self.store.getLeaseByIp(ip_str);

        // Decode the nonce from hex if available.
        var nonce_raw: [16]u8 = undefined;
        var has_nonce = false;
        if (lease) |l| {
            if (l.forcerenew_nonce) |hex_nonce| {
                if (hex_nonce.len == 32) {
                    has_nonce = true;
                    for (0..16) |bi| {
                        nonce_raw[bi] = std.fmt.parseInt(u8, hex_nonce[bi * 2 ..][0..2], 16) catch {
                            has_nonce = false;
                            break;
                        };
                    }
                }
            }
        }

        var pkt: [400]u8 align(4) = [_]u8{0} ** 400;
        const hdr: *DHCPHeader = @ptrCast(@alignCast(&pkt));
        hdr.op = 2; // BOOTREPLY
        hdr.htype = 1;
        hdr.hlen = 6;
        hdr.xid = std.crypto.random.int(u32);
        hdr.magic = dhcp_magic_cookie;
        @memcpy(&hdr.siaddr, &self.server_ip);

        // Set client MAC in chaddr if we have the lease.
        if (lease) |l| {
            // Parse "xx:xx:xx:xx:xx:xx" MAC string into 6 bytes.
            if (l.mac.len == 17) {
                for (0..6) |mi| {
                    hdr.chaddr[mi] = std.fmt.parseInt(u8, l.mac[mi * 3 ..][0..2], 16) catch 0;
                }
            }
        }

        var i: usize = dhcp_min_packet_size;
        // Option 53: Message Type = FORCERENEW (9)
        pkt[i] = 53;
        pkt[i + 1] = 1;
        pkt[i + 2] = 9;
        i += 3;
        // Option 54: Server Identifier
        pkt[i] = 54;
        pkt[i + 1] = 4;
        @memcpy(pkt[i + 2 .. i + 6], &self.server_ip);
        i += 6;

        // Option 90: Authentication (RFC 6704 §4 / RFC 3118)
        // Only included when we have a valid nonce from the original DHCPACK.
        // Format: [90][27][protocol=3][algorithm=1][rdm=0][replay=8bytes][hmac=16bytes]
        var auth_info_offset: usize = 0; // offset of the 16-byte HMAC field within pkt
        if (has_nonce) {
            pkt[i] = @intFromEnum(OptionCode.Authentication);
            pkt[i + 1] = 27; // length: 1+1+1+8+16
            pkt[i + 2] = 3; // protocol: Reconfigure Key Authentication (RFC 6704)
            pkt[i + 3] = 1; // algorithm: HMAC-MD5
            pkt[i + 4] = 0; // RDM: Monotonically Increasing Value
            // Replay detection: current time as u64 big-endian
            const now_u64: u64 = @intCast(@max(@as(i64, 0), std.time.timestamp()));
            const replay_bytes = std.mem.toBytes(std.mem.nativeToBig(u64, now_u64));
            @memcpy(pkt[i + 5 .. i + 13], &replay_bytes);
            // Authentication Information: 16 bytes HMAC-MD5 (zeroed for now; computed below)
            auth_info_offset = i + 13;
            @memset(pkt[auth_info_offset .. auth_info_offset + 16], 0);
            i += 29; // 2 (code+len) + 27 (data)
        }

        // End
        pkt[i] = 255;
        i += 1;

        // Compute HMAC-MD5 over the entire DHCP message with the Authentication
        // Information field zeroed (already is). The nonce serves as the HMAC key.
        if (has_nonce) {
            const HmacMd5 = std.crypto.auth.hmac.Hmac(std.crypto.hash.Md5);
            var ctx = HmacMd5.init(&nonce_raw);
            ctx.update(pkt[0..i]);
            var mac: [HmacMd5.mac_length]u8 = undefined;
            ctx.final(&mac);
            @memcpy(pkt[auth_info_offset .. auth_info_offset + 16], &mac);
        }

        const dest = std.posix.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, dhcp_client_port),
            .addr = std.mem.readInt(u32, &client_ip, .big),
        };
        _ = std.posix.sendto(fd, pkt[0..i], 0, @ptrCast(&dest), @sizeOf(std.posix.sockaddr.in)) catch |err| {
            std.log.debug("FORCERENEW to {d}.{d}.{d}.{d} failed: {s}", .{
                client_ip[0], client_ip[1], client_ip[2], client_ip[3], @errorName(err),
            });
            return;
        };

        _ = self.counters.forcerenew.fetchAdd(1, .monotonic);
        std.log.info("FORCERENEW sent to {d}.{d}.{d}.{d}{s}", .{
            client_ip[0],                              client_ip[1], client_ip[2], client_ip[3],
            if (has_nonce) " (authenticated)" else "",
        });
    }

    /// Send FORCERENEW to all active leases in a specific pool.
    pub fn forceRenewPool(self: *Self, pool: *const config_mod.PoolConfig) void {
        const leases = self.store.listLeases() catch return;
        defer self.allocator.free(leases);
        const now = std.time.timestamp();
        const subnet_bytes = config_mod.parseIpv4(pool.subnet) catch return;
        const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
        for (leases) |lease| {
            if (lease.expires <= now) continue;
            const ip_bytes = config_mod.parseIpv4(lease.ip) catch continue;
            const ip_int = std.mem.readInt(u32, &ip_bytes, .big);
            if ((ip_int & pool.subnet_mask) != (subnet_int & pool.subnet_mask)) continue;
            self.sendForceRenew(ip_bytes);
        }
    }

    // -----------------------------------------------------------------------
    // Per-pool helpers
    // -----------------------------------------------------------------------

    fn createDnsUpdaters(allocator: std.mem.Allocator, cfg: *Config) ![]?*dns_mod.DNSUpdater {
        const updaters = try allocator.alloc(?*dns_mod.DNSUpdater, cfg.pools.len);
        errdefer allocator.free(updaters);
        for (cfg.pools, 0..) |*pool, i| {
            updaters[i] = dns_mod.create_updater(allocator, &pool.dns_update) catch |err| blk: {
                std.log.err("DNS updater for pool {d} ({s}) failed ({s}); disabled for that pool", .{ i, pool.subnet, @errorName(err) });
                break :blk null;
            };
        }
        return updaters;
    }

    fn freeDnsUpdaters(allocator: std.mem.Allocator, updaters: []?*dns_mod.DNSUpdater) void {
        for (updaters) |u| if (u) |du| du.cleanup();
        allocator.free(updaters);
    }

    /// Select the pool that should handle a request, given the relay gateway address
    /// and the client's current IP (ciaddr). Priority:
    ///   1. giaddr != 0 → pool whose subnet contains giaddr (relay agent identifies the subnet)
    ///   2. ciaddr != 0 → pool whose subnet contains ciaddr (client renewal)
    ///   3. server_ip   → pool whose subnet contains the server's own IP (direct clients)
    ///   4. fallback    → first pool
    fn isPoolDisabled(self: *Self, pool: *const config_mod.PoolConfig) bool {
        if (self.sync_mgr) |s| {
            const subnet_ip = config_mod.parseIpv4(pool.subnet) catch return false;
            return !s.isPoolEnabled(subnet_ip, pool.prefix_len);
        }
        return false;
    }

    fn selectPool(self: *Self, giaddr: [4]u8, ciaddr: [4]u8) ?*const config_mod.PoolConfig {
        const zero = [4]u8{ 0, 0, 0, 0 };

        if (!std.mem.eql(u8, &giaddr, &zero)) {
            const g_int = std.mem.readInt(u32, &giaddr, .big);
            for (self.cfg.pools) |*pool| {
                const s = config_mod.parseIpv4(pool.subnet) catch continue;
                if ((g_int & pool.subnet_mask) == (std.mem.readInt(u32, &s, .big) & pool.subnet_mask)) {
                    if (!self.isPoolDisabled(pool)) return pool;
                }
            }
        }

        if (!std.mem.eql(u8, &ciaddr, &zero)) {
            const ci_int = std.mem.readInt(u32, &ciaddr, .big);
            for (self.cfg.pools) |*pool| {
                const s = config_mod.parseIpv4(pool.subnet) catch continue;
                if ((ci_int & pool.subnet_mask) == (std.mem.readInt(u32, &s, .big) & pool.subnet_mask)) {
                    if (!self.isPoolDisabled(pool)) return pool;
                }
            }
        }

        const sv_int = std.mem.readInt(u32, &self.server_ip, .big);
        for (self.cfg.pools) |*pool| {
            const s = config_mod.parseIpv4(pool.subnet) catch continue;
            if ((sv_int & pool.subnet_mask) == (std.mem.readInt(u32, &s, .big) & pool.subnet_mask)) {
                if (!self.isPoolDisabled(pool)) return pool;
            }
        }

        // Fallback to first enabled pool.
        for (self.cfg.pools) |*pool| {
            if (!self.isPoolDisabled(pool)) return pool;
        }
        return null; // all pools disabled
    }

    /// Return the index of `pool` in cfg.pools (pointer arithmetic).
    fn poolIndex(self: *Self, pool: *const config_mod.PoolConfig) usize {
        return (@intFromPtr(pool) - @intFromPtr(self.cfg.pools.ptr)) / @sizeOf(config_mod.PoolConfig);
    }

    /// Return the DNS updater for the given pool, or null if disabled.
    fn dnsUpdaterForPool(self: *Self, pool: *const config_mod.PoolConfig) ?*dns_mod.DNSUpdater {
        const idx = self.poolIndex(pool);
        if (idx < self.dns_updaters.len) return self.dns_updaters[idx];
        return null;
    }

    /// Find the pool whose subnet contains `ip_str`. Returns null if no pool matches.
    fn poolForIp(self: *Self, ip_str: []const u8) ?*const config_mod.PoolConfig {
        const ip_bytes = config_mod.parseIpv4(ip_str) catch return null;
        const ip_int = std.mem.readInt(u32, &ip_bytes, .big);
        for (self.cfg.pools) |*pool| {
            const s = config_mod.parseIpv4(pool.subnet) catch continue;
            if ((ip_int & pool.subnet_mask) == std.mem.readInt(u32, &s, .big)) return pool;
        }
        return null;
    }

    /// Seed static reservations from config into the state store.
    /// Synchronise the state store's reserved entries with the current config.
    ///
    /// Pass 1 — remove or de-reserve store entries no longer in config:
    ///   A store entry is kept only if config has the same MAC **and** the same IP.
    ///   Changed IP → old entry removed, new one added in pass 2.
    ///   Removed from config → entry fully deleted from store.
    ///
    /// Pass 2 — add entries from config not already in store (or whose IP changed):
    ///   addReservation preserves the existing lease expiry so active leases
    ///   are not interrupted mid-life.
    pub fn syncReservations(self: *Self) void {
        // Collect MACs that need removal (cannot modify the map while iterating).
        var to_remove = std.ArrayListUnmanaged([]u8){};
        defer {
            for (to_remove.items) |m| self.allocator.free(m);
            to_remove.deinit(self.allocator);
        }

        var it = self.store.leases.valueIterator();
        while (it.next()) |lease| {
            if (!lease.reserved) continue;
            const still_valid = blk: {
                for (self.cfg.pools) |pool| {
                    for (pool.reservations) |r| {
                        if (std.mem.eql(u8, r.mac, lease.mac) and std.mem.eql(u8, r.ip, lease.ip))
                            break :blk true;
                    }
                }
                break :blk false;
            };
            if (!still_valid) {
                const mac_copy = self.allocator.dupe(u8, lease.mac) catch continue;
                to_remove.append(self.allocator, mac_copy) catch {
                    self.allocator.free(mac_copy);
                };
            }
        }

        for (to_remove.items) |mac| {
            std.log.info("Removing reservation for {s} (removed or changed in config)", .{mac});
            self.store.forceRemoveLease(mac);
        }

        // Add entries from config that are new or had their IP changed.
        for (self.cfg.pools) |pool| {
            for (pool.reservations) |r| {
                if (self.store.getReservationByMac(r.mac)) |existing| {
                    if (std.mem.eql(u8, existing.ip, r.ip)) continue; // unchanged
                }
                self.store.addReservation(r.mac, r.ip, r.hostname, r.client_id) catch |err| {
                    std.log.warn("Failed to seed reservation for {s}: {s}", .{ r.mac, @errorName(err) });
                    continue;
                };
                std.log.info("Seeded reservation: {s} -> {s}", .{ r.mac, r.ip });
            }
        }
    }

    /// Reload config.yaml in-place. Called from the run loop on SIGHUP.
    fn reloadConfig(self: *Self) void {
        std.log.info("Reloading configuration from {s}...", .{self.cfg_path});
        var new_cfg = config_mod.load(self.allocator, self.cfg_path) catch |err| {
            std.log.err("Config reload failed ({s}), keeping existing config", .{@errorName(err)});
            return;
        };

        // Recreate DNS updaters for the new pool configuration.
        const new_updaters = createDnsUpdaters(self.allocator, &new_cfg) catch |err| blk: {
            std.log.err("Failed to recreate DNS updaters on reload ({s}); DNS updates disabled", .{@errorName(err)});
            // Allocating zero bytes is effectively infallible; unreachable if it fails.
            break :blk self.allocator.alloc(?*dns_mod.DNSUpdater, 0) catch unreachable;
        };

        // Replace the config in-place.
        self.cfg.deinit();
        self.cfg.* = new_cfg;
        self.log_level.* = self.cfg.log_level;

        // Update the StateStore's dir reference — the old string was freed by deinit().
        self.store.dir = self.cfg.state_dir;

        // Recompute per-pool hashes and notify sync manager so peers with stale
        // configs are disconnected and forced to re-handshake.
        if (self.sync_mgr) |s| {
            s.updatePoolStates(self.cfg);
        }

        freeDnsUpdaters(self.allocator, self.dns_updaters);
        self.dns_updaters = new_updaters;

        self.syncReservations();
        std.log.info("Configuration reloaded successfully", .{});
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
        std.posix.sigaction(std.posix.SIG.HUP, &sig_action, null);

        // Parse listen address
        const listen_ip = try config_mod.parseIpv4(self.cfg.listen_address);

        // Bind UDP socket
        const sock_fd = try std.posix.socket(
            std.posix.AF.INET,
            std.posix.SOCK.DGRAM,
            std.posix.IPPROTO.UDP,
        );
        self.sock_fd.store(@intCast(sock_fd), .release);
        defer {
            self.sock_fd.store(-1, .release);
            std.posix.close(sock_fd);
        }

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
                info.mac[0],
                info.mac[1],
                info.mac[2],
                info.mac[3],
                info.mac[4],
                info.mac[5],
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
            if (g_reload.load(.seq_cst)) {
                self.reloadConfig();
                g_reload.store(false, .seq_cst);
            }

            // Build poll fds: DHCP socket always present; sync socket when enabled.
            var poll_fds: [2]std.posix.pollfd = undefined;
            poll_fds[0] = .{ .fd = sock_fd, .events = std.posix.POLL.IN, .revents = 0 };
            const sync_fd: i32 = if (self.sync_mgr) |s| s.sock_fd else -1;
            poll_fds[1] = .{ .fd = sync_fd, .events = std.posix.POLL.IN, .revents = 0 };
            const nfds: usize = if (self.sync_mgr != null) 2 else 1;

            _ = std.posix.poll(poll_fds[0..nfds], 1000) catch |err| {
                if (err == error.Interrupted) continue;
                std.log.err("poll error: {s}", .{@errorName(err)});
                continue;
            };

            const now_ts = std.time.timestamp();

            // Handle sync socket if readable
            if (self.sync_mgr) |s| {
                if (poll_fds[1].revents & std.posix.POLL.IN != 0) {
                    s.handlePacket();
                }
                s.tick(now_ts);
            }

            if (now_ts - self.last_prune > 60) {
                self.pruneExpiredWithDns();
                self.last_prune = now_ts;
            }

            // Handle DHCP socket if readable
            if (poll_fds[0].revents & std.posix.POLL.IN == 0) continue;

            const n = std.posix.recvfrom(
                sock_fd,
                &buf,
                0,
                @ptrCast(&src_addr),
                &src_len,
            ) catch |err| {
                switch (err) {
                    error.WouldBlock => {},
                    else => std.log.err("recvfrom error: {s}", .{@errorName(err)}),
                }
                continue;
            };

            const packet = buf[0..n];

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
                if (self.shouldHandleDns(lease.local)) {
                    if (self.poolForIp(lease.ip)) |pool| {
                        if (self.dnsUpdaterForPool(pool)) |du| {
                            du.notifyLeaseRemoved(lease.ip, lease.hostname);
                        }
                    }
                }
            }
            self.store.removeLease(mac);
        }
    }

    fn processPacket(self: *Self, packet: []const u8) !?[]u8 {
        if (packet.len < dhcp_min_packet_size) return null;

        // Safety: packet is at least dhcp_min_packet_size bytes, and DHCPHeader
        // is an extern struct so alignment is 1.
        const header: *const DHCPHeader = @ptrCast(@alignCast(packet.ptr));

        if (!std.mem.eql(u8, &header.magic, &dhcp_magic_cookie)) return null;

        const msg_type = getMessageType(packet) orelse return null;

        switch (msg_type) {
            .DHCPDISCOVER => {
                _ = self.counters.discover.fetchAdd(1, .monotonic);
                const resp = try self.createOffer(packet);
                if (resp != null) _ = self.counters.offer.fetchAdd(1, .monotonic);
                return resp;
            },
            .DHCPREQUEST => {
                _ = self.counters.request.fetchAdd(1, .monotonic);
                const resp = try self.createAck(packet);
                if (resp) |r| {
                    // Distinguish ACK from NAK by checking option 53 in the response
                    if (getMessageType(r)) |rt| {
                        if (rt == .DHCPACK) {
                            _ = self.counters.ack.fetchAdd(1, .monotonic);
                        } else {
                            _ = self.counters.nak.fetchAdd(1, .monotonic);
                        }
                    }
                }
                return resp;
            },
            .DHCPRELEASE => {
                _ = self.counters.release.fetchAdd(1, .monotonic);
                self.handleRelease(packet);
                return null;
            },
            .DHCPDECLINE => {
                _ = self.counters.decline.fetchAdd(1, .monotonic);
                self.handleDecline(packet);
                return null;
            },
            .DHCPINFORM => {
                _ = self.counters.inform.fetchAdd(1, .monotonic);
                return self.handleInform(packet);
            },
            .DHCPLEASEQUERY => {
                _ = self.counters.leasequery.fetchAdd(1, .monotonic);
                return self.handleLeaseQuery(packet);
            },
            else => return null,
        }
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

    /// Returns true if the client's option 60 (Vendor Class Identifier) begins with
    /// "HTTPClient", indicating a UEFI HTTP/HTTPS network boot request (per UEFI
    /// Specification §24.4 and RFC 7386).
    fn isHttpClient(packet: []const u8) bool {
        const vci = getOption(packet, .VendorClassIdentifier) orelse return false;
        return std.mem.startsWith(u8, vci, "HTTPClient");
    }

    fn getMessageType(packet: []const u8) ?MessageType {
        const val = getOption(packet, .MessageType) orelse return null;
        if (val.len < 1) return null;
        return @enumFromInt(val[0]);
    }

    /// Scan the pool's subnet for an unallocated host address to offer.
    ///
    /// Returns the first host address in the subnet that has no active lease,
    /// skipping the router and (if specific) the server's own address.
    /// Returns null when the pool is exhausted.
    /// Returns true if ip_bytes falls within the given pool's subnet.
    /// Returns true if `ip_bytes` falls within the pool's allocatable range:
    /// same subnet AND within [pool_start, pool_end] (when configured).
    /// Used to validate lease-reuse candidates in allocateIp — if pool_end
    /// was reduced after a lease was issued, the stale IP is outside the range
    /// and must not be re-offered.
    fn ipInPool(ip_bytes: [4]u8, pool: *const config_mod.PoolConfig) bool {
        const ip_int = std.mem.readInt(u32, &ip_bytes, .big);
        const subnet_bytes = config_mod.parseIpv4(pool.subnet) catch return false;
        const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
        if ((ip_int & pool.subnet_mask) != subnet_int) return false;
        if (pool.pool_start.len > 0) {
            const b = config_mod.parseIpv4(pool.pool_start) catch return false;
            if (ip_int < std.mem.readInt(u32, &b, .big)) return false;
        }
        if (pool.pool_end.len > 0) {
            const b = config_mod.parseIpv4(pool.pool_end) catch return false;
            if (ip_int > std.mem.readInt(u32, &b, .big)) return false;
        }
        return true;
    }

    /// Returns true if this server should send a DNS update for the given lease.
    /// The originating server (local=true) always handles DNS. A standby server (local=false)
    /// takes over DNS when the originating peer is down or sync is disabled (failover mode).
    fn shouldHandleDns(self: *Self, lease_local: bool) bool {
        if (lease_local) return true;
        const s = self.sync_mgr orelse return true; // no sync = single server, always handle
        return s.isLowestActivePeer(self.server_ip);
    }

    /// Returns true if the given IP string has an active probe-conflict quarantine entry.
    fn isIpQuarantined(store: *state_mod.StateStore, ip_str: []const u8) bool {
        var mac_buf: [24]u8 = undefined; // "conflict:255.255.255.255" = 24 chars
        const conflict_mac = std.fmt.bufPrint(&mac_buf, "conflict:{s}", .{ip_str}) catch return false;
        return store.getLeaseByMac(conflict_mac) != null;
    }

    fn allocateIp(self: *Self, pool: *const config_mod.PoolConfig, mac_bytes: [6]u8, client_id: ?[]const u8) !?[4]u8 {
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
                _ = self.counters.decline_refused.fetchAdd(1, .monotonic);
                return null;
            }
        }

        // Reuse an existing confirmed lease for this client if it belongs to the selected pool.
        // Client identifier (option 61) takes precedence over chaddr per RFC 2131 §2.
        // A client moving between pools should receive a fresh allocation from the new pool,
        // not its old IP from a different subnet.
        // Skip reuse if the IP was quarantined by a probe conflict — fall through to pool scan
        // so a different address is allocated instead of retrying the same conflicted one.
        if (client_id) |cid| {
            var cid_hex_buf: [510]u8 = undefined;
            const cid_hex = std.fmt.bufPrint(&cid_hex_buf, "{x}", .{cid}) catch "";
            if (cid_hex.len > 0) {
                if (self.store.getLeaseByClientId(cid_hex)) |lease| {
                    const ip = try config_mod.parseIpv4(lease.ip);
                    if (ipInPool(ip, pool) and !isIpQuarantined(self.store, lease.ip)) return ip;
                }
            }
        }
        if (self.store.getLeaseByMac(mac_str)) |lease| {
            const ip = try config_mod.parseIpv4(lease.ip);
            if (ipInPool(ip, pool) and !isIpQuarantined(self.store, lease.ip)) return ip;
        }

        // Check for a reservation for this client in the selected pool's config (ignores expiry).
        // Searching pool.reservations directly (rather than the state store) ensures a MAC
        // listed in multiple pools' reservations gets the correct IP for each pool.
        if (client_id) |cid| {
            var cid_hex_buf2: [510]u8 = undefined;
            const cid_hex2 = std.fmt.bufPrint(&cid_hex_buf2, "{x}", .{cid}) catch "";
            if (cid_hex2.len > 0) {
                for (pool.reservations) |r| {
                    if (r.client_id) |rcid|
                        if (std.mem.eql(u8, cid_hex2, rcid))
                            return try config_mod.parseIpv4(r.ip);
                }
            }
        }
        for (pool.reservations) |r| {
            if (std.mem.eql(u8, r.mac, mac_str))
                return try config_mod.parseIpv4(r.ip);
        }

        const subnet_bytes = try config_mod.parseIpv4(pool.subnet);
        const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
        const mask = pool.subnet_mask;
        const broadcast_int = subnet_int | ~mask;

        const router_bytes = try config_mod.parseIpv4(pool.router);
        const router_int = std.mem.readInt(u32, &router_bytes, .big);

        const server_bytes = try config_mod.parseIpv4(self.cfg.listen_address);
        const server_int = std.mem.readInt(u32, &server_bytes, .big);

        var pool_start_int: u32 = subnet_int + 1;
        var pool_end_int: u32 = broadcast_int - 1;
        if (pool.pool_start.len > 0) {
            const b = config_mod.parseIpv4(pool.pool_start) catch blk: {
                break :blk subnet_bytes;
            };
            pool_start_int = std.mem.readInt(u32, &b, .big);
        }
        if (pool.pool_end.len > 0) {
            const b = config_mod.parseIpv4(pool.pool_end) catch blk: {
                break :blk subnet_bytes;
            };
            pool_end_int = std.mem.readInt(u32, &b, .big);
        }

        if (pool_end_int < pool_start_int) return null; // empty pool

        const pool_size: u32 = pool_end_int - pool_start_int + 1;

        // Starting offset: random when pool_allocation_random=true, else 0 (sequential).
        const start_offset: u32 = if (self.cfg.pool_allocation_random)
            std.crypto.random.int(u32) % pool_size
        else
            0;

        var i: u32 = 0;
        while (i < pool_size) : (i += 1) {
            // Wrapping scan: start at start_offset, wrap around at pool_end.
            const offset = (start_offset + i) % pool_size;
            const candidate = pool_start_int + offset;

            blk: {
                if (candidate == router_int) break :blk;
                if (server_int != 0 and candidate == server_int) break :blk;

                var ip_bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &ip_bytes, candidate, .big);
                var ip_buf: [15]u8 = undefined;
                const ip_str = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{
                    ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                }) catch unreachable;

                // Skip IPs reserved for a different client.
                if (self.store.getReservationByIp(ip_str) != null) break :blk;

                if (self.store.getLeaseByIp(ip_str) == null) return ip_bytes;
            }
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
    /// `client_mac` is excluded from ARP replies so a client that already holds
    /// the offered IP is not treated as a conflict.
    fn probeConflict(self: *Self, ip: [4]u8, is_relayed: bool, client_mac: [6]u8) bool {
        if (is_relayed) {
            return probe_mod.icmpProbe(ip) catch false;
        } else {
            const info = self.if_info orelse return false;
            return probe_mod.arpProbe(info.mac, info.index, ip, client_mac) catch false;
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
        _ = self.counters.probe_conflict.fetchAdd(1, .monotonic);
        std.log.warn("Probe conflict: {s} is already in use, quarantining for {d}s", .{
            ip_str, probe_mod.probe_quarantine_secs,
        });
    }

    fn createOffer(self: *Self, request: []const u8) !?[]u8 {
        const req_header: *const DHCPHeader = @ptrCast(@alignCast(request.ptr));
        const pool = self.selectPool(req_header.giaddr, req_header.ciaddr) orelse return null;

        const mac_bytes: [6]u8 = req_header.chaddr[0..6].*;
        const client_id_raw = getClientId(request);

        // giaddr != 0 means the DISCOVER came through a relay agent.
        const is_relayed = !std.mem.eql(u8, &req_header.giaddr, &[_]u8{ 0, 0, 0, 0 });

        // Resolve the client's currently-leased IP, if any. Probing it would get a false
        // positive from the client itself (ARP handles this via MAC filter, but ICMP cannot).
        const client_existing_ip: ?[4]u8 = blk: {
            var mac_str_buf: [17]u8 = undefined;
            const mac_str_tmp = std.fmt.bufPrint(&mac_str_buf, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
                mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5],
            }) catch break :blk null;
            const lease = self.store.getLeaseByMac(mac_str_tmp) orelse break :blk null;
            break :blk config_mod.parseIpv4(lease.ip) catch null;
        };

        // Probe up to probe_max_tries candidates. On conflict, quarantine the IP
        // (so allocateIp skips it next iteration) and try again.
        const offered_ip = blk: {
            for (0..probe_mod.probe_max_tries) |_| {
                const candidate = (try self.allocateIp(pool, mac_bytes, client_id_raw)) orelse break :blk null;
                // Skip probe if this is the client's own existing IP — they legitimately hold it.
                const is_clients_own = if (client_existing_ip) |cip| std.mem.eql(u8, &cip, &candidate) else false;
                if (is_clients_own or !self.probeConflict(candidate, is_relayed, mac_bytes)) break :blk candidate;
                self.quarantineProbeConflict(candidate);
            }
            break :blk null;
        } orelse return null;

        logRelayAgentInfo(request);

        const prl = getOption(request, .ParameterRequestList);

        // Build MAC string for override matching.
        var mac_str_for_ov: [17]u8 = undefined;
        _ = std.fmt.bufPrint(&mac_str_for_ov, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
            mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5],
        }) catch {};

        // Look up per-MAC reservation for option overrides.
        const reservation = findConfigReservation(pool, &mac_str_for_ov);

        // Collect merged overrides: pool.dhcp_options → mac_classes → reservation.
        var overrides = collectOverrides(
            self.allocator,
            pool,
            &mac_str_for_ov,
            reservation,
            pool.mac_classes,
        );
        defer overrides.dhcp_options.deinit();

        const server_ip = self.server_ip;
        const subnet_mask = std.mem.toBytes(std.mem.nativeToBig(u32, pool.subnet_mask));
        const eff_router = overrides.router orelse pool.router;
        const router_ip = try config_mod.parseIpv4(eff_router);
        const lease_time = std.mem.toBytes(std.mem.nativeToBig(u32, pool.lease_time));
        const renewal_time = std.mem.toBytes(std.mem.nativeToBig(u32, pool.lease_time / 2));
        const rebind_time = std.mem.toBytes(std.mem.nativeToBig(u32, pool.lease_time * 7 / 8));

        // Effective values: MAC class overrides fall back to pool defaults.
        const eff_dns_servers = overrides.dns_servers orelse pool.dns_servers;
        const eff_domain_name = overrides.domain_name orelse pool.domain_name;
        const eff_domain_search = overrides.domain_search orelse pool.domain_search;
        const eff_ntp_servers = overrides.ntp_servers orelse pool.ntp_servers;
        const eff_log_servers = overrides.log_servers orelse pool.log_servers;
        const eff_wins_servers = overrides.wins_servers orelse pool.wins_servers;
        const eff_tftp_servers = overrides.tftp_servers orelse pool.tftp_servers;
        const eff_boot_filename = overrides.boot_filename orelse pool.boot_filename;
        const eff_http_boot_url = overrides.http_boot_url orelse pool.http_boot_url;
        const eff_static_routes = overrides.static_routes orelse pool.static_routes;
        const eff_time_offset: ?i32 = overrides.time_offset orelse pool.time_offset;

        // Build options into a temporary buffer
        var opts_buf: [1024]u8 = undefined;
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

        // Option 51: IP Address Lease Time — MUST be included per RFC 2131 §4.3.1
        opts_buf[opts_len] = @intFromEnum(OptionCode.IPAddressLeaseTime);
        opts_buf[opts_len + 1] = 4;
        @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &lease_time);
        opts_len += 6;

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

        // Option 6: DNS Servers (ordered, with hostname resolution)
        appendResolvedIpListOpt(&opts_buf, &opts_len, prl, .DomainNameServer, eff_dns_servers, &self.resolve_cache, null);

        // Option 15: Domain Name
        if (isRequested(prl, .DomainName) and eff_domain_name.len > 0) {
            const dn_len = @min(eff_domain_name.len, 255);
            opts_buf[opts_len] = @intFromEnum(OptionCode.DomainName);
            opts_buf[opts_len + 1] = @intCast(dn_len);
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 2 + dn_len], eff_domain_name[0..dn_len]);
            opts_len += 2 + dn_len;
        }

        // Option 119: Domain Search List (RFC 3397)
        if (isRequested(prl, .DomainSearch) and eff_domain_search.len > 0) {
            if (opts_len + 2 < opts_buf.len) {
                const data_len = encodeDnsSearchList(opts_buf[opts_len + 2 ..], eff_domain_search);
                if (data_len > 0 and data_len <= 255) {
                    opts_buf[opts_len] = @intFromEnum(OptionCode.DomainSearch);
                    opts_buf[opts_len + 1] = @intCast(data_len);
                    opts_len += 2 + data_len;
                }
            }
        }

        // Option 2: Time Offset
        if (isRequested(prl, .TimeOffset)) {
            if (eff_time_offset) |offset| {
                opts_buf[opts_len] = @intFromEnum(OptionCode.TimeOffset);
                opts_buf[opts_len + 1] = 4;
                const be = std.mem.nativeToBig(i32, offset);
                @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &std.mem.toBytes(be));
                opts_len += 6;
            }
        }

        // Shuffle seed from xid for load-distributing server lists.
        const xid_seed: u32 = req_header.xid;

        // Option 4: Time Servers (RFC 868) — shuffled for load distribution.
        // Use explicit time_servers if configured, otherwise mirror ntp_servers.
        appendResolvedIpListOpt(&opts_buf, &opts_len, prl, .TimeServer, if (pool.time_servers.len > 0) pool.time_servers else eff_ntp_servers, &self.resolve_cache, xid_seed);

        // Option 7: Log Servers — shuffled for load distribution.
        appendResolvedIpListOpt(&opts_buf, &opts_len, prl, .LogServer, eff_log_servers, &self.resolve_cache, xid_seed);

        // Option 42: NTP Servers — shuffled for load distribution.
        appendResolvedIpListOpt(&opts_buf, &opts_len, prl, .NtpServers, eff_ntp_servers, &self.resolve_cache, xid_seed);

        // Option 26: Interface MTU
        if (!isOverridden(&overrides.dhcp_options, 26)) {
            if (pool.mtu) |mtu| {
                if (isRequestedCode(prl, 26) and opts_len + 4 <= opts_buf.len) {
                    opts_buf[opts_len] = @intFromEnum(OptionCode.InterfaceMTU);
                    opts_buf[opts_len + 1] = 2;
                    const mtu_be = std.mem.nativeToBig(u16, mtu);
                    @memcpy(opts_buf[opts_len + 2 .. opts_len + 4], &std.mem.toBytes(mtu_be));
                    opts_len += 4;
                }
            }
        }

        // Option 28: Broadcast Address (auto-derived from subnet)
        if (!isOverridden(&overrides.dhcp_options, 28)) {
            if (isRequestedCode(prl, 28) and opts_len + 6 <= opts_buf.len) {
                const bcast_sip = config_mod.parseIpv4(pool.subnet) catch null;
                if (bcast_sip) |sip| {
                    const bcast_ip_int = std.mem.readInt(u32, &sip, .big);
                    const bcast = bcast_ip_int | ~pool.subnet_mask;
                    opts_buf[opts_len] = @intFromEnum(OptionCode.BroadcastAddress);
                    opts_buf[opts_len + 1] = 4;
                    const bcast_be = std.mem.nativeToBig(u32, bcast);
                    @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &std.mem.toBytes(bcast_be));
                    opts_len += 6;
                }
            }
        }

        // Option 44: NetBIOS/WINS Name Servers — shuffled for load distribution.
        if (!isOverridden(&overrides.dhcp_options, 44)) {
            appendResolvedIpListOpt(&opts_buf, &opts_len, prl, .NetBIOSNameServers, eff_wins_servers, &self.resolve_cache, xid_seed);
        }

        // Option 66/67: Boot options (TFTP or UEFI HTTP boot).
        if (isHttpClient(request) and eff_http_boot_url.len > 0) {
            // UEFI HTTP boot: echo option 60 "HTTPClient" and serve URL as option 67.
            // Both sent unconditionally per UEFI Spec §24.4.
            appendRawStringOpt(&opts_buf, &opts_len, .VendorClassIdentifier, "HTTPClient");
            appendRawStringOpt(&opts_buf, &opts_len, .BootFileName, eff_http_boot_url);
        } else {
            appendStringOpt(&opts_buf, &opts_len, prl, .TftpServerName, if (eff_tftp_servers.len > 0) eff_tftp_servers[0] else "");
            appendStringOpt(&opts_buf, &opts_len, prl, .BootFileName, eff_boot_filename);
        }

        // Option 150: Cisco TFTP Server (ordered, with hostname resolution)
        if (!isOverridden(&overrides.dhcp_options, 150)) {
            appendResolvedIpListOpt(&opts_buf, &opts_len, prl, .CiscoTftp, eff_tftp_servers, &self.resolve_cache, null);
        }

        // Option 33: Static Routes (RFC 2132)
        if (isRequested(prl, .StaticRoutes) and eff_static_routes.len > 0) {
            if (opts_len + 2 < opts_buf.len) {
                const data_len = encodeStaticRoutes(opts_buf[opts_len + 2 ..], eff_static_routes);
                if (data_len > 0 and data_len <= 255) {
                    opts_buf[opts_len] = @intFromEnum(OptionCode.StaticRoutes);
                    opts_buf[opts_len + 1] = @intCast(data_len);
                    opts_len += 2 + data_len;
                }
            }
        }

        // Option 121: Classless Static Routes (RFC 3442)
        if (isRequested(prl, .ClasslessStaticRoutes) and eff_static_routes.len > 0) {
            if (opts_len + 2 < opts_buf.len) {
                const data_len = encodeClasslessStaticRoutes(opts_buf[opts_len + 2 ..], eff_static_routes);
                if (data_len > 0 and data_len <= 255) {
                    opts_buf[opts_len] = @intFromEnum(OptionCode.ClasslessStaticRoutes);
                    opts_buf[opts_len + 1] = @intCast(data_len);
                    opts_len += 2 + data_len;
                }
            }
        }

        // Inject merged overrides: pool.dhcp_options → mac_classes → reservation
        var opts_it = overrides.dhcp_options.iterator();
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
        const resp_header: *DHCPHeader = @ptrCast(@alignCast(pkt.ptr));
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

        log_v.debug("DHCPOFFER {d}.{d}.{d}.{d} to {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
            offered_ip[0], offered_ip[1], offered_ip[2], offered_ip[3],
            mac_bytes[0],  mac_bytes[1],  mac_bytes[2],  mac_bytes[3],
            mac_bytes[4],  mac_bytes[5],
        });

        return pkt;
    }

    /// Build a DHCPACK in response to a DHCPREQUEST.
    ///
    /// Allocates and returns a packet buffer; caller is responsible for freeing.
    /// Returns null if the request is directed at another server.
    /// Returns a DHCPNAK packet if the requested IP is invalid.
    fn createAck(self: *Self, request: []const u8) !?[]u8 {
        const req_header: *const DHCPHeader = @ptrCast(@alignCast(request.ptr));
        const pool = self.selectPool(req_header.giaddr, req_header.ciaddr) orelse return null;

        // Option 54: ignore requests directed at a different server.
        if (getServerIdentifier(request)) |sid| {
            if (!std.mem.eql(u8, &sid, &self.server_ip)) return null;
        } else {
            // No server identifier — rebinding or renewal broadcast. If the client's existing
            // lease was originated by a peer (local=false) and that peer is still authenticated,
            // defer so only the originating server responds. If the peer is down, fall through
            // and take over (failover).
            const mac_bytes_tmp = req_header.chaddr[0..6];
            var mac_str_tmp: [17]u8 = undefined;
            const mac_s = std.fmt.bufPrint(&mac_str_tmp, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
                mac_bytes_tmp[0], mac_bytes_tmp[1], mac_bytes_tmp[2],
                mac_bytes_tmp[3], mac_bytes_tmp[4], mac_bytes_tmp[5],
            }) catch "";
            if (self.store.leases.get(mac_s)) |existing| {
                if (!existing.local) {
                    if (self.sync_mgr) |s| {
                        if (!s.isLowestActivePeer(self.server_ip)) return null;
                    }
                }
            }
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

        // Send DHCPNAK if the requested IP is not valid for this pool's subnet.
        if (!self.isIpValid(pool, client_ip, mac_str, client_id_hex)) return self.createNak(request);

        const server_ip = self.server_ip;
        const subnet_mask = std.mem.toBytes(std.mem.nativeToBig(u32, pool.subnet_mask));
        const lease_time = std.mem.toBytes(std.mem.nativeToBig(u32, pool.lease_time));
        const renewal_time = std.mem.toBytes(std.mem.nativeToBig(u32, pool.lease_time / 2));
        const rebind_time = std.mem.toBytes(std.mem.nativeToBig(u32, pool.lease_time * 7 / 8));

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

        // RFC 6704: generate a 16-byte random nonce for Forcerenew Nonce Authentication.
        // Stored as a 32-char hex string on the lease for JSON compatibility.
        var nonce_bytes: [16]u8 = undefined;
        std.crypto.random.bytes(&nonce_bytes);
        var nonce_hex: [32]u8 = undefined;
        _ = std.fmt.bufPrint(&nonce_hex, "{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
            nonce_bytes[0],  nonce_bytes[1],  nonce_bytes[2],  nonce_bytes[3],
            nonce_bytes[4],  nonce_bytes[5],  nonce_bytes[6],  nonce_bytes[7],
            nonce_bytes[8],  nonce_bytes[9],  nonce_bytes[10], nonce_bytes[11],
            nonce_bytes[12], nonce_bytes[13], nonce_bytes[14], nonce_bytes[15],
        }) catch unreachable;

        const new_lease = state_mod.Lease{
            .mac = mac_str,
            .ip = ip_str,
            .hostname = effective_hostname,
            .expires = now + @as(i64, pool.lease_time),
            .client_id = client_id_hex,
            .reserved = reservation != null,
            .local = true, // this server issued the DHCPACK
            .forcerenew_nonce = &nonce_hex,
        };
        self.store.addLease(new_lease) catch |err| {
            std.log.warn("Failed to store lease ({s})", .{@errorName(err)});
        };

        log_v.debug("DHCPACK {s} to {s}{s}{f} lease={d}s", .{
            ip_str,                                           mac_str,
            if (effective_hostname != null) " host=" else "", util.escapedStr(effective_hostname orelse ""),
            pool.lease_time,
        });

        // Notify sync peers of new/updated lease (use store's copy which has last_modified set)
        if (self.sync_mgr) |s| {
            if (self.store.leases.get(mac_str)) |stored| {
                s.notifyLeaseUpdate(stored);
            }
        }

        // Notify DNS updater for this pool
        if (self.dnsUpdaterForPool(pool)) |du| du.notifyLeaseAdded(ip_str, effective_hostname);

        logRelayAgentInfo(request);

        const prl = getOption(request, .ParameterRequestList);

        // Collect merged overrides: pool.dhcp_options → mac_classes → reservation.
        const config_res = findConfigReservation(pool, mac_str);
        var overrides = collectOverrides(
            self.allocator,
            pool,
            mac_str,
            config_res,
            pool.mac_classes,
        );
        defer overrides.dhcp_options.deinit();

        // Effective values: MAC class overrides fall back to pool defaults.
        const eff_router = overrides.router orelse pool.router;
        const router_ip = try config_mod.parseIpv4(eff_router);
        const eff_dns_servers = overrides.dns_servers orelse pool.dns_servers;
        const eff_domain_name = overrides.domain_name orelse pool.domain_name;
        const eff_domain_search = overrides.domain_search orelse pool.domain_search;
        const eff_ntp_servers = overrides.ntp_servers orelse pool.ntp_servers;
        const eff_log_servers = overrides.log_servers orelse pool.log_servers;
        const eff_wins_servers = overrides.wins_servers orelse pool.wins_servers;
        const eff_tftp_servers = overrides.tftp_servers orelse pool.tftp_servers;
        const eff_boot_filename = overrides.boot_filename orelse pool.boot_filename;
        const eff_http_boot_url = overrides.http_boot_url orelse pool.http_boot_url;
        const eff_static_routes = overrides.static_routes orelse pool.static_routes;
        const eff_time_offset: ?i32 = overrides.time_offset orelse pool.time_offset;

        // Build options
        var opts_buf: [1024]u8 = undefined;
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

        // Option 51: IP Address Lease Time — MUST be included per RFC 2131 §4.3.1
        opts_buf[opts_len] = @intFromEnum(OptionCode.IPAddressLeaseTime);
        opts_buf[opts_len + 1] = 4;
        @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &lease_time);
        opts_len += 6;

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

        // Option 6: DNS Servers (ordered, with hostname resolution)
        appendResolvedIpListOpt(&opts_buf, &opts_len, prl, .DomainNameServer, eff_dns_servers, &self.resolve_cache, null);

        // Option 15: Domain Name
        if (isRequested(prl, .DomainName) and eff_domain_name.len > 0) {
            const dn_len = @min(eff_domain_name.len, 255);
            opts_buf[opts_len] = @intFromEnum(OptionCode.DomainName);
            opts_buf[opts_len + 1] = @intCast(dn_len);
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 2 + dn_len], eff_domain_name[0..dn_len]);
            opts_len += 2 + dn_len;
        }

        // Option 119: Domain Search List (RFC 3397)
        if (isRequested(prl, .DomainSearch) and eff_domain_search.len > 0) {
            if (opts_len + 2 < opts_buf.len) {
                const data_len = encodeDnsSearchList(opts_buf[opts_len + 2 ..], eff_domain_search);
                if (data_len > 0 and data_len <= 255) {
                    opts_buf[opts_len] = @intFromEnum(OptionCode.DomainSearch);
                    opts_buf[opts_len + 1] = @intCast(data_len);
                    opts_len += 2 + data_len;
                }
            }
        }

        // Option 2: Time Offset
        if (isRequested(prl, .TimeOffset)) {
            if (eff_time_offset) |offset| {
                opts_buf[opts_len] = @intFromEnum(OptionCode.TimeOffset);
                opts_buf[opts_len + 1] = 4;
                const be = std.mem.nativeToBig(i32, offset);
                @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &std.mem.toBytes(be));
                opts_len += 6;
            }
        }

        // Shuffle seed from xid for load-distributing server lists.
        const xid_seed: u32 = req_header.xid;

        // Option 4: Time Servers (RFC 868) — shuffled for load distribution.
        // Use explicit time_servers if configured, otherwise mirror ntp_servers.
        appendResolvedIpListOpt(&opts_buf, &opts_len, prl, .TimeServer, if (pool.time_servers.len > 0) pool.time_servers else eff_ntp_servers, &self.resolve_cache, xid_seed);

        // Option 7: Log Servers — shuffled for load distribution.
        appendResolvedIpListOpt(&opts_buf, &opts_len, prl, .LogServer, eff_log_servers, &self.resolve_cache, xid_seed);

        // Option 42: NTP Servers — shuffled for load distribution.
        appendResolvedIpListOpt(&opts_buf, &opts_len, prl, .NtpServers, eff_ntp_servers, &self.resolve_cache, xid_seed);

        // Option 26: Interface MTU
        if (!isOverridden(&overrides.dhcp_options, 26)) {
            if (pool.mtu) |mtu| {
                if (isRequestedCode(prl, 26) and opts_len + 4 <= opts_buf.len) {
                    opts_buf[opts_len] = @intFromEnum(OptionCode.InterfaceMTU);
                    opts_buf[opts_len + 1] = 2;
                    const mtu_be = std.mem.nativeToBig(u16, mtu);
                    @memcpy(opts_buf[opts_len + 2 .. opts_len + 4], &std.mem.toBytes(mtu_be));
                    opts_len += 4;
                }
            }
        }

        // Option 28: Broadcast Address (auto-derived from subnet)
        if (!isOverridden(&overrides.dhcp_options, 28)) {
            if (isRequestedCode(prl, 28) and opts_len + 6 <= opts_buf.len) {
                const bcast_sip = config_mod.parseIpv4(pool.subnet) catch null;
                if (bcast_sip) |sip| {
                    const bcast_ip_int = std.mem.readInt(u32, &sip, .big);
                    const bcast = bcast_ip_int | ~pool.subnet_mask;
                    opts_buf[opts_len] = @intFromEnum(OptionCode.BroadcastAddress);
                    opts_buf[opts_len + 1] = 4;
                    const bcast_be = std.mem.nativeToBig(u32, bcast);
                    @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &std.mem.toBytes(bcast_be));
                    opts_len += 6;
                }
            }
        }

        // Option 44: NetBIOS/WINS Name Servers — shuffled for load distribution.
        if (!isOverridden(&overrides.dhcp_options, 44)) {
            appendResolvedIpListOpt(&opts_buf, &opts_len, prl, .NetBIOSNameServers, eff_wins_servers, &self.resolve_cache, xid_seed);
        }

        // Option 66/67: Boot options (TFTP or UEFI HTTP boot).
        if (isHttpClient(request) and eff_http_boot_url.len > 0) {
            // UEFI HTTP boot: echo option 60 "HTTPClient" and serve URL as option 67.
            // Both sent unconditionally per UEFI Spec §24.4.
            appendRawStringOpt(&opts_buf, &opts_len, .VendorClassIdentifier, "HTTPClient");
            appendRawStringOpt(&opts_buf, &opts_len, .BootFileName, eff_http_boot_url);
        } else {
            appendStringOpt(&opts_buf, &opts_len, prl, .TftpServerName, if (eff_tftp_servers.len > 0) eff_tftp_servers[0] else "");
            appendStringOpt(&opts_buf, &opts_len, prl, .BootFileName, eff_boot_filename);
        }

        // Option 150: Cisco TFTP Server (ordered, with hostname resolution)
        if (!isOverridden(&overrides.dhcp_options, 150)) {
            appendResolvedIpListOpt(&opts_buf, &opts_len, prl, .CiscoTftp, eff_tftp_servers, &self.resolve_cache, null);
        }

        // Option 33: Static Routes (RFC 2132)
        if (isRequested(prl, .StaticRoutes) and eff_static_routes.len > 0) {
            if (opts_len + 2 < opts_buf.len) {
                const data_len = encodeStaticRoutes(opts_buf[opts_len + 2 ..], eff_static_routes);
                if (data_len > 0 and data_len <= 255) {
                    opts_buf[opts_len] = @intFromEnum(OptionCode.StaticRoutes);
                    opts_buf[opts_len + 1] = @intCast(data_len);
                    opts_len += 2 + data_len;
                }
            }
        }

        // Option 121: Classless Static Routes (RFC 3442)
        if (isRequested(prl, .ClasslessStaticRoutes) and eff_static_routes.len > 0) {
            if (opts_len + 2 < opts_buf.len) {
                const data_len = encodeClasslessStaticRoutes(opts_buf[opts_len + 2 ..], eff_static_routes);
                if (data_len > 0 and data_len <= 255) {
                    opts_buf[opts_len] = @intFromEnum(OptionCode.ClasslessStaticRoutes);
                    opts_buf[opts_len + 1] = @intCast(data_len);
                    opts_len += 2 + data_len;
                }
            }
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

        // Inject merged overrides: pool.dhcp_options → mac_classes → reservation
        var opts_it = overrides.dhcp_options.iterator();
        while (opts_it.next()) |entry| {
            const code = std.fmt.parseInt(u8, entry.key_ptr.*, 10) catch continue;
            if (!isRequestedCode(prl, code)) continue;
            const encoded = encodeOptionValue(opts_buf[opts_len + 2 ..], entry.value_ptr.*);
            if (encoded.len > 255 or opts_len + 2 + encoded.len > opts_buf.len - 1) continue;
            opts_buf[opts_len] = code;
            opts_buf[opts_len + 1] = @intCast(encoded.len);
            opts_len += 2 + encoded.len;
        }

        // Option 145: Forcerenew Nonce Authentication (RFC 6704 §3)
        // Format: [145][17][algorithm=1][16 nonce bytes]
        if (opts_len + 19 <= opts_buf.len - 1) {
            opts_buf[opts_len] = @intFromEnum(OptionCode.ForcerenewNonce);
            opts_buf[opts_len + 1] = 17; // length: 1 (algorithm) + 16 (nonce)
            opts_buf[opts_len + 2] = 1; // algorithm: HMAC-MD5
            @memcpy(opts_buf[opts_len + 3 .. opts_len + 19], &nonce_bytes);
            opts_len += 19;
        }

        // End
        opts_buf[opts_len] = @intFromEnum(OptionCode.End);
        opts_len += 1;

        // Allocate response packet
        const pkt_len = dhcp_min_packet_size + opts_len;
        const pkt = try self.allocator.alloc(u8, pkt_len);
        @memset(pkt, 0);

        const resp_header: *DHCPHeader = @ptrCast(@alignCast(pkt.ptr));
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
        const req_header: *const DHCPHeader = @ptrCast(@alignCast(request.ptr));
        const mac_bytes = req_header.chaddr[0..6];
        var mac_str_buf: [17]u8 = undefined;
        const mac_str = std.fmt.bufPrint(&mac_str_buf, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
            mac_bytes[0], mac_bytes[1], mac_bytes[2],
            mac_bytes[3], mac_bytes[4], mac_bytes[5],
        }) catch return;

        // Get IP and hostname from current lease before removing (for DNS cleanup).
        // Copy the strings we need — removeLease frees the originals for non-reserved leases.
        const old_lease = self.store.getLeaseByMac(mac_str);
        var ip_copy: [16]u8 = undefined;
        var ip_len: usize = 0;
        var hn_copy: [256]u8 = undefined;
        var hn_len: usize = 0;
        var old_local: bool = false;
        if (old_lease) |l| {
            ip_len = @min(l.ip.len, ip_copy.len);
            @memcpy(ip_copy[0..ip_len], l.ip[0..ip_len]);
            if (l.hostname) |h| {
                hn_len = @min(h.len, hn_copy.len);
                @memcpy(hn_copy[0..hn_len], h[0..hn_len]);
            }
            old_local = l.local;
        }
        // Check if reserved before removal (reserved leases get expires=0, not deleted)
        const is_reserved = if (self.store.leases.get(mac_str)) |l| l.reserved else false;
        self.store.removeLease(mac_str);
        if (old_lease != null) {
            const ip_str = ip_copy[0..ip_len];
            const hn_str: ?[]const u8 = if (hn_len > 0) hn_copy[0..hn_len] else null;
            log_v.debug("DHCPRELEASE {s} from {s}", .{ ip_str, mac_str });
            if (self.shouldHandleDns(old_local)) {
                if (self.poolForIp(ip_str)) |pool| {
                    if (self.dnsUpdaterForPool(pool)) |du| du.notifyLeaseRemoved(ip_str, hn_str);
                }
            }
        }
        // Notify sync peers: reserved leases are LEASE_UPDATE (expires=0), regular are LEASE_DELETE
        if (self.sync_mgr) |s| {
            if (is_reserved) {
                if (self.store.leases.get(mac_str)) |stored| s.notifyLeaseUpdate(stored);
            } else {
                s.notifyLeaseDelete(mac_str);
            }
        }
    }

    fn handleDecline(self: *Self, request: []const u8) void {
        if (request.len < dhcp_min_packet_size) return;
        const req_header: *const DHCPHeader = @ptrCast(@alignCast(request.ptr));
        const pool = self.selectPool(req_header.giaddr, req_header.ciaddr) orelse return;

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
                _ = self.counters.decline_global_limited.fetchAdd(1, .monotonic);
                return;
            }
            self.global_decline_count += 1;
        }

        // Quarantine the declined IP for max(lease_time/10, 5 min) using a sentinel MAC.
        // allocateIp skips IPs where getLeaseByIp != null.
        // isIpValid rejects IPs whose stored MAC != client MAC ("conflict:..." never matches).
        // pruneExpiredWithDns removes the quarantine after the quarantine period.
        const quarantine_secs: u32 = @max(pool.lease_time / 10, 300);
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
        _ = self.counters.decline_ip_quarantined.fetchAdd(1, .monotonic);
        log_v.debug("DHCPDECLINE {s} from {s} (quarantined {d}s)", .{ ip_str, mac_str, quarantine_secs });

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
            _ = self.counters.decline_mac_blocked.fetchAdd(1, .monotonic);
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
            // Truncate logged bytes to 16 to prevent blob output from large
            // relay-agent sub-options; always show the actual length.
            const preview = sub_data[0..@min(sub_data.len, 16)];
            const truncated = sub_data.len > 16;
            switch (sub_code) {
                1 => std.log.debug("Option 82 circuit-id ({d}B){s}: {x}", .{ sub_len, if (truncated) "…" else "", preview }),
                2 => std.log.debug("Option 82 remote-id ({d}B){s}: {x}", .{ sub_len, if (truncated) "…" else "", preview }),
                else => std.log.debug("Option 82 sub-option {d} ({d}B){s}: {x}", .{ sub_code, sub_len, if (truncated) "…" else "", preview }),
            }
            i += 2 + sub_len;
        }
    }

    /// Returns true if `ip` is a valid host address in the pool's subnet that is either
    /// unleased or already leased to this client (matched by mac_str or client_id_hex).
    fn isIpValid(self: *Self, pool: *const config_mod.PoolConfig, ip: [4]u8, mac_str: []const u8, client_id_hex: ?[]const u8) bool {
        const ip_int = std.mem.readInt(u32, &ip, .big);
        const subnet_bytes = config_mod.parseIpv4(pool.subnet) catch return false;
        const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
        const mask = pool.subnet_mask;
        const broadcast_int = subnet_int | ~mask;

        if ((ip_int & mask) != subnet_int) return false;
        if (ip_int == subnet_int or ip_int == broadcast_int) return false;

        // Reject reserved addresses: router and server's own IP.
        const router_bytes = config_mod.parseIpv4(pool.router) catch return false;
        if (ip_int == std.mem.readInt(u32, &router_bytes, .big)) return false;
        if (std.mem.eql(u8, &ip, &self.server_ip)) return false;

        if (pool.pool_start.len > 0) {
            const b = config_mod.parseIpv4(pool.pool_start) catch return false;
            if (ip_int < std.mem.readInt(u32, &b, .big)) return false;
        }
        if (pool.pool_end.len > 0) {
            const b = config_mod.parseIpv4(pool.pool_end) catch return false;
            if (ip_int > std.mem.readInt(u32, &b, .big)) return false;
        }

        var ip_buf: [15]u8 = undefined;
        const ip_str = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch return false;

        // Reject a reserved IP for a client that doesn't own the reservation.
        if (self.store.getReservationByIp(ip_str)) |res| {
            const mac_ok = std.mem.eql(u8, res.mac, mac_str);
            const cid_ok = if (client_id_hex) |cid|
                if (res.client_id) |rcid| std.mem.eql(u8, cid, rcid) else false
            else
                false;
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
        const req_header: *const DHCPHeader = @ptrCast(@alignCast(request.ptr));
        const pool = self.selectPool(req_header.giaddr, req_header.ciaddr) orelse return null;
        const server_ip = self.server_ip;

        logRelayAgentInfo(request);

        const prl = getOption(request, .ParameterRequestList);

        // Build MAC string for override matching.
        const mac_bytes = req_header.chaddr[0..6];
        var mac_str_buf_inf: [17]u8 = undefined;
        const mac_str_inf = std.fmt.bufPrint(&mac_str_buf_inf, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
            mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5],
        }) catch "";
        const config_res_inf = findConfigReservation(pool, mac_str_inf);
        var overrides = collectOverrides(self.allocator, pool, mac_str_inf, config_res_inf, pool.mac_classes);
        defer overrides.dhcp_options.deinit();

        // Effective values: MAC class overrides fall back to pool defaults.
        const eff_router = overrides.router orelse pool.router;
        const eff_dns_servers = overrides.dns_servers orelse pool.dns_servers;
        const eff_domain_name = overrides.domain_name orelse pool.domain_name;
        const eff_domain_search = overrides.domain_search orelse pool.domain_search;
        const eff_ntp_servers = overrides.ntp_servers orelse pool.ntp_servers;
        const eff_log_servers = overrides.log_servers orelse pool.log_servers;
        const eff_wins_servers = overrides.wins_servers orelse pool.wins_servers;
        const eff_tftp_servers = overrides.tftp_servers orelse pool.tftp_servers;
        const eff_boot_filename = overrides.boot_filename orelse pool.boot_filename;
        const eff_http_boot_url = overrides.http_boot_url orelse pool.http_boot_url;
        const eff_static_routes = overrides.static_routes orelse pool.static_routes;
        const eff_time_offset: ?i32 = overrides.time_offset orelse pool.time_offset;

        var opts_buf: [1024]u8 = undefined;
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
            const subnet_mask = std.mem.toBytes(std.mem.nativeToBig(u32, pool.subnet_mask));
            opts_buf[opts_len] = @intFromEnum(OptionCode.SubnetMask);
            opts_buf[opts_len + 1] = 4;
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &subnet_mask);
            opts_len += 6;
        }

        // Option 3: Router
        if (isRequested(prl, .Router)) {
            const router_ip = try config_mod.parseIpv4(eff_router);
            opts_buf[opts_len] = @intFromEnum(OptionCode.Router);
            opts_buf[opts_len + 1] = 4;
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &router_ip);
            opts_len += 6;
        }

        // Option 6: DNS Servers (ordered, with hostname resolution)
        appendResolvedIpListOpt(&opts_buf, &opts_len, prl, .DomainNameServer, eff_dns_servers, &self.resolve_cache, null);

        // Option 15: Domain Name
        if (isRequested(prl, .DomainName) and eff_domain_name.len > 0) {
            const dn_len = @min(eff_domain_name.len, 255);
            opts_buf[opts_len] = @intFromEnum(OptionCode.DomainName);
            opts_buf[opts_len + 1] = @intCast(dn_len);
            @memcpy(opts_buf[opts_len + 2 .. opts_len + 2 + dn_len], eff_domain_name[0..dn_len]);
            opts_len += 2 + dn_len;
        }

        // Option 119: Domain Search List (RFC 3397)
        if (isRequested(prl, .DomainSearch) and eff_domain_search.len > 0) {
            if (opts_len + 2 < opts_buf.len) {
                const data_len = encodeDnsSearchList(opts_buf[opts_len + 2 ..], eff_domain_search);
                if (data_len > 0 and data_len <= 255) {
                    opts_buf[opts_len] = @intFromEnum(OptionCode.DomainSearch);
                    opts_buf[opts_len + 1] = @intCast(data_len);
                    opts_len += 2 + data_len;
                }
            }
        }

        // Option 2: Time Offset
        if (isRequested(prl, .TimeOffset)) {
            if (eff_time_offset) |offset| {
                opts_buf[opts_len] = @intFromEnum(OptionCode.TimeOffset);
                opts_buf[opts_len + 1] = 4;
                const be = std.mem.nativeToBig(i32, offset);
                @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &std.mem.toBytes(be));
                opts_len += 6;
            }
        }

        // Shuffle seed from xid for load-distributing server lists.
        const xid_seed: u32 = req_header.xid;

        // Option 4: Time Servers (RFC 868) — shuffled for load distribution.
        // Use explicit time_servers if configured, otherwise mirror ntp_servers.
        appendResolvedIpListOpt(&opts_buf, &opts_len, prl, .TimeServer, if (pool.time_servers.len > 0) pool.time_servers else eff_ntp_servers, &self.resolve_cache, xid_seed);

        // Option 7: Log Servers — shuffled for load distribution.
        appendResolvedIpListOpt(&opts_buf, &opts_len, prl, .LogServer, eff_log_servers, &self.resolve_cache, xid_seed);

        // Option 42: NTP Servers — shuffled for load distribution.
        appendResolvedIpListOpt(&opts_buf, &opts_len, prl, .NtpServers, eff_ntp_servers, &self.resolve_cache, xid_seed);

        // Option 26: Interface MTU
        if (!isOverridden(&overrides.dhcp_options, 26)) {
            if (pool.mtu) |mtu| {
                if (isRequestedCode(prl, 26) and opts_len + 4 <= opts_buf.len) {
                    opts_buf[opts_len] = @intFromEnum(OptionCode.InterfaceMTU);
                    opts_buf[opts_len + 1] = 2;
                    const mtu_be = std.mem.nativeToBig(u16, mtu);
                    @memcpy(opts_buf[opts_len + 2 .. opts_len + 4], &std.mem.toBytes(mtu_be));
                    opts_len += 4;
                }
            }
        }

        // Option 28: Broadcast Address (auto-derived from subnet)
        if (!isOverridden(&overrides.dhcp_options, 28)) {
            if (isRequestedCode(prl, 28) and opts_len + 6 <= opts_buf.len) {
                const bcast_sip = config_mod.parseIpv4(pool.subnet) catch null;
                if (bcast_sip) |sip| {
                    const bcast_ip_int = std.mem.readInt(u32, &sip, .big);
                    const bcast = bcast_ip_int | ~pool.subnet_mask;
                    opts_buf[opts_len] = @intFromEnum(OptionCode.BroadcastAddress);
                    opts_buf[opts_len + 1] = 4;
                    const bcast_be = std.mem.nativeToBig(u32, bcast);
                    @memcpy(opts_buf[opts_len + 2 .. opts_len + 6], &std.mem.toBytes(bcast_be));
                    opts_len += 6;
                }
            }
        }

        // Option 44: NetBIOS/WINS Name Servers — shuffled for load distribution.
        if (!isOverridden(&overrides.dhcp_options, 44)) {
            appendResolvedIpListOpt(&opts_buf, &opts_len, prl, .NetBIOSNameServers, eff_wins_servers, &self.resolve_cache, xid_seed);
        }

        // Option 66/67: Boot options (TFTP or UEFI HTTP boot).
        if (isHttpClient(request) and eff_http_boot_url.len > 0) {
            // UEFI HTTP boot: echo option 60 "HTTPClient" and serve URL as option 67.
            // Both sent unconditionally per UEFI Spec §24.4.
            appendRawStringOpt(&opts_buf, &opts_len, .VendorClassIdentifier, "HTTPClient");
            appendRawStringOpt(&opts_buf, &opts_len, .BootFileName, eff_http_boot_url);
        } else {
            appendStringOpt(&opts_buf, &opts_len, prl, .TftpServerName, if (eff_tftp_servers.len > 0) eff_tftp_servers[0] else "");
            appendStringOpt(&opts_buf, &opts_len, prl, .BootFileName, eff_boot_filename);
        }

        // Option 150: Cisco TFTP Server (ordered, with hostname resolution)
        if (!isOverridden(&overrides.dhcp_options, 150)) {
            appendResolvedIpListOpt(&opts_buf, &opts_len, prl, .CiscoTftp, eff_tftp_servers, &self.resolve_cache, null);
        }

        // Option 33: Static Routes (RFC 2132)
        if (isRequested(prl, .StaticRoutes) and eff_static_routes.len > 0) {
            if (opts_len + 2 < opts_buf.len) {
                const data_len = encodeStaticRoutes(opts_buf[opts_len + 2 ..], eff_static_routes);
                if (data_len > 0 and data_len <= 255) {
                    opts_buf[opts_len] = @intFromEnum(OptionCode.StaticRoutes);
                    opts_buf[opts_len + 1] = @intCast(data_len);
                    opts_len += 2 + data_len;
                }
            }
        }

        // Option 121: Classless Static Routes (RFC 3442)
        if (isRequested(prl, .ClasslessStaticRoutes) and eff_static_routes.len > 0) {
            if (opts_len + 2 < opts_buf.len) {
                const data_len = encodeClasslessStaticRoutes(opts_buf[opts_len + 2 ..], eff_static_routes);
                if (data_len > 0 and data_len <= 255) {
                    opts_buf[opts_len] = @intFromEnum(OptionCode.ClasslessStaticRoutes);
                    opts_buf[opts_len + 1] = @intCast(data_len);
                    opts_len += 2 + data_len;
                }
            }
        }

        // Inject merged overrides: pool.dhcp_options → mac_classes → reservation
        var opts_it = overrides.dhcp_options.iterator();
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

        const resp_header: *DHCPHeader = @ptrCast(@alignCast(pkt.ptr));
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
        const req_header: *const DHCPHeader = @ptrCast(@alignCast(request.ptr));
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
        const resp: *DHCPHeader = @ptrCast(@alignCast(pkt.ptr));
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

        const nak_mac = req_header.chaddr[0..6];
        log_v.debug("DHCPNAK to {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
            nak_mac[0], nak_mac[1], nak_mac[2], nak_mac[3], nak_mac[4], nak_mac[5],
        });

        return pkt;
    }

    // ---------------------------------------------------------------------------
    // RFC 4388 — DHCP Leasequery
    // ---------------------------------------------------------------------------

    /// Handle an inbound DHCPLEASEQUERY (message type 10).
    /// Determines the query type from the request fields, looks up the lease,
    /// and returns a DHCPLEASEACTIVE, DHCPLEASEUNASSIGNED, or DHCPLEASEUNKNOWN response.
    fn handleLeaseQuery(self: *Self, request: []const u8) !?[]u8 {
        if (request.len < dhcp_min_packet_size) return null;
        const req_header: *const DHCPHeader = @ptrCast(@alignCast(request.ptr));

        // Determine query type from request fields.
        const zero_mac = [6]u8{ 0, 0, 0, 0, 0, 0 };
        const zero_ip = [4]u8{ 0, 0, 0, 0 };
        const has_ciaddr = !std.mem.eql(u8, &req_header.ciaddr, &zero_ip);
        const has_chaddr = !std.mem.eql(u8, req_header.chaddr[0..6], &zero_mac);
        const client_id = getOption(request, .ClientID);

        // Look up the lease based on query type.
        var lease: ?state_mod.Lease = null;
        var query_desc: []const u8 = "unknown";

        if (has_ciaddr) {
            // Query by IP address.
            var ip_buf: [16]u8 = undefined;
            const ip_str = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{
                req_header.ciaddr[0], req_header.ciaddr[1],
                req_header.ciaddr[2], req_header.ciaddr[3],
            }) catch return null;
            lease = self.store.getLeaseByIp(ip_str);
            query_desc = "IP";
        } else if (has_chaddr) {
            // Query by MAC address.
            var mac_buf: [17]u8 = undefined;
            const mac_str = std.fmt.bufPrint(&mac_buf, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
                req_header.chaddr[0], req_header.chaddr[1], req_header.chaddr[2],
                req_header.chaddr[3], req_header.chaddr[4], req_header.chaddr[5],
            }) catch return null;
            lease = self.store.getLeaseByMac(mac_str);
            query_desc = "MAC";
        } else if (client_id != null) {
            // Query by client identifier (option 61).
            lease = self.store.getLeaseByClientId(client_id.?);
            query_desc = "ClientID";
        } else if (getOption(request, .RelayAgentInformation) != null and
            !std.mem.eql(u8, &req_header.giaddr, &zero_ip))
        {
            // RFC 6148: Query by relay agent information.
            // Find the first active lease in the relay's subnet (matched via giaddr).
            const gi_int = std.mem.readInt(u32, &req_header.giaddr, .big);
            for (self.cfg.pools) |*pool| {
                const s = config_mod.parseIpv4(pool.subnet) catch continue;
                const s_int = std.mem.readInt(u32, &s, .big);
                if ((gi_int & pool.subnet_mask) == (s_int & pool.subnet_mask)) {
                    // Found the pool for this relay — scan leases for an active one.
                    const all = self.store.listLeases() catch break;
                    defer self.allocator.free(all);
                    const now = std.time.timestamp();
                    for (all) |l| {
                        if (l.expires <= now) continue;
                        const lip = config_mod.parseIpv4(l.ip) catch continue;
                        const lip_int = std.mem.readInt(u32, &lip, .big);
                        if ((lip_int & pool.subnet_mask) == (s_int & pool.subnet_mask)) {
                            lease = l;
                            break;
                        }
                    }
                    break;
                }
            }
            query_desc = "relay agent info";
        } else {
            return null; // No valid query field
        }

        // Log the query source.
        const gi = req_header.giaddr;
        std.log.info("LEASEQUERY from {d}.{d}.{d}.{d} by {s}: {s}", .{
            gi[0],      gi[1],                                        gi[2], gi[3],
            query_desc, if (lease != null) "active" else "not found",
        });

        // Active lease found — respond with DHCPLEASEACTIVE.
        if (lease) |l| {
            return self.buildLeaseQueryResponse(req_header, .DHCPLEASEACTIVE, l);
        }

        // No active lease. Check if IP is in any pool (for query-by-IP).
        if (has_ciaddr) {
            const ip_int = std.mem.readInt(u32, &req_header.ciaddr, .big);
            for (self.cfg.pools) |*pool| {
                const s = config_mod.parseIpv4(pool.subnet) catch continue;
                const s_int = std.mem.readInt(u32, &s, .big);
                if ((ip_int & pool.subnet_mask) == (s_int & pool.subnet_mask)) {
                    // IP is in a pool but not leased — DHCPLEASEUNASSIGNED.
                    return self.buildLeaseQueryResponse(req_header, .DHCPLEASEUNASSIGNED, null);
                }
            }
        }

        // IP not in any pool, or MAC/client_id has no active lease — DHCPLEASEUNKNOWN.
        return self.buildLeaseQueryResponse(req_header, .DHCPLEASEUNKNOWN, null);
    }

    /// Build a leasequery response packet (DHCPLEASEACTIVE, DHCPLEASEUNASSIGNED,
    /// or DHCPLEASEUNKNOWN). Caller owns the returned allocation.
    fn buildLeaseQueryResponse(
        self: *Self,
        req_header: *const DHCPHeader,
        msg_type: MessageType,
        lease: ?state_mod.Lease,
    ) !?[]u8 {
        var resp = try self.allocator.alloc(u8, 1024);
        @memset(resp, 0);

        const hdr: *DHCPHeader = @ptrCast(@alignCast(resp.ptr));
        hdr.op = 2; // BOOTREPLY
        hdr.htype = req_header.htype;
        hdr.hlen = req_header.hlen;
        hdr.xid = req_header.xid;
        hdr.magic = dhcp_magic_cookie;
        @memcpy(&hdr.giaddr, &req_header.giaddr); // copy for relay routing

        var opts_len: usize = dhcp_min_packet_size;

        // Option 53: Message Type
        resp[opts_len] = @intFromEnum(OptionCode.MessageType);
        resp[opts_len + 1] = 1;
        resp[opts_len + 2] = @intFromEnum(msg_type);
        opts_len += 3;

        // Option 54: Server Identifier
        resp[opts_len] = @intFromEnum(OptionCode.ServerIdentifier);
        resp[opts_len + 1] = 4;
        @memcpy(resp[opts_len + 2 .. opts_len + 6], &self.server_ip);
        opts_len += 6;

        if (msg_type == .DHCPLEASEACTIVE) {
            if (lease) |l| {
                // Set ciaddr and chaddr from the lease.
                const lip = config_mod.parseIpv4(l.ip) catch [4]u8{ 0, 0, 0, 0 };
                @memcpy(&hdr.ciaddr, &lip);

                // Parse and set MAC in chaddr.
                if (l.mac.len == 17) {
                    for (0..6) |bi| {
                        hdr.chaddr[bi] = std.fmt.parseInt(u8, l.mac[bi * 3 .. bi * 3 + 2], 16) catch 0;
                    }
                }

                // Option 51: Lease time remaining (seconds until expiry).
                const now = std.time.timestamp();
                const remaining: u32 = if (l.expires > now)
                    @intCast(@min(l.expires - now, std.math.maxInt(u32)))
                else
                    0;
                if (opts_len + 6 <= resp.len - 1) {
                    resp[opts_len] = @intFromEnum(OptionCode.IPAddressLeaseTime);
                    resp[opts_len + 1] = 4;
                    std.mem.writeInt(u32, resp[opts_len + 2 ..][0..4], remaining, .big);
                    opts_len += 6;
                }

                // Option 91: Client Last Transaction Time (seconds since last DHCP interaction).
                const cltt: u32 = if (l.last_modified > 0 and now > l.last_modified)
                    @intCast(@min(now - l.last_modified, std.math.maxInt(u32)))
                else
                    0;
                if (opts_len + 6 <= resp.len - 1) {
                    resp[opts_len] = @intFromEnum(OptionCode.ClientLastTransactionTime);
                    resp[opts_len + 1] = 4;
                    std.mem.writeInt(u32, resp[opts_len + 2 ..][0..4], cltt, .big);
                    opts_len += 6;
                }

                // Option 1: Subnet Mask (from matching pool).
                for (self.cfg.pools) |*pool| {
                    const s = config_mod.parseIpv4(pool.subnet) catch continue;
                    const s_int = std.mem.readInt(u32, &s, .big);
                    const lip_int = std.mem.readInt(u32, &lip, .big);
                    if ((lip_int & pool.subnet_mask) == (s_int & pool.subnet_mask)) {
                        // Subnet mask
                        if (opts_len + 6 <= resp.len - 1) {
                            resp[opts_len] = @intFromEnum(OptionCode.SubnetMask);
                            resp[opts_len + 1] = 4;
                            std.mem.writeInt(u32, resp[opts_len + 2 ..][0..4], pool.subnet_mask, .big);
                            opts_len += 6;
                        }
                        // Router
                        const rip = config_mod.parseIpv4(pool.router) catch break;
                        if (opts_len + 6 <= resp.len - 1) {
                            resp[opts_len] = @intFromEnum(OptionCode.Router);
                            resp[opts_len + 1] = 4;
                            @memcpy(resp[opts_len + 2 .. opts_len + 6], &rip);
                            opts_len += 6;
                        }
                        break;
                    }
                }

                // Option 12: Hostname (if available).
                if (l.hostname) |hn| {
                    if (hn.len > 0 and hn.len <= 255 and opts_len + 2 + hn.len <= resp.len - 1) {
                        resp[opts_len] = @intFromEnum(OptionCode.HostName);
                        resp[opts_len + 1] = @intCast(hn.len);
                        @memcpy(resp[opts_len + 2 .. opts_len + 2 + hn.len], hn);
                        opts_len += 2 + hn.len;
                    }
                }

                // Option 61: Client ID (if available).
                if (l.client_id) |cid| {
                    if (cid.len > 0 and cid.len <= 255 and opts_len + 2 + cid.len <= resp.len - 1) {
                        resp[opts_len] = @intFromEnum(OptionCode.ClientID);
                        resp[opts_len + 1] = @intCast(cid.len);
                        @memcpy(resp[opts_len + 2 .. opts_len + 2 + cid.len], cid);
                        opts_len += 2 + cid.len;
                    }
                }
            }
        } else {
            // For DHCPLEASEUNASSIGNED/DHCPLEASEUNKNOWN, copy the queried fields from the request.
            @memcpy(&hdr.ciaddr, &req_header.ciaddr);
            @memcpy(hdr.chaddr[0..16], req_header.chaddr[0..16]);
        }

        // End option
        resp[opts_len] = @intFromEnum(OptionCode.End);
        opts_len += 1;

        // Shrink the allocation to the actual packet size so callers can free it correctly.
        const result = self.allocator.realloc(resp, opts_len) catch resp;
        return result[0..opts_len];
    }
};

pub fn create_server(
    allocator: std.mem.Allocator,
    cfg: *Config,
    cfg_path: []const u8,
    store: *StateStore,
    log_level: *config_mod.LogLevel,
    sync_mgr: ?*sync_mod.SyncManager,
) !*DHCPServer {
    return DHCPServer.create(allocator, cfg, cfg_path, store, log_level, sync_mgr);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

var test_log_level: config_mod.LogLevel = .info;

test "resolveDestination: giaddr set -> relay at giaddr:67" {
    var pkt = std.mem.zeroes([dhcp_min_packet_size]u8);
    const hdr: *DHCPHeader = @ptrCast(@alignCast(&pkt));
    hdr.giaddr = [_]u8{ 10, 0, 0, 1 };
    const dst = resolveDestination(&pkt);
    try std.testing.expectEqual(std.mem.nativeToBig(u16, dhcp_server_port), dst.port);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 1 }, &@as([4]u8, @bitCast(dst.addr)));
}

test "resolveDestination: ciaddr set -> unicast to client:68" {
    var pkt = std.mem.zeroes([dhcp_min_packet_size]u8);
    const hdr: *DHCPHeader = @ptrCast(@alignCast(&pkt));
    hdr.ciaddr = [_]u8{ 192, 168, 1, 50 };
    const dst = resolveDestination(&pkt);
    try std.testing.expectEqual(std.mem.nativeToBig(u16, dhcp_client_port), dst.port);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 50 }, &@as([4]u8, @bitCast(dst.addr)));
}

test "resolveDestination: giaddr takes priority over ciaddr" {
    var pkt = std.mem.zeroes([dhcp_min_packet_size]u8);
    const hdr: *DHCPHeader = @ptrCast(@alignCast(&pkt));
    hdr.giaddr = [_]u8{ 10, 0, 0, 1 };
    hdr.ciaddr = [_]u8{ 192, 168, 1, 50 };
    const dst = resolveDestination(&pkt);
    try std.testing.expectEqual(std.mem.nativeToBig(u16, dhcp_server_port), dst.port);
}

test "resolveDestination: broadcast flag -> 255.255.255.255:68" {
    var pkt = std.mem.zeroes([dhcp_min_packet_size]u8);
    const hdr: *DHCPHeader = @ptrCast(@alignCast(&pkt));
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
    const hdr: *DHCPHeader = @ptrCast(@alignCast(buf.ptr));
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

/// Create a fully initialized test Config with a single pool. Caller must call cfg.deinit().
fn makeTestConfig(allocator: std.mem.Allocator) !config_mod.Config {
    const pools = try allocator.alloc(config_mod.PoolConfig, 1);
    pools[0] = config_mod.PoolConfig{
        .subnet = try allocator.dupe(u8, "192.168.1.0"),
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = try allocator.dupe(u8, "192.168.1.1"),
        .pool_start = try allocator.dupe(u8, ""),
        .pool_end = try allocator.dupe(u8, ""),
        .dns_servers = try allocator.alloc([]const u8, 0),
        .domain_name = try allocator.dupe(u8, ""),
        .domain_search = try allocator.alloc([]const u8, 0),
        .lease_time = 3600,
        .time_offset = null,
        .time_servers = try allocator.alloc([]const u8, 0),
        .log_servers = try allocator.alloc([]const u8, 0),
        .ntp_servers = try allocator.alloc([]const u8, 0),
        .mtu = null,
        .wins_servers = try allocator.alloc([]const u8, 0),
        .tftp_servers = try allocator.alloc([]const u8, 0),
        .boot_filename = try allocator.dupe(u8, ""),
        .http_boot_url = try allocator.dupe(u8, ""),
        .dns_update = .{
            .enable = false,
            .server = try allocator.dupe(u8, ""),
            .zone = try allocator.dupe(u8, ""),
            .rev_zone = try allocator.dupe(u8, ""),
            .key_name = try allocator.dupe(u8, ""),
            .key_file = try allocator.dupe(u8, ""),
            .lease_time = 3600,
        },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = try allocator.alloc(config_mod.Reservation, 0),
        .static_routes = try allocator.alloc(config_mod.StaticRoute, 0),
    };
    return config_mod.Config{
        .allocator = allocator,
        .listen_address = try allocator.dupe(u8, "192.168.1.1"),
        .state_dir = try allocator.dupe(u8, "/tmp"),
        .log_level = .info,
        .pool_allocation_random = false,
        .sync = null,
        .pools = pools,
        .admin_ssh = .{ .enable = false, .port = 2267, .bind = try allocator.dupe(u8, "0.0.0.0"), .read_only = false, .host_key = try allocator.dupe(u8, ""), .authorized_keys = try allocator.dupe(u8, "") },
        .metrics = .{ .collect = false, .http_enable = false, .http_port = 9167, .http_bind = try allocator.dupe(u8, "127.0.0.1") },
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

/// Create a test Config with two non-overlapping pools. Caller must call cfg.deinit().
/// Pool 0: 192.168.1.0/24, router 192.168.1.1  (matches listen_address → server_ip)
/// Pool 1: 10.0.0.0/24,    router 10.0.0.1      (separate subnet for relay/multi-pool tests)
fn makeTestConfig2Pool(allocator: std.mem.Allocator) !config_mod.Config {
    const pools = try allocator.alloc(config_mod.PoolConfig, 2);
    pools[0] = config_mod.PoolConfig{
        .subnet = try allocator.dupe(u8, "192.168.1.0"),
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = try allocator.dupe(u8, "192.168.1.1"),
        .pool_start = try allocator.dupe(u8, ""),
        .pool_end = try allocator.dupe(u8, ""),
        .dns_servers = try allocator.alloc([]const u8, 0),
        .domain_name = try allocator.dupe(u8, ""),
        .domain_search = try allocator.alloc([]const u8, 0),
        .lease_time = 3600,
        .time_offset = null,
        .time_servers = try allocator.alloc([]const u8, 0),
        .log_servers = try allocator.alloc([]const u8, 0),
        .ntp_servers = try allocator.alloc([]const u8, 0),
        .mtu = null,
        .wins_servers = try allocator.alloc([]const u8, 0),
        .tftp_servers = try allocator.alloc([]const u8, 0),
        .boot_filename = try allocator.dupe(u8, ""),
        .http_boot_url = try allocator.dupe(u8, ""),
        .dns_update = .{
            .enable = false,
            .server = try allocator.dupe(u8, ""),
            .zone = try allocator.dupe(u8, ""),
            .rev_zone = try allocator.dupe(u8, ""),
            .key_name = try allocator.dupe(u8, ""),
            .key_file = try allocator.dupe(u8, ""),
            .lease_time = 3600,
        },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = try allocator.alloc(config_mod.Reservation, 0),
        .static_routes = try allocator.alloc(config_mod.StaticRoute, 0),
    };
    pools[1] = config_mod.PoolConfig{
        .subnet = try allocator.dupe(u8, "10.0.0.0"),
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = try allocator.dupe(u8, "10.0.0.1"),
        .pool_start = try allocator.dupe(u8, ""),
        .pool_end = try allocator.dupe(u8, ""),
        .dns_servers = try allocator.alloc([]const u8, 0),
        .domain_name = try allocator.dupe(u8, ""),
        .domain_search = try allocator.alloc([]const u8, 0),
        .lease_time = 7200,
        .time_offset = null,
        .time_servers = try allocator.alloc([]const u8, 0),
        .log_servers = try allocator.alloc([]const u8, 0),
        .ntp_servers = try allocator.alloc([]const u8, 0),
        .mtu = null,
        .wins_servers = try allocator.alloc([]const u8, 0),
        .tftp_servers = try allocator.alloc([]const u8, 0),
        .boot_filename = try allocator.dupe(u8, ""),
        .http_boot_url = try allocator.dupe(u8, ""),
        .dns_update = .{
            .enable = false,
            .server = try allocator.dupe(u8, ""),
            .zone = try allocator.dupe(u8, ""),
            .rev_zone = try allocator.dupe(u8, ""),
            .key_name = try allocator.dupe(u8, ""),
            .key_file = try allocator.dupe(u8, ""),
            .lease_time = 7200,
        },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = try allocator.alloc(config_mod.Reservation, 0),
        .static_routes = try allocator.alloc(config_mod.StaticRoute, 0),
    };
    return config_mod.Config{
        .allocator = allocator,
        .listen_address = try allocator.dupe(u8, "192.168.1.1"),
        .state_dir = try allocator.dupe(u8, "/tmp"),
        .log_level = .info,
        .pool_allocation_random = false,
        .sync = null,
        .pools = pools,
        .admin_ssh = .{ .enable = false, .port = 2267, .bind = try allocator.dupe(u8, "0.0.0.0"), .read_only = false, .host_key = try allocator.dupe(u8, ""), .authorized_keys = try allocator.dupe(u8, "") },
        .metrics = .{ .collect = false, .http_enable = false, .http_port = 9167, .http_bind = try allocator.dupe(u8, "127.0.0.1") },
    };
}

test "createAck returns null when option 54 does not match our IP" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    var buf align(4) = [_]u8{0} ** 512;
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
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    var buf align(4) = [_]u8{0} ** 512;
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
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    var buf align(4) = [_]u8{0} ** 512;
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
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    var buf align(4) = [_]u8{0} ** 512;
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
    const hdr: *DHCPHeader = @ptrCast(@alignCast(buf.ptr));
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
    alloc.free(cfg.pools[0].pool_start);
    cfg.pools[0].pool_start = try alloc.dupe(u8, "192.168.1.100");
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    const ip = try server.allocateIp(&server.cfg.pools[0], [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, null);
    try std.testing.expect(ip != null);
    const ip_int = std.mem.readInt(u32, &ip.?, .big);
    const start_int = std.mem.readInt(u32, &[4]u8{ 192, 168, 1, 100 }, .big);
    try std.testing.expect(ip_int >= start_int);
}

test "isIpValid rejects IP outside pool range" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    alloc.free(cfg.pools[0].pool_start);
    alloc.free(cfg.pools[0].pool_end);
    cfg.pools[0].pool_start = try alloc.dupe(u8, "192.168.1.100");
    cfg.pools[0].pool_end = try alloc.dupe(u8, "192.168.1.200");
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // Below pool_start
    try std.testing.expect(!server.isIpValid(&server.cfg.pools[0], [4]u8{ 192, 168, 1, 50 }, "aa:bb:cc:dd:ee:ff", null));
    // Above pool_end
    try std.testing.expect(!server.isIpValid(&server.cfg.pools[0], [4]u8{ 192, 168, 1, 210 }, "aa:bb:cc:dd:ee:ff", null));
    // Inside pool
    try std.testing.expect(server.isIpValid(&server.cfg.pools[0], [4]u8{ 192, 168, 1, 150 }, "aa:bb:cc:dd:ee:ff", null));
}

test "handleDecline quarantines declined IP" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    var buf align(4) = [_]u8{0} ** 512;
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
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
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

    var buf align(4) = [_]u8{0} ** 512;
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
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // Override server_ip to something different from listen_address
    server.server_ip = [4]u8{ 192, 168, 1, 5 };

    var buf align(4) = [_]u8{0} ** 512;
    @memset(&buf, 0);
    const hdr: *DHCPHeader = @ptrCast(@alignCast(&buf));
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
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    server.server_ip = [4]u8{ 192, 168, 1, 5 };

    var buf align(4) = [_]u8{0} ** 512;
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
    try cfg.pools[0].dhcp_options.put(opt_key, opt_val);

    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // Send a DISCOVER
    var buf align(4) = [_]u8{0} ** 512;
    @memset(&buf, 0);
    const hdr: *DHCPHeader = @ptrCast(@alignCast(&buf));
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
        if (code == @intFromEnum(OptionCode.Pad)) {
            j += 1;
            continue;
        }
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
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    const mac = [6]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 };

    // Send decline_threshold DHCPDECLINE packets for different IPs.
    // Each one should be processed without blocking.
    var i: u32 = 0;
    while (i < decline_threshold) : (i += 1) {
        var buf align(4) = [_]u8{0} ** 512;
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
    const ip = try server.allocateIp(&server.cfg.pools[0], mac, null);
    try std.testing.expect(ip == null);
}

test "quarantine period is max(lease_time/10, 300)" {
    const alloc = std.testing.allocator;

    // lease_time = 3600 → quarantine = 360s
    {
        var cfg = try makeTestConfig(alloc);
        defer cfg.deinit();
        cfg.pools[0].lease_time = 3600;
        const store = try makeTestStore(alloc);
        defer store.deinit();
        const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
        defer server.deinit();

        var buf align(4) = [_]u8{0} ** 512;
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
        cfg.pools[0].lease_time = 600;
        const store = try makeTestStore(alloc);
        defer store.deinit();
        const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
        defer server.deinit();

        var buf align(4) = [_]u8{0} ** 512;
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
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // Force the window to be current so counts don't reset.
    server.global_decline_window_start = std.time.timestamp();

    // Send global_decline_limit declines from distinct MACs — all should quarantine.
    var i: u32 = 0;
    while (i < global_decline_limit) : (i += 1) {
        var buf align(4) = [_]u8{0} ** 512;
        const mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0x00, 0x00, @intCast(i) };
        const ip = [4]u8{ 192, 168, 1, @intCast(10 + i) };
        const len = makeDecline(&buf, mac, ip);
        _ = try server.processPacket(buf[0..len]);
    }
    try std.testing.expectEqual(global_decline_limit, server.global_decline_count);

    // One more decline (new MAC, new IP) should be dropped — no quarantine lease added.
    {
        var buf align(4) = [_]u8{0} ** 512;
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
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // Build a DISCOVER with hops=3
    var buf align(4) = [_]u8{0} ** 512;
    @memset(&buf, 0);
    {
        const hdr: *DHCPHeader = @ptrCast(@alignCast(&buf));
        hdr.op = 1;
        hdr.htype = 1;
        hdr.hlen = 6;
        hdr.hops = 3;
        hdr.xid = 0x11111111;
        hdr.magic = dhcp_magic_cookie;
        @memcpy(hdr.chaddr[0..6], &[6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01 });
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
        const resp_hdr: *const DHCPHeader = @ptrCast(@alignCast(resp.?.ptr));
        try std.testing.expectEqual(@as(u8, 3), resp_hdr.hops);
    }

    // Build a REQUEST with hops=2
    {
        const len = makeRequest(&buf, [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01 }, [4]u8{ 192, 168, 1, 2 }, [4]u8{ 192, 168, 1, 1 }, null);
        const hdr: *DHCPHeader = @ptrCast(@alignCast(&buf));
        hdr.hops = 2;
        const resp = try server.processPacket(buf[0..len]);
        try std.testing.expect(resp != null);
        defer alloc.free(resp.?);
        const resp_hdr: *const DHCPHeader = @ptrCast(@alignCast(resp.?.ptr));
        try std.testing.expectEqual(@as(u8, 2), resp_hdr.hops);
    }
}

test "createAck stores client_id from option 61" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    const mac = [6]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    const client_id_bytes = [_]u8{ 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }; // type=Ethernet + MAC

    var buf align(4) = [_]u8{0} ** 512;
    const len = makeRequest(&buf, mac, [4]u8{ 192, 168, 1, 50 }, [4]u8{ 192, 168, 1, 1 }, null);
    // Append option 61 before the End byte
    var pkt = buf[0..len];
    const end_pos = len - 1; // position of End option
    var new_buf = [_]u8{0} ** 512;
    @memcpy(new_buf[0..end_pos], pkt[0..end_pos]);
    var i: usize = end_pos;
    new_buf[i] = @intFromEnum(OptionCode.ClientID);
    i += 1;
    new_buf[i] = @intCast(client_id_bytes.len);
    i += 1;
    @memcpy(new_buf[i..][0..client_id_bytes.len], &client_id_bytes);
    i += client_id_bytes.len;
    new_buf[i] = @intFromEnum(OptionCode.End);
    i += 1;

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
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
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
    const ip = try server.allocateIp(&server.cfg.pools[0], different_mac, &client_id_bytes);
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
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    var buf align(4) = [_]u8{0} ** 512;
    const hdr: *DHCPHeader = @ptrCast(@alignCast(&buf));
    hdr.op = 1;
    hdr.htype = 1;
    hdr.hlen = 6;
    hdr.xid = 0x11223344;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01 });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType);
    buf[i + 1] = 1;
    buf[i + 2] = @intFromEnum(MessageType.DHCPDISCOVER);
    i += 3;
    // PRL with only subnet mask (1) and router (3) — no DNS (6), no lease time (51)
    buf[i] = @intFromEnum(OptionCode.ParameterRequestList);
    buf[i + 1] = 2;
    buf[i + 2] = 1;
    buf[i + 3] = 3;
    i += 4;
    buf[i] = @intFromEnum(OptionCode.End);
    i += 1;

    const resp = try server.processPacket(buf[0..i]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);

    try std.testing.expectEqual(MessageType.DHCPOFFER, DHCPServer.getMessageType(resp.?).?);
    // Subnet mask and router should be present (requested)
    try std.testing.expect(DHCPServer.getOption(resp.?, .SubnetMask) != null);
    try std.testing.expect(DHCPServer.getOption(resp.?, .Router) != null);
    // DNS and renewal time should be absent (not requested)
    // Note: lease time (51) is always sent per RFC 2131 §4.3.1, so we check renewal time (58) instead.
    try std.testing.expect(DHCPServer.getOption(resp.?, .DomainNameServer) == null);
    try std.testing.expect(DHCPServer.getOption(resp.?, .RenewalTimeValue) == null);
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
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    var buf align(4) = [_]u8{0} ** 512;
    @memset(&buf, 0);
    const hdr: *DHCPHeader = @ptrCast(@alignCast(&buf));
    hdr.op = 1;
    hdr.htype = 1;
    hdr.hlen = 6;
    hdr.xid = 0xAABBCCDD;
    hdr.magic = dhcp_magic_cookie;
    hdr.ciaddr = [4]u8{ 192, 168, 1, 55 }; // client already has an IP
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType);
    buf[i + 1] = 1;
    buf[i + 2] = @intFromEnum(MessageType.DHCPINFORM);
    i += 3;
    buf[i] = @intFromEnum(OptionCode.End);
    i += 1;

    const resp = try server.processPacket(buf[0..i]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);

    // Must be DHCPACK
    try std.testing.expectEqual(MessageType.DHCPACK, DHCPServer.getMessageType(resp.?).?);

    // yiaddr must be 0 (no address assigned)
    const resp_hdr: *const DHCPHeader = @ptrCast(@alignCast(resp.?.ptr));
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
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // makeTestConfig sets router = "192.168.1.1"
    const router_ip = [4]u8{ 192, 168, 1, 1 };
    try std.testing.expect(!server.isIpValid(&server.cfg.pools[0], router_ip, "aa:bb:cc:dd:ee:ff", null));
}

test "DHCPREQUEST for router IP results in DHCPNAK" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    var buf align(4) = [_]u8{0} ** 512;
    const hdr: *DHCPHeader = @ptrCast(@alignCast(&buf));
    hdr.op = 1;
    hdr.htype = 1;
    hdr.hlen = 6;
    hdr.xid = 0xDEAD;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType);
    buf[i + 1] = 1;
    buf[i + 2] = @intFromEnum(MessageType.DHCPREQUEST);
    i += 3;
    // Request the router's IP address (192.168.1.1)
    buf[i] = @intFromEnum(OptionCode.RequestedIPAddress);
    buf[i + 1] = 4;
    buf[i + 2] = 192;
    buf[i + 3] = 168;
    buf[i + 4] = 1;
    buf[i + 5] = 1;
    i += 6;
    buf[i] = @intFromEnum(OptionCode.End);
    i += 1;

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

    // Add reservation to pool config so allocateIp finds it when scanning pool.reservations.
    alloc.free(cfg.pools[0].reservations);
    const reservations = try alloc.alloc(config_mod.Reservation, 1);
    reservations[0] = .{
        .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff"),
        .ip = try alloc.dupe(u8, "192.168.1.50"),
        .hostname = null,
        .client_id = null,
    };
    cfg.pools[0].reservations = reservations;

    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    try putReservationInStore(store, "aa:bb:cc:dd:ee:ff", "192.168.1.50", null);

    const ip = try server.allocateIp(&server.cfg.pools[0], [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, null);
    try std.testing.expect(ip != null);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 50 }, &ip.?);
}

test "allocateIp skips reserved IP for non-matching client" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    // Set tight pool so only .50 is available; if skipped, nothing else exists.
    alloc.free(cfg.pools[0].pool_start);
    alloc.free(cfg.pools[0].pool_end);
    cfg.pools[0].pool_start = try alloc.dupe(u8, "192.168.1.50");
    cfg.pools[0].pool_end = try alloc.dupe(u8, "192.168.1.50");
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // Reserve .50 for a specific MAC.
    try putReservationInStore(store, "aa:bb:cc:dd:ee:ff", "192.168.1.50", null);

    // A different MAC should get null (pool only has .50, which is reserved).
    const ip = try server.allocateIp(&server.cfg.pools[0], [6]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, null);
    try std.testing.expect(ip == null);
}

test "isIpValid rejects reserved IP for non-matching MAC" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    try putReservationInStore(store, "aa:bb:cc:dd:ee:ff", "192.168.1.50", null);

    // Non-matching MAC requesting the reserved IP — should be rejected.
    try std.testing.expect(!server.isIpValid(&server.cfg.pools[0], [4]u8{ 192, 168, 1, 50 }, "11:22:33:44:55:66", null));
    // Matching MAC — should be accepted.
    try std.testing.expect(server.isIpValid(&server.cfg.pools[0], [4]u8{ 192, 168, 1, 50 }, "aa:bb:cc:dd:ee:ff", null));
}

test "createAck: reserved client gets reserved IP and option 12 hostname" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    try putReservationInStore(store, "aa:bb:cc:dd:ee:ff", "192.168.1.50", "printer");

    // Build REQUEST with PRL requesting hostname (12).
    var buf align(4) = [_]u8{0} ** 512;
    @memset(&buf, 0);
    const hdr: *DHCPHeader = @ptrCast(@alignCast(&buf));
    hdr.op = 1;
    hdr.htype = 1;
    hdr.hlen = 6;
    hdr.xid = 0xAABBCCDD;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType);
    buf[i + 1] = 1;
    buf[i + 2] = @intFromEnum(MessageType.DHCPREQUEST);
    i += 3;
    buf[i] = @intFromEnum(OptionCode.RequestedIPAddress);
    buf[i + 1] = 4;
    buf[i + 2] = 192;
    buf[i + 3] = 168;
    buf[i + 4] = 1;
    buf[i + 5] = 50;
    i += 6;
    buf[i] = @intFromEnum(OptionCode.ServerIdentifier);
    buf[i + 1] = 4;
    buf[i + 2] = 192;
    buf[i + 3] = 168;
    buf[i + 4] = 1;
    buf[i + 5] = 1;
    i += 6;
    buf[i] = @intFromEnum(OptionCode.ParameterRequestList);
    buf[i + 1] = 1;
    buf[i + 2] = 12;
    i += 3; // request hostname
    buf[i] = @intFromEnum(OptionCode.End);
    i += 1;

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
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    try putReservationInStore(store, "aa:bb:cc:dd:ee:ff", "192.168.1.50", null);

    var buf align(4) = [_]u8{0} ** 512;
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
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // Seed an active reservation.
    try store.addReservation("aa:bb:cc:dd:ee:ff", "192.168.1.50", "printer", null);
    // Set expiry to simulate an active lease.
    store.leases.getPtr("aa:bb:cc:dd:ee:ff").?.expires = std.time.timestamp() + 3600;

    // Build a RELEASE.
    var buf align(4) = [_]u8{0} ** 512;
    @memset(&buf, 0);
    const hdr: *DHCPHeader = @ptrCast(@alignCast(&buf));
    hdr.op = 1;
    hdr.htype = 1;
    hdr.hlen = 6;
    hdr.xid = 0x11223344;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType);
    buf[i + 1] = 1;
    buf[i + 2] = @intFromEnum(MessageType.DHCPRELEASE);
    i += 3;
    buf[i] = @intFromEnum(OptionCode.End);
    i += 1;

    const resp = try server.processPacket(buf[0..i]);
    try std.testing.expect(resp == null); // RELEASE has no response

    // Entry must still exist with expires=0.
    const entry = store.leases.get("aa:bb:cc:dd:ee:ff");
    try std.testing.expect(entry != null);
    try std.testing.expectEqual(@as(i64, 0), entry.?.expires);
    try std.testing.expect(entry.?.reserved);
}

test "encodeDnsSearchList: single and multiple domains" {
    var buf: [128]u8 = undefined;

    // Single domain: "example.com" → \x07example\x03com\x00
    const domains1 = [_][]const u8{"example.com"};
    const n1 = encodeDnsSearchList(&buf, &domains1);
    try std.testing.expectEqual(@as(usize, 13), n1);
    try std.testing.expectEqualSlices(u8, &.{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 }, buf[0..n1]);

    // Trailing dot stripped: "local." same as "local"
    const domains2 = [_][]const u8{"local."};
    const n2 = encodeDnsSearchList(&buf, &domains2);
    try std.testing.expectEqual(@as(usize, 7), n2);
    try std.testing.expectEqualSlices(u8, &.{ 5, 'l', 'o', 'c', 'a', 'l', 0 }, buf[0..n2]);

    // Multiple domains concatenated: ["stardust.lan", "local"]
    const domains3 = [_][]const u8{ "stardust.lan", "local" };
    const n3 = encodeDnsSearchList(&buf, &domains3);
    // "stardust.lan" → \x08stardust\x03lan\x00 = 14 bytes
    // "local"        → \x05local\x00            = 7 bytes
    try std.testing.expectEqual(@as(usize, 21), n3);
    try std.testing.expectEqualSlices(u8, &.{ 8, 's', 't', 'a', 'r', 'd', 'u', 's', 't', 3, 'l', 'a', 'n', 0 }, buf[0..14]);
    try std.testing.expectEqualSlices(u8, &.{ 5, 'l', 'o', 'c', 'a', 'l', 0 }, buf[14..21]);
}

test "encodeStaticRoutes: single route" {
    var buf: [16]u8 = undefined;
    const routes = [_]config_mod.StaticRoute{
        .{ .destination = [4]u8{ 10, 10, 10, 0 }, .prefix_len = 24, .router = [4]u8{ 192, 168, 1, 1 } },
    };
    const n = encodeStaticRoutes(&buf, &routes);
    try std.testing.expectEqual(@as(usize, 8), n);
    // [dest 4 bytes][router 4 bytes]
    try std.testing.expectEqualSlices(u8, &.{ 10, 10, 10, 0, 192, 168, 1, 1 }, buf[0..n]);
}

test "encodeStaticRoutes: multiple routes" {
    var buf: [32]u8 = undefined;
    const routes = [_]config_mod.StaticRoute{
        .{ .destination = [4]u8{ 10, 10, 10, 0 }, .prefix_len = 24, .router = [4]u8{ 192, 168, 1, 1 } },
        .{ .destination = [4]u8{ 172, 16, 0, 0 }, .prefix_len = 12, .router = [4]u8{ 192, 168, 1, 254 } },
    };
    const n = encodeStaticRoutes(&buf, &routes);
    try std.testing.expectEqual(@as(usize, 16), n);
    try std.testing.expectEqualSlices(u8, &.{ 10, 10, 10, 0, 192, 168, 1, 1 }, buf[0..8]);
    try std.testing.expectEqualSlices(u8, &.{ 172, 16, 0, 0, 192, 168, 1, 254 }, buf[8..16]);
}

test "encodeClasslessStaticRoutes: /8 route" {
    // /8: prefix_len=8, sig=1 → [8][d1][router] = 6 bytes
    var buf: [16]u8 = undefined;
    const routes = [_]config_mod.StaticRoute{
        .{ .destination = [4]u8{ 10, 0, 0, 0 }, .prefix_len = 8, .router = [4]u8{ 192, 168, 1, 1 } },
    };
    const n = encodeClasslessStaticRoutes(&buf, &routes);
    try std.testing.expectEqual(@as(usize, 6), n);
    try std.testing.expectEqualSlices(u8, &.{ 8, 10, 192, 168, 1, 1 }, buf[0..n]);
}

test "encodeClasslessStaticRoutes: /24 route" {
    // /24: sig=3 → [24][d1][d2][d3][router] = 8 bytes
    var buf: [16]u8 = undefined;
    const routes = [_]config_mod.StaticRoute{
        .{ .destination = [4]u8{ 10, 10, 10, 0 }, .prefix_len = 24, .router = [4]u8{ 192, 168, 1, 1 } },
    };
    const n = encodeClasslessStaticRoutes(&buf, &routes);
    try std.testing.expectEqual(@as(usize, 8), n);
    try std.testing.expectEqualSlices(u8, &.{ 24, 10, 10, 10, 192, 168, 1, 1 }, buf[0..n]);
}

test "encodeClasslessStaticRoutes: /32 host route" {
    // /32: sig=4 → [32][d1][d2][d3][d4][router] = 9 bytes
    var buf: [16]u8 = undefined;
    const routes = [_]config_mod.StaticRoute{
        .{ .destination = [4]u8{ 10, 10, 10, 1 }, .prefix_len = 32, .router = [4]u8{ 192, 168, 1, 1 } },
    };
    const n = encodeClasslessStaticRoutes(&buf, &routes);
    try std.testing.expectEqual(@as(usize, 9), n);
    try std.testing.expectEqualSlices(u8, &.{ 32, 10, 10, 10, 1, 192, 168, 1, 1 }, buf[0..n]);
}

test "encodeClasslessStaticRoutes: multiple routes" {
    // /8 → 6 bytes, /24 → 8 bytes; total 14 bytes
    var buf: [32]u8 = undefined;
    const routes = [_]config_mod.StaticRoute{
        .{ .destination = [4]u8{ 10, 0, 0, 0 }, .prefix_len = 8, .router = [4]u8{ 192, 168, 1, 1 } },
        .{ .destination = [4]u8{ 10, 10, 10, 0 }, .prefix_len = 24, .router = [4]u8{ 192, 168, 1, 254 } },
    };
    const n = encodeClasslessStaticRoutes(&buf, &routes);
    try std.testing.expectEqual(@as(usize, 14), n);
    try std.testing.expectEqualSlices(u8, &.{ 8, 10, 192, 168, 1, 1 }, buf[0..6]);
    try std.testing.expectEqualSlices(u8, &.{ 24, 10, 10, 10, 192, 168, 1, 254 }, buf[6..14]);
}

test "OFFER includes option 33 when PRL requests it" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    // Add a static route to the config.
    alloc.free(cfg.pools[0].static_routes);
    cfg.pools[0].static_routes = try alloc.dupe(config_mod.StaticRoute, &[_]config_mod.StaticRoute{
        .{ .destination = [4]u8{ 10, 10, 10, 0 }, .prefix_len = 24, .router = [4]u8{ 192, 168, 1, 1 } },
    });
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    var buf align(4) = [_]u8{0} ** 512;
    const hdr: *DHCPHeader = @ptrCast(@alignCast(&buf));
    hdr.op = 1;
    hdr.htype = 1;
    hdr.hlen = 6;
    hdr.xid = 0x11223344;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01 });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType);
    buf[i + 1] = 1;
    buf[i + 2] = @intFromEnum(MessageType.DHCPDISCOVER);
    i += 3;
    buf[i] = @intFromEnum(OptionCode.ParameterRequestList);
    buf[i + 1] = 1;
    buf[i + 2] = 33;
    i += 3; // request option 33
    buf[i] = @intFromEnum(OptionCode.End);
    i += 1;

    const resp = try server.processPacket(buf[0..i]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);

    const opt33 = DHCPServer.getOption(resp.?, .StaticRoutes);
    try std.testing.expect(opt33 != null);
    try std.testing.expectEqual(@as(usize, 8), opt33.?.len);
    try std.testing.expectEqualSlices(u8, &.{ 10, 10, 10, 0, 192, 168, 1, 1 }, opt33.?);
}

test "OFFER includes option 121 when PRL requests it" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    alloc.free(cfg.pools[0].static_routes);
    cfg.pools[0].static_routes = try alloc.dupe(config_mod.StaticRoute, &[_]config_mod.StaticRoute{
        .{ .destination = [4]u8{ 10, 10, 10, 0 }, .prefix_len = 24, .router = [4]u8{ 192, 168, 1, 1 } },
    });
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    var buf align(4) = [_]u8{0} ** 512;
    const hdr: *DHCPHeader = @ptrCast(@alignCast(&buf));
    hdr.op = 1;
    hdr.htype = 1;
    hdr.hlen = 6;
    hdr.xid = 0x11223345;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02 });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType);
    buf[i + 1] = 1;
    buf[i + 2] = @intFromEnum(MessageType.DHCPDISCOVER);
    i += 3;
    buf[i] = @intFromEnum(OptionCode.ParameterRequestList);
    buf[i + 1] = 1;
    buf[i + 2] = 121;
    i += 3; // request option 121
    buf[i] = @intFromEnum(OptionCode.End);
    i += 1;

    const resp = try server.processPacket(buf[0..i]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);

    const opt121 = DHCPServer.getOption(resp.?, .ClasslessStaticRoutes);
    try std.testing.expect(opt121 != null);
    // /24: [24][d1][d2][d3][router] = 8 bytes
    try std.testing.expectEqual(@as(usize, 8), opt121.?.len);
    try std.testing.expectEqualSlices(u8, &.{ 24, 10, 10, 10, 192, 168, 1, 1 }, opt121.?);
}

test "OFFER omits static route options when not in PRL" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    alloc.free(cfg.pools[0].static_routes);
    cfg.pools[0].static_routes = try alloc.dupe(config_mod.StaticRoute, &[_]config_mod.StaticRoute{
        .{ .destination = [4]u8{ 10, 10, 10, 0 }, .prefix_len = 24, .router = [4]u8{ 192, 168, 1, 1 } },
    });
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    var buf align(4) = [_]u8{0} ** 512;
    const hdr: *DHCPHeader = @ptrCast(@alignCast(&buf));
    hdr.op = 1;
    hdr.htype = 1;
    hdr.hlen = 6;
    hdr.xid = 0x11223346;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x03 });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType);
    buf[i + 1] = 1;
    buf[i + 2] = @intFromEnum(MessageType.DHCPDISCOVER);
    i += 3;
    // PRL with only subnet mask (1) and router (3) — no static routes
    buf[i] = @intFromEnum(OptionCode.ParameterRequestList);
    buf[i + 1] = 2;
    buf[i + 2] = 1;
    buf[i + 3] = 3;
    i += 4;
    buf[i] = @intFromEnum(OptionCode.End);
    i += 1;

    const resp = try server.processPacket(buf[0..i]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);

    try std.testing.expect(DHCPServer.getOption(resp.?, .StaticRoutes) == null);
    try std.testing.expect(DHCPServer.getOption(resp.?, .ClasslessStaticRoutes) == null);
}

test "getOption: zero-length option value" {
    // Option code present with len=0 should return a valid but empty slice.
    var pkt = [_]u8{0} ** (dhcp_min_packet_size + 4);
    @memcpy(pkt[dhcp_min_packet_size - 4 .. dhcp_min_packet_size], &dhcp_magic_cookie);
    pkt[dhcp_min_packet_size + 0] = @intFromEnum(OptionCode.MessageType);
    pkt[dhcp_min_packet_size + 1] = 0; // len = 0, no value bytes
    pkt[dhcp_min_packet_size + 2] = @intFromEnum(OptionCode.End);

    const val = DHCPServer.getOption(&pkt, .MessageType);
    try std.testing.expect(val != null);
    try std.testing.expectEqual(@as(usize, 0), val.?.len);
}

test "getOption: End marker stops parsing before target" {
    // End option (255) appears before the target; target should not be found.
    var pkt = [_]u8{0} ** (dhcp_min_packet_size + 8);
    @memcpy(pkt[dhcp_min_packet_size - 4 .. dhcp_min_packet_size], &dhcp_magic_cookie);
    pkt[dhcp_min_packet_size + 0] = @intFromEnum(OptionCode.End);
    // These bytes come after End and must not be parsed:
    pkt[dhcp_min_packet_size + 1] = @intFromEnum(OptionCode.MessageType);
    pkt[dhcp_min_packet_size + 2] = 1;
    pkt[dhcp_min_packet_size + 3] = @intFromEnum(MessageType.DHCPDISCOVER);

    try std.testing.expect(DHCPServer.getOption(&pkt, .MessageType) == null);
}

test "allocateIp: single-IP pool allocates the one IP" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    alloc.free(cfg.pools[0].pool_start);
    alloc.free(cfg.pools[0].pool_end);
    cfg.pools[0].pool_start = try alloc.dupe(u8, "192.168.1.42");
    cfg.pools[0].pool_end = try alloc.dupe(u8, "192.168.1.42");
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    const ip = try server.allocateIp(&server.cfg.pools[0], [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, null);
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 42 }, ip.?);
}

test "allocateIp: stale lease above shrunk pool_end is not reused" {
    // Regression: if pool_end is reduced after a lease was issued, allocateIp must
    // not re-offer the now-out-of-range IP.  Previously ipInPool only checked subnet
    // membership, so .150 passed even when pool_end=.120.
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    alloc.free(cfg.pools[0].pool_start);
    alloc.free(cfg.pools[0].pool_end);
    cfg.pools[0].pool_start = try alloc.dupe(u8, "192.168.1.100");
    cfg.pools[0].pool_end = try alloc.dupe(u8, "192.168.1.120"); // shrunk; .150 is outside

    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // Seed a stale lease at .150 for the client MAC.
    const mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    try store.addLease(.{
        .mac = "aa:bb:cc:dd:ee:ff",
        .ip = "192.168.1.150",
        .hostname = null,
        .expires = std.time.timestamp() + 3600,
        .client_id = null,
    });

    const ip = try server.allocateIp(&server.cfg.pools[0], mac, null);
    // Must not return the stale .150; must return an address within [.100, .120].
    try std.testing.expect(ip != null);
    const ip_int = std.mem.readInt(u32, &ip.?, .big);
    const start_int = std.mem.readInt(u32, &[4]u8{ 192, 168, 1, 100 }, .big);
    const end_int = std.mem.readInt(u32, &[4]u8{ 192, 168, 1, 120 }, .big);
    try std.testing.expect(ip_int >= start_int and ip_int <= end_int);
}

test "allocateIp: stale lease below shrunk pool_start is not reused" {
    // Mirror of the above: lease at .10 when pool_start was raised to .50.
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    alloc.free(cfg.pools[0].pool_start);
    alloc.free(cfg.pools[0].pool_end);
    cfg.pools[0].pool_start = try alloc.dupe(u8, "192.168.1.50");
    cfg.pools[0].pool_end = try alloc.dupe(u8, "192.168.1.80");

    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    const mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01 };
    try store.addLease(.{
        .mac = "aa:bb:cc:dd:ee:01",
        .ip = "192.168.1.10", // below new pool_start
        .hostname = null,
        .expires = std.time.timestamp() + 3600,
        .client_id = null,
    });

    const ip = try server.allocateIp(&server.cfg.pools[0], mac, null);
    try std.testing.expect(ip != null);
    const ip_int = std.mem.readInt(u32, &ip.?, .big);
    const start_int = std.mem.readInt(u32, &[4]u8{ 192, 168, 1, 50 }, .big);
    const end_int = std.mem.readInt(u32, &[4]u8{ 192, 168, 1, 80 }, .big);
    try std.testing.expect(ip_int >= start_int and ip_int <= end_int);
}

test "allocateIp: pool exhausted returns null" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    alloc.free(cfg.pools[0].pool_start);
    alloc.free(cfg.pools[0].pool_end);
    cfg.pools[0].pool_start = try alloc.dupe(u8, "192.168.1.10");
    cfg.pools[0].pool_end = try alloc.dupe(u8, "192.168.1.11");
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // Lease every IP in the two-address pool.
    try store.addLease(.{ .mac = "aa:bb:cc:00:00:01", .ip = "192.168.1.10", .hostname = null, .expires = std.time.timestamp() + 3600, .client_id = null });
    try store.addLease(.{ .mac = "aa:bb:cc:00:00:02", .ip = "192.168.1.11", .hostname = null, .expires = std.time.timestamp() + 3600, .client_id = null });

    const ip = try server.allocateIp(&server.cfg.pools[0], [6]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, null);
    try std.testing.expect(ip == null);
}

test "allocateIp: pool_end at u32 max terminates cleanly" {
    // Regression test for the u32 overflow bug: if pool_end == 0xFFFFFFFF and
    // all IPs are leased, the loop must not wrap and must return null.
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    alloc.free(cfg.pools[0].pool_start);
    alloc.free(cfg.pools[0].pool_end);
    cfg.pools[0].pool_start = try alloc.dupe(u8, "255.255.255.255");
    cfg.pools[0].pool_end = try alloc.dupe(u8, "255.255.255.255");
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // First call: pool not exhausted, returns the single available IP.
    const ip1 = try server.allocateIp(&server.cfg.pools[0], [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, null);
    try std.testing.expectEqual([4]u8{ 255, 255, 255, 255 }, ip1.?);

    // Lease that IP; pool is now exhausted.
    try store.addLease(.{
        .mac = "aa:bb:cc:dd:ee:ff",
        .ip = "255.255.255.255",
        .hostname = null,
        .expires = std.time.timestamp() + 3600,
        .client_id = null,
    });

    // Second call must return null without u32 wrapping to 0.
    const ip2 = try server.allocateIp(&server.cfg.pools[0], [6]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, null);
    try std.testing.expect(ip2 == null);
}

test "allocateIp: random mode returns an IP within pool range" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    alloc.free(cfg.pools[0].pool_start);
    alloc.free(cfg.pools[0].pool_end);
    cfg.pools[0].pool_start = try alloc.dupe(u8, "192.168.1.10");
    cfg.pools[0].pool_end = try alloc.dupe(u8, "192.168.1.20");
    cfg.pool_allocation_random = true;
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    const ip = try server.allocateIp(&server.cfg.pools[0], [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, null);
    try std.testing.expect(ip != null);
    const ip_int = std.mem.readInt(u32, &ip.?, .big);
    const start_int = std.mem.readInt(u32, &[4]u8{ 192, 168, 1, 10 }, .big);
    const end_int = std.mem.readInt(u32, &[4]u8{ 192, 168, 1, 20 }, .big);
    try std.testing.expect(ip_int >= start_int);
    try std.testing.expect(ip_int <= end_int);
}

test "allocateIp: random mode returns null when pool exhausted" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    alloc.free(cfg.pools[0].pool_start);
    alloc.free(cfg.pools[0].pool_end);
    cfg.pools[0].pool_start = try alloc.dupe(u8, "192.168.1.10");
    cfg.pools[0].pool_end = try alloc.dupe(u8, "192.168.1.12");
    cfg.pool_allocation_random = true;
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // Fill all 3 IPs (192.168.1.10, .11, .12) — router is .1 so none are skipped
    try store.addLease(.{ .mac = "aa:bb:cc:dd:ee:01", .ip = "192.168.1.10", .hostname = null, .expires = std.time.timestamp() + 3600, .client_id = null });
    try store.addLease(.{ .mac = "aa:bb:cc:dd:ee:02", .ip = "192.168.1.11", .hostname = null, .expires = std.time.timestamp() + 3600, .client_id = null });
    try store.addLease(.{ .mac = "aa:bb:cc:dd:ee:03", .ip = "192.168.1.12", .hostname = null, .expires = std.time.timestamp() + 3600, .client_id = null });

    const ip = try server.allocateIp(&server.cfg.pools[0], [6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, null);
    try std.testing.expect(ip == null);
}

test "allocateIp: random mode wraps at pool_end" {
    // With a tiny pool of 3 IPs and 2 already leased, the scan must wrap to find the remaining one.
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    alloc.free(cfg.pools[0].pool_start);
    alloc.free(cfg.pools[0].pool_end);
    cfg.pools[0].pool_start = try alloc.dupe(u8, "192.168.1.50");
    cfg.pools[0].pool_end = try alloc.dupe(u8, "192.168.1.52");
    cfg.pool_allocation_random = true;
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // Lease .51 and .52; the only free IP is .50
    try store.addLease(.{ .mac = "aa:bb:cc:dd:ee:51", .ip = "192.168.1.51", .hostname = null, .expires = std.time.timestamp() + 3600, .client_id = null });
    try store.addLease(.{ .mac = "aa:bb:cc:dd:ee:52", .ip = "192.168.1.52", .hostname = null, .expires = std.time.timestamp() + 3600, .client_id = null });

    // Regardless of starting offset, wrapping scan must find 192.168.1.50
    const ip = try server.allocateIp(&server.cfg.pools[0], [6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, null);
    try std.testing.expect(ip != null);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 50 }, &ip.?);
}

// ---------------------------------------------------------------------------
// selectPool tests
// ---------------------------------------------------------------------------

test "selectPool: giaddr in pool[1] subnet routes to pool[1]" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig2Pool(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    const pool = server.selectPool([4]u8{ 10, 0, 0, 1 }, [4]u8{ 0, 0, 0, 0 });
    try std.testing.expectEqual(&server.cfg.pools[1], pool.?);
}

test "selectPool: ciaddr in pool[1] subnet routes to pool[1] when giaddr is zero" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig2Pool(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    const pool = server.selectPool([4]u8{ 0, 0, 0, 0 }, [4]u8{ 10, 0, 0, 50 });
    try std.testing.expectEqual(&server.cfg.pools[1], pool.?);
}

test "selectPool: giaddr takes priority over ciaddr in different pool" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig2Pool(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // giaddr in pool[0], ciaddr in pool[1] → pool[0] must win
    const pool = server.selectPool([4]u8{ 192, 168, 1, 10 }, [4]u8{ 10, 0, 0, 50 });
    try std.testing.expectEqual(&server.cfg.pools[0], pool.?);
}

test "selectPool: matches server_ip pool when giaddr and ciaddr are zero" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig2Pool(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    // server_ip is derived from listen_address = "192.168.1.1" → pool[0]
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    const pool = server.selectPool([4]u8{ 0, 0, 0, 0 }, [4]u8{ 0, 0, 0, 0 });
    try std.testing.expectEqual(&server.cfg.pools[0], pool.?);
}

test "selectPool: falls back to pool[0] when nothing matches" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig2Pool(alloc);
    defer cfg.deinit();
    // Override listen_address to an IP not in any configured pool
    alloc.free(cfg.listen_address);
    cfg.listen_address = try alloc.dupe(u8, "172.16.0.1");
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    const pool = server.selectPool([4]u8{ 0, 0, 0, 0 }, [4]u8{ 0, 0, 0, 0 });
    try std.testing.expectEqual(&server.cfg.pools[0], pool.?);
}

// ---------------------------------------------------------------------------
// Multi-pool allocateIp tests
// ---------------------------------------------------------------------------

test "allocateIp: allocates from pool[1] range for a fresh client" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig2Pool(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    const ip = try server.allocateIp(&server.cfg.pools[1], [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, null);
    try std.testing.expect(ip != null);
    // Result must be in 10.0.0.0/24
    const ip_int = std.mem.readInt(u32, &ip.?, .big);
    const net_int = std.mem.readInt(u32, &[4]u8{ 10, 0, 0, 0 }, .big);
    try std.testing.expectEqual(net_int, ip_int & 0xFFFFFF00);
}

test "allocateIp: existing lease in pool[0] not reused when allocating from pool[1]" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig2Pool(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // Client has an active lease in pool[0]
    try store.addLease(.{
        .mac = "aa:bb:cc:dd:ee:ff",
        .ip = "192.168.1.50",
        .hostname = null,
        .expires = std.time.timestamp() + 3600,
        .client_id = null,
    });

    // Allocating from pool[1] must return a 10.0.0.x address, not the pool[0] lease
    const ip = try server.allocateIp(&server.cfg.pools[1], [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, null);
    try std.testing.expect(ip != null);
    const ip_int = std.mem.readInt(u32, &ip.?, .big);
    const net_int = std.mem.readInt(u32, &[4]u8{ 10, 0, 0, 0 }, .big);
    try std.testing.expectEqual(net_int, ip_int & 0xFFFFFF00);
}

test "allocateIp: MAC reserved in both pools gets correct IP per pool" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig2Pool(alloc);
    defer cfg.deinit();

    // Seed a reservation in pool[0]
    alloc.free(cfg.pools[0].reservations);
    const res0 = try alloc.alloc(config_mod.Reservation, 1);
    res0[0] = .{
        .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff"),
        .ip = try alloc.dupe(u8, "192.168.1.42"),
        .hostname = null,
        .client_id = null,
    };
    cfg.pools[0].reservations = res0;

    // Seed a reservation for the same MAC in pool[1]
    alloc.free(cfg.pools[1].reservations);
    const res1 = try alloc.alloc(config_mod.Reservation, 1);
    res1[0] = .{
        .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff"),
        .ip = try alloc.dupe(u8, "10.0.0.42"),
        .hostname = null,
        .client_id = null,
    };
    cfg.pools[1].reservations = res1;

    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // pool[0] must honour its own reservation
    const ip0 = try server.allocateIp(&server.cfg.pools[0], [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, null);
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 42 }, ip0.?);

    // pool[1] must honour its own reservation, not return the pool[0] IP
    const ip1 = try server.allocateIp(&server.cfg.pools[1], [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, null);
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 42 }, ip1.?);
}

test "isHttpClient: detects HTTPClient prefix" {
    var pkt = [_]u8{0} ** (dhcp_min_packet_size + 32);
    @memcpy(pkt[dhcp_min_packet_size - 4 .. dhcp_min_packet_size], &dhcp_magic_cookie);
    const vci = "HTTPClient";
    pkt[dhcp_min_packet_size + 0] = @intFromEnum(OptionCode.VendorClassIdentifier);
    pkt[dhcp_min_packet_size + 1] = @intCast(vci.len);
    @memcpy(pkt[dhcp_min_packet_size + 2 ..][0..vci.len], vci);
    pkt[dhcp_min_packet_size + 2 + vci.len] = @intFromEnum(OptionCode.End);

    try std.testing.expect(DHCPServer.isHttpClient(&pkt));
}

test "isHttpClient: detects HTTPClient with trailing data" {
    // UEFI spec allows "HTTPClient" followed by architecture-specific suffix.
    var pkt = [_]u8{0} ** (dhcp_min_packet_size + 32);
    @memcpy(pkt[dhcp_min_packet_size - 4 .. dhcp_min_packet_size], &dhcp_magic_cookie);
    const vci = "HTTPClient:Arch:00007";
    pkt[dhcp_min_packet_size + 0] = @intFromEnum(OptionCode.VendorClassIdentifier);
    pkt[dhcp_min_packet_size + 1] = @intCast(vci.len);
    @memcpy(pkt[dhcp_min_packet_size + 2 ..][0..vci.len], vci);
    pkt[dhcp_min_packet_size + 2 + vci.len] = @intFromEnum(OptionCode.End);

    try std.testing.expect(DHCPServer.isHttpClient(&pkt));
}

test "isHttpClient: rejects non-HTTP VCI" {
    var pkt = [_]u8{0} ** (dhcp_min_packet_size + 32);
    @memcpy(pkt[dhcp_min_packet_size - 4 .. dhcp_min_packet_size], &dhcp_magic_cookie);
    const vci = "PXEClient:Arch:00000";
    pkt[dhcp_min_packet_size + 0] = @intFromEnum(OptionCode.VendorClassIdentifier);
    pkt[dhcp_min_packet_size + 1] = @intCast(vci.len);
    @memcpy(pkt[dhcp_min_packet_size + 2 ..][0..vci.len], vci);
    pkt[dhcp_min_packet_size + 2 + vci.len] = @intFromEnum(OptionCode.End);

    try std.testing.expect(!DHCPServer.isHttpClient(&pkt));
}

test "isHttpClient: returns false when option 60 absent" {
    var pkt = [_]u8{0} ** (dhcp_min_packet_size + 4);
    @memcpy(pkt[dhcp_min_packet_size - 4 .. dhcp_min_packet_size], &dhcp_magic_cookie);
    pkt[dhcp_min_packet_size] = @intFromEnum(OptionCode.End);

    try std.testing.expect(!DHCPServer.isHttpClient(&pkt));
}

/// Build a minimal DISCOVER packet, optionally with option 60 (VCI).
fn makeDiscover(buf: []u8, mac: [6]u8, vci: ?[]const u8) usize {
    @memset(buf, 0);
    const hdr: *DHCPHeader = @ptrCast(@alignCast(buf.ptr));
    hdr.op = 1;
    hdr.htype = 1;
    hdr.hlen = 6;
    hdr.xid = 0xDEADBEEF;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &mac);

    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType);
    buf[i + 1] = 1;
    buf[i + 2] = @intFromEnum(MessageType.DHCPDISCOVER);
    i += 3;
    if (vci) |v| {
        buf[i] = @intFromEnum(OptionCode.VendorClassIdentifier);
        buf[i + 1] = @intCast(v.len);
        @memcpy(buf[i + 2 ..][0..v.len], v);
        i += 2 + v.len;
    }
    buf[i] = @intFromEnum(OptionCode.End);
    i += 1;
    return i;
}

test "UEFI HTTP boot: DISCOVER with HTTPClient gets option 60 echo and URL in option 67" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    alloc.free(cfg.pools[0].http_boot_url);
    cfg.pools[0].http_boot_url = try alloc.dupe(u8, "http://boot.example.com/efi/bootx64.efi");
    cfg.pools[0].pool_start = blk: {
        alloc.free(cfg.pools[0].pool_start);
        break :blk try alloc.dupe(u8, "192.168.1.10");
    };
    cfg.pools[0].pool_end = blk: {
        alloc.free(cfg.pools[0].pool_end);
        break :blk try alloc.dupe(u8, "192.168.1.20");
    };
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    var buf align(4) = [_]u8{0} ** 512;
    const len = makeDiscover(&buf, [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11 }, "HTTPClient");
    const resp = try server.processPacket(buf[0..len]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);

    try std.testing.expectEqual(MessageType.DHCPOFFER, DHCPServer.getMessageType(resp.?).?);
    // Option 60 must be echoed back as "HTTPClient"
    const opt60 = DHCPServer.getOption(resp.?, .VendorClassIdentifier);
    try std.testing.expect(opt60 != null);
    try std.testing.expectEqualStrings("HTTPClient", opt60.?);
    // Option 67 must contain the HTTP URL
    const opt67 = DHCPServer.getOption(resp.?, .BootFileName);
    try std.testing.expect(opt67 != null);
    try std.testing.expectEqualStrings("http://boot.example.com/efi/bootx64.efi", opt67.?);
    // Option 66 (TftpServerName) must NOT be present
    try std.testing.expect(DHCPServer.getOption(resp.?, .TftpServerName) == null);
}

test "UEFI HTTP boot: DISCOVER without HTTPClient gets normal TFTP options" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    alloc.free(cfg.pools[0].http_boot_url);
    cfg.pools[0].http_boot_url = try alloc.dupe(u8, "http://boot.example.com/efi/bootx64.efi");
    alloc.free(cfg.pools[0].tftp_servers);
    cfg.pools[0].tftp_servers = try alloc.alloc([]const u8, 1);
    cfg.pools[0].tftp_servers[0] = try alloc.dupe(u8, "tftp.example.com");
    alloc.free(cfg.pools[0].boot_filename);
    cfg.pools[0].boot_filename = try alloc.dupe(u8, "pxelinux.0");
    cfg.pools[0].pool_start = blk: {
        alloc.free(cfg.pools[0].pool_start);
        break :blk try alloc.dupe(u8, "192.168.1.10");
    };
    cfg.pools[0].pool_end = blk: {
        alloc.free(cfg.pools[0].pool_end);
        break :blk try alloc.dupe(u8, "192.168.1.20");
    };
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // No VCI option — regular PXE client
    var buf align(4) = [_]u8{0} ** 512;
    const len = makeDiscover(&buf, [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x22 }, null);
    const resp = try server.processPacket(buf[0..len]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);

    try std.testing.expectEqual(MessageType.DHCPOFFER, DHCPServer.getMessageType(resp.?).?);
    // Option 60 must NOT be present (no echo for non-HTTP clients)
    try std.testing.expect(DHCPServer.getOption(resp.?, .VendorClassIdentifier) == null);
    // Option 67 must contain TFTP filename, not the HTTP URL
    const opt67 = DHCPServer.getOption(resp.?, .BootFileName);
    try std.testing.expect(opt67 != null);
    try std.testing.expectEqualStrings("pxelinux.0", opt67.?);
}

test "UEFI HTTP boot: http_boot_url empty => normal TFTP options even with HTTPClient VCI" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    // http_boot_url is empty (default); tftp options set
    alloc.free(cfg.pools[0].tftp_servers);
    cfg.pools[0].tftp_servers = try alloc.alloc([]const u8, 1);
    cfg.pools[0].tftp_servers[0] = try alloc.dupe(u8, "tftp.example.com");
    alloc.free(cfg.pools[0].boot_filename);
    cfg.pools[0].boot_filename = try alloc.dupe(u8, "pxelinux.0");
    cfg.pools[0].pool_start = blk: {
        alloc.free(cfg.pools[0].pool_start);
        break :blk try alloc.dupe(u8, "192.168.1.10");
    };
    cfg.pools[0].pool_end = blk: {
        alloc.free(cfg.pools[0].pool_end);
        break :blk try alloc.dupe(u8, "192.168.1.20");
    };
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    var buf align(4) = [_]u8{0} ** 512;
    const len = makeDiscover(&buf, [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x33 }, "HTTPClient");
    const resp = try server.processPacket(buf[0..len]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);

    try std.testing.expectEqual(MessageType.DHCPOFFER, DHCPServer.getMessageType(resp.?).?);
    // http_boot_url empty => fallback to TFTP options
    try std.testing.expect(DHCPServer.getOption(resp.?, .VendorClassIdentifier) == null);
    const opt67 = DHCPServer.getOption(resp.?, .BootFileName);
    try std.testing.expect(opt67 != null);
    try std.testing.expectEqualStrings("pxelinux.0", opt67.?);
}

// ---------------------------------------------------------------------------
// MAC class matching tests
// ---------------------------------------------------------------------------

test "matchMacClass: OUI prefix match" {
    try std.testing.expect(matchMacClass("64:16:7f:aa:bb:cc", "64:16:7f"));
}

test "matchMacClass: OUI prefix with trailing wildcard" {
    try std.testing.expect(matchMacClass("64:16:7f:aa:bb:cc", "64:16:7f:*"));
}

test "matchMacClass: exact MAC match" {
    try std.testing.expect(matchMacClass("aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"));
}

test "matchMacClass: no match" {
    try std.testing.expect(!matchMacClass("64:16:7f:aa:bb:cc", "00:25:90"));
}

test "matchMacClass: case insensitive" {
    try std.testing.expect(matchMacClass("AA:BB:CC:dd:ee:ff", "aa:bb:cc"));
}

test "matchMacClass: wildcard-only matches everything" {
    try std.testing.expect(matchMacClass("aa:bb:cc:dd:ee:ff", "*"));
}

test "matchMacClass: two-octet prefix" {
    try std.testing.expect(matchMacClass("aa:bb:cc:dd:ee:ff", "aa:bb"));
    try std.testing.expect(!matchMacClass("aa:bc:cc:dd:ee:ff", "aa:bb"));
}

test "collectOverrides: priority pool < mac_class < reservation" {
    const allocator = std.testing.allocator;

    // Pool options: "66" = "pool-tftp", "15" = "pool.lan"
    var pool_opts = std.StringHashMap([]const u8).init(allocator);
    defer pool_opts.deinit();
    try pool_opts.put("66", "pool-tftp");
    try pool_opts.put("15", "pool.lan");

    var pool = config_mod.PoolConfig{
        .subnet = "192.168.1.0",
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = "192.168.1.1",
        .pool_start = "",
        .pool_end = "",
        .dns_servers = &.{},
        .domain_name = "",
        .domain_search = &.{},
        .lease_time = 3600,
        .time_offset = null,
        .time_servers = &.{},
        .log_servers = &.{},
        .ntp_servers = &.{},
        .mtu = null,
        .wins_servers = &.{},
        .tftp_servers = &.{},
        .boot_filename = "",
        .http_boot_url = "",
        .dns_update = .{ .enable = false, .server = "", .zone = "", .rev_zone = "", .key_name = "", .key_file = "", .lease_time = 3600 },
        .dhcp_options = pool_opts,
        .reservations = &.{},
        .static_routes = &.{},
    };

    // MAC class (OUI "aa:bb:cc") overrides "66", adds "67"
    var mc_opts = std.StringHashMap([]const u8).init(allocator);
    defer mc_opts.deinit();
    try mc_opts.put("66", "class-tftp");
    try mc_opts.put("67", "class-boot.img");

    var mac_classes = [_]config_mod.MacClass{.{
        .name = "TestClass",
        .match = "aa:bb:cc",
        .dhcp_options = mc_opts,
    }};

    // Reservation overrides "66"
    var res_opts = std.StringHashMap([]const u8).init(allocator);
    defer res_opts.deinit();
    try res_opts.put("66", "res-tftp");

    const reservation = config_mod.Reservation{
        .mac = "aa:bb:cc:dd:ee:ff",
        .ip = "192.168.1.50",
        .hostname = null,
        .client_id = null,
        .dhcp_options = res_opts,
    };

    var overrides = collectOverrides(allocator, &pool, "aa:bb:cc:dd:ee:ff", &reservation, &mac_classes);
    defer overrides.dhcp_options.deinit();

    // "66" should be reservation value (highest priority)
    try std.testing.expectEqualStrings("res-tftp", overrides.dhcp_options.get("66").?);
    // "67" should be MAC class value (pool didn't set it)
    try std.testing.expectEqualStrings("class-boot.img", overrides.dhcp_options.get("67").?);
    // "15" should be pool value (no override from class or reservation)
    try std.testing.expectEqualStrings("pool.lan", overrides.dhcp_options.get("15").?);
}

test "collectOverrides: most specific MAC class wins" {
    const allocator = std.testing.allocator;

    var pool = config_mod.PoolConfig{
        .subnet = "192.168.1.0",
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = "192.168.1.1",
        .pool_start = "",
        .pool_end = "",
        .dns_servers = &.{},
        .domain_name = "",
        .domain_search = &.{},
        .lease_time = 3600,
        .time_offset = null,
        .time_servers = &.{},
        .log_servers = &.{},
        .ntp_servers = &.{},
        .mtu = null,
        .wins_servers = &.{},
        .tftp_servers = &.{},
        .boot_filename = "",
        .http_boot_url = "",
        .dns_update = .{ .enable = false, .server = "", .zone = "", .rev_zone = "", .key_name = "", .key_file = "", .lease_time = 3600 },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = &.{},
        .static_routes = &.{},
    };
    defer pool.dhcp_options.deinit();

    // OUI class (less specific) and exact MAC class (more specific)
    var oui_opts = std.StringHashMap([]const u8).init(allocator);
    defer oui_opts.deinit();
    try oui_opts.put("66", "oui-tftp");

    var exact_opts = std.StringHashMap([]const u8).init(allocator);
    defer exact_opts.deinit();
    try exact_opts.put("66", "exact-tftp");

    var mac_classes = [_]config_mod.MacClass{
        .{ .name = "OUI", .match = "aa:bb:cc", .dhcp_options = oui_opts },
        .{ .name = "Exact", .match = "aa:bb:cc:dd:ee:ff", .dhcp_options = exact_opts },
    };

    var overrides = collectOverrides(allocator, &pool, "aa:bb:cc:dd:ee:ff", null, &mac_classes);
    defer overrides.dhcp_options.deinit();

    // More specific (exact MAC) should win over OUI prefix
    try std.testing.expectEqualStrings("exact-tftp", overrides.dhcp_options.get("66").?);
}

test "collectOverrides: no matches returns pool options only" {
    const allocator = std.testing.allocator;

    var pool_opts = std.StringHashMap([]const u8).init(allocator);
    defer pool_opts.deinit();
    try pool_opts.put("66", "pool-tftp");

    var pool = config_mod.PoolConfig{
        .subnet = "192.168.1.0",
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = "192.168.1.1",
        .pool_start = "",
        .pool_end = "",
        .dns_servers = &.{},
        .domain_name = "",
        .domain_search = &.{},
        .lease_time = 3600,
        .time_offset = null,
        .time_servers = &.{},
        .log_servers = &.{},
        .ntp_servers = &.{},
        .mtu = null,
        .wins_servers = &.{},
        .tftp_servers = &.{},
        .boot_filename = "",
        .http_boot_url = "",
        .dns_update = .{ .enable = false, .server = "", .zone = "", .rev_zone = "", .key_name = "", .key_file = "", .lease_time = 3600 },
        .dhcp_options = pool_opts,
        .reservations = &.{},
        .static_routes = &.{},
    };

    // MAC class that doesn't match
    var mc_opts = std.StringHashMap([]const u8).init(allocator);
    defer mc_opts.deinit();
    try mc_opts.put("66", "class-tftp");

    var mac_classes = [_]config_mod.MacClass{.{
        .name = "Other",
        .match = "ff:ff:ff",
        .dhcp_options = mc_opts,
    }};

    var overrides = collectOverrides(allocator, &pool, "aa:bb:cc:dd:ee:ff", null, &mac_classes);
    defer overrides.dhcp_options.deinit();

    // Only pool option should be present
    try std.testing.expectEqualStrings("pool-tftp", overrides.dhcp_options.get("66").?);
    try std.testing.expectEqual(@as(usize, 1), overrides.dhcp_options.count());
}

test "OFFER includes MTU option 26 as big-endian u16" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    cfg.pools[0].mtu = 9000;

    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // DISCOVER with PRL requesting option 26
    var buf align(4) = [_]u8{0} ** 512;
    const hdr: *DHCPHeader = @ptrCast(@alignCast(&buf));
    hdr.op = 1;
    hdr.htype = 1;
    hdr.hlen = 6;
    hdr.xid = 0x11223344;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03 });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType);
    buf[i + 1] = 1;
    buf[i + 2] = @intFromEnum(MessageType.DHCPDISCOVER);
    i += 3;
    buf[i] = @intFromEnum(OptionCode.ParameterRequestList);
    buf[i + 1] = 1;
    buf[i + 2] = 26; // request MTU
    i += 3;
    buf[i] = @intFromEnum(OptionCode.End);
    i += 1;

    const resp = try server.processPacket(buf[0..i]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);

    // Find option 26 in response and verify encoding: 9000 = 0x2328
    const opts = resp.?[dhcp_min_packet_size..];
    var j: usize = 0;
    var found = false;
    while (j + 1 < opts.len) {
        const code = opts[j];
        if (code == @intFromEnum(OptionCode.End)) break;
        if (code == 0) {
            j += 1;
            continue;
        }
        const olen = opts[j + 1];
        if (code == 26 and olen == 2) {
            try std.testing.expectEqualSlices(u8, &[2]u8{ 0x23, 0x28 }, opts[j + 2 .. j + 4]);
            found = true;
        }
        j += 2 + olen;
    }
    try std.testing.expect(found);
}

test "OFFER includes broadcast address option 28 auto-derived from subnet" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    // Subnet is 192.168.1.0/24, broadcast should be 192.168.1.255

    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    var buf align(4) = [_]u8{0} ** 512;
    const hdr: *DHCPHeader = @ptrCast(@alignCast(&buf));
    hdr.op = 1;
    hdr.htype = 1;
    hdr.hlen = 6;
    hdr.xid = 0x22334455;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0xAA, 0xBB, 0xCC, 0x04, 0x05, 0x06 });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType);
    buf[i + 1] = 1;
    buf[i + 2] = @intFromEnum(MessageType.DHCPDISCOVER);
    i += 3;
    buf[i] = @intFromEnum(OptionCode.ParameterRequestList);
    buf[i + 1] = 1;
    buf[i + 2] = 28; // request broadcast address
    i += 3;
    buf[i] = @intFromEnum(OptionCode.End);
    i += 1;

    const resp = try server.processPacket(buf[0..i]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);

    // Find option 28: should be 192.168.1.255
    const opts = resp.?[dhcp_min_packet_size..];
    var j: usize = 0;
    var found = false;
    while (j + 1 < opts.len) {
        const code = opts[j];
        if (code == @intFromEnum(OptionCode.End)) break;
        if (code == 0) {
            j += 1;
            continue;
        }
        const olen = opts[j + 1];
        if (code == 28 and olen == 4) {
            try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 255 }, opts[j + 2 .. j + 6]);
            found = true;
        }
        j += 2 + olen;
    }
    try std.testing.expect(found);
}

test "OFFER includes WINS option 44 and Cisco TFTP option 150" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();

    // Set up WINS and Cisco TFTP servers
    cfg.pools[0].wins_servers = try alloc.alloc([]const u8, 1);
    cfg.pools[0].wins_servers[0] = try alloc.dupe(u8, "10.0.0.5");
    cfg.pools[0].tftp_servers = try alloc.alloc([]const u8, 1);
    cfg.pools[0].tftp_servers[0] = try alloc.dupe(u8, "10.0.0.6");

    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    var buf align(4) = [_]u8{0} ** 512;
    const hdr: *DHCPHeader = @ptrCast(@alignCast(&buf));
    hdr.op = 1;
    hdr.htype = 1;
    hdr.hlen = 6;
    hdr.xid = 0x33445566;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0xAA, 0xBB, 0xCC, 0x07, 0x08, 0x09 });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType);
    buf[i + 1] = 1;
    buf[i + 2] = @intFromEnum(MessageType.DHCPDISCOVER);
    i += 3;
    buf[i] = @intFromEnum(OptionCode.ParameterRequestList);
    buf[i + 1] = 2;
    buf[i + 2] = 44; // WINS
    buf[i + 3] = 150; // Cisco TFTP
    i += 4;
    buf[i] = @intFromEnum(OptionCode.End);
    i += 1;

    const resp = try server.processPacket(buf[0..i]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);

    const opts = resp.?[dhcp_min_packet_size..];
    var j: usize = 0;
    var found_44 = false;
    var found_150 = false;
    while (j + 1 < opts.len) {
        const code = opts[j];
        if (code == @intFromEnum(OptionCode.End)) break;
        if (code == 0) {
            j += 1;
            continue;
        }
        const olen = opts[j + 1];
        if (code == 44 and olen == 4) {
            try std.testing.expectEqualSlices(u8, &[4]u8{ 10, 0, 0, 5 }, opts[j + 2 .. j + 6]);
            found_44 = true;
        }
        if (code == 150 and olen == 4) {
            try std.testing.expectEqualSlices(u8, &[4]u8{ 10, 0, 0, 6 }, opts[j + 2 .. j + 6]);
            found_150 = true;
        }
        j += 2 + olen;
    }
    try std.testing.expect(found_44);
    try std.testing.expect(found_150);
}

// ---------------------------------------------------------------------------
// shuffleIps unit tests
// ---------------------------------------------------------------------------

test "shuffleIps: zero items does not crash" {
    var items = [_][4]u8{};
    shuffleIps(&items, 42);
}

test "shuffleIps: single item unchanged" {
    var items = [_][4]u8{.{ 10, 0, 0, 1 }};
    shuffleIps(&items, 42);
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 1 }, items[0]);
}

test "shuffleIps: deterministic with fixed seed" {
    var a = [_][4]u8{ .{ 1, 1, 1, 1 }, .{ 2, 2, 2, 2 }, .{ 3, 3, 3, 3 }, .{ 4, 4, 4, 4 } };
    var b = [_][4]u8{ .{ 1, 1, 1, 1 }, .{ 2, 2, 2, 2 }, .{ 3, 3, 3, 3 }, .{ 4, 4, 4, 4 } };
    shuffleIps(&a, 12345);
    shuffleIps(&b, 12345);
    // Same seed must produce identical order.
    try std.testing.expectEqualSlices([4]u8, &a, &b);
}

test "shuffleIps: different seeds produce different orders" {
    var a = [_][4]u8{ .{ 1, 1, 1, 1 }, .{ 2, 2, 2, 2 }, .{ 3, 3, 3, 3 }, .{ 4, 4, 4, 4 }, .{ 5, 5, 5, 5 } };
    var b = [_][4]u8{ .{ 1, 1, 1, 1 }, .{ 2, 2, 2, 2 }, .{ 3, 3, 3, 3 }, .{ 4, 4, 4, 4 }, .{ 5, 5, 5, 5 } };
    shuffleIps(&a, 1);
    shuffleIps(&b, 999999);
    // With 5 items and wildly different seeds, the orders should differ.
    var same = true;
    for (a, b) |ai, bi| {
        if (!std.mem.eql(u8, &ai, &bi)) {
            same = false;
            break;
        }
    }
    try std.testing.expect(!same);
}

// ---------------------------------------------------------------------------
// Option 66 from tftp_servers[0] test
// ---------------------------------------------------------------------------

test "OFFER includes option 66 (TFTP server name) from tftp_servers[0] as string" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();

    // Set tftp_servers to two entries.
    alloc.free(cfg.pools[0].tftp_servers);
    cfg.pools[0].tftp_servers = try alloc.alloc([]const u8, 2);
    cfg.pools[0].tftp_servers[0] = try alloc.dupe(u8, "10.0.0.5");
    cfg.pools[0].tftp_servers[1] = try alloc.dupe(u8, "10.0.0.6");
    cfg.pools[0].pool_start = blk: {
        alloc.free(cfg.pools[0].pool_start);
        break :blk try alloc.dupe(u8, "192.168.1.10");
    };
    cfg.pools[0].pool_end = blk: {
        alloc.free(cfg.pools[0].pool_end);
        break :blk try alloc.dupe(u8, "192.168.1.20");
    };

    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // Build a DISCOVER with PRL requesting option 66.
    var buf align(4) = [_]u8{0} ** 512;
    const hdr: *DHCPHeader = @ptrCast(@alignCast(&buf));
    hdr.op = 1;
    hdr.htype = 1;
    hdr.hlen = 6;
    hdr.xid = 0x66666666;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(hdr.chaddr[0..6], &[6]u8{ 0xAA, 0xBB, 0xCC, 0x66, 0x66, 0x66 });
    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType);
    buf[i + 1] = 1;
    buf[i + 2] = @intFromEnum(MessageType.DHCPDISCOVER);
    i += 3;
    buf[i] = @intFromEnum(OptionCode.ParameterRequestList);
    buf[i + 1] = 1;
    buf[i + 2] = 66; // request option 66
    i += 3;
    buf[i] = @intFromEnum(OptionCode.End);
    i += 1;

    const resp = try server.processPacket(buf[0..i]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);

    // Verify option 66 is "10.0.0.5" as a raw string (not IP-encoded 4 bytes).
    const opt66 = DHCPServer.getOption(resp.?, .TftpServerName);
    try std.testing.expect(opt66 != null);
    try std.testing.expectEqualStrings("10.0.0.5", opt66.?);
}

// ---------------------------------------------------------------------------
// Leasequery tests
// ---------------------------------------------------------------------------

/// Build a minimal DHCPLEASEQUERY packet. Returns total packet length.
fn makeLeaseQuery(buf: []u8, ciaddr: [4]u8, chaddr: [6]u8) usize {
    @memset(buf, 0);
    const hdr: *DHCPHeader = @ptrCast(@alignCast(buf.ptr));
    hdr.op = 1; // BOOTREQUEST
    hdr.htype = 1;
    hdr.hlen = 6;
    hdr.xid = 0xABCDABCD;
    hdr.magic = dhcp_magic_cookie;
    @memcpy(&hdr.ciaddr, &ciaddr);
    @memcpy(hdr.chaddr[0..6], &chaddr);

    var i: usize = dhcp_min_packet_size;
    buf[i] = @intFromEnum(OptionCode.MessageType);
    buf[i + 1] = 1;
    buf[i + 2] = @intFromEnum(MessageType.DHCPLEASEQUERY);
    i += 3;
    buf[i] = @intFromEnum(OptionCode.End);
    i += 1;
    return i;
}

test "DHCPLEASEQUERY by IP returns DHCPLEASEACTIVE for active lease" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // Seed an active lease into the store.
    const now = std.time.timestamp();
    try store.addLease(.{
        .mac = "aa:bb:cc:dd:ee:01",
        .ip = "192.168.1.50",
        .hostname = "testhost",
        .expires = now + 3600,
        .client_id = null,
    });

    // Build a DHCPLEASEQUERY with ciaddr = 192.168.1.50.
    var buf align(4) = [_]u8{0} ** 512;
    const len = makeLeaseQuery(&buf, [4]u8{ 192, 168, 1, 50 }, [6]u8{ 0, 0, 0, 0, 0, 0 });
    const resp = try server.processPacket(buf[0..len]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);

    // Message type must be DHCPLEASEACTIVE (13).
    try std.testing.expectEqual(MessageType.DHCPLEASEACTIVE, DHCPServer.getMessageType(resp.?).?);

    // ciaddr in the response should be the lease IP.
    const resp_hdr: *const DHCPHeader = @ptrCast(@alignCast(resp.?.ptr));
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 50 }, resp_hdr.ciaddr);

    // chaddr should be the lease MAC.
    try std.testing.expectEqual(@as(u8, 0xaa), resp_hdr.chaddr[0]);
    try std.testing.expectEqual(@as(u8, 0xbb), resp_hdr.chaddr[1]);
    try std.testing.expectEqual(@as(u8, 0xcc), resp_hdr.chaddr[2]);
    try std.testing.expectEqual(@as(u8, 0xdd), resp_hdr.chaddr[3]);
    try std.testing.expectEqual(@as(u8, 0xee), resp_hdr.chaddr[4]);
    try std.testing.expectEqual(@as(u8, 0x01), resp_hdr.chaddr[5]);

    // Option 51 (lease time) must be present and > 0.
    const opt51 = DHCPServer.getOption(resp.?, .IPAddressLeaseTime);
    try std.testing.expect(opt51 != null);
    const remaining = std.mem.readInt(u32, opt51.?[0..4], .big);
    try std.testing.expect(remaining > 0);

    // Option 91 (client last transaction time) must be present.
    const opt91 = DHCPServer.getOption(resp.?, .ClientLastTransactionTime);
    try std.testing.expect(opt91 != null);
}

test "DHCPLEASEQUERY by IP returns DHCPLEASEUNKNOWN for IP not in any pool" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // Query for an IP that is outside the configured 192.168.1.0/24 pool.
    var buf align(4) = [_]u8{0} ** 512;
    const len = makeLeaseQuery(&buf, [4]u8{ 10, 99, 99, 99 }, [6]u8{ 0, 0, 0, 0, 0, 0 });
    const resp = try server.processPacket(buf[0..len]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);

    // Message type must be DHCPLEASEUNKNOWN (12).
    try std.testing.expectEqual(MessageType.DHCPLEASEUNKNOWN, DHCPServer.getMessageType(resp.?).?);
}

// ---------------------------------------------------------------------------
// collectOverrides: MAC class first-class field overrides
// ---------------------------------------------------------------------------

test "collectOverrides: MAC class overrides router and dns_servers first-class fields" {
    const allocator = std.testing.allocator;

    var pool = config_mod.PoolConfig{
        .subnet = "192.168.1.0",
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = "192.168.1.1",
        .pool_start = "",
        .pool_end = "",
        .dns_servers = &.{},
        .domain_name = "",
        .domain_search = &.{},
        .lease_time = 3600,
        .time_offset = null,
        .time_servers = &.{},
        .log_servers = &.{},
        .ntp_servers = &.{},
        .mtu = null,
        .wins_servers = &.{},
        .tftp_servers = &.{},
        .boot_filename = "",
        .http_boot_url = "",
        .dns_update = .{ .enable = false, .server = "", .zone = "", .rev_zone = "", .key_name = "", .key_file = "", .lease_time = 3600 },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = &.{},
        .static_routes = &.{},
    };
    defer pool.dhcp_options.deinit();

    // MAC class that overrides router and dns_servers (first-class fields, not dhcp_options).
    var dns_list = [_][]const u8{ "8.8.8.8", "8.8.4.4" };
    var mac_classes = [_]config_mod.MacClass{.{
        .name = "CustomDNS",
        .match = "aa:bb:cc",
        .router = "10.0.0.1",
        .dns_servers = &dns_list,
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
    }};

    var overrides = collectOverrides(allocator, &pool, "aa:bb:cc:dd:ee:ff", null, &mac_classes);
    defer overrides.dhcp_options.deinit();

    // router should come from the MAC class, not the pool.
    try std.testing.expect(overrides.router != null);
    try std.testing.expectEqualStrings("10.0.0.1", overrides.router.?);

    // dns_servers should come from the MAC class.
    try std.testing.expect(overrides.dns_servers != null);
    try std.testing.expectEqual(@as(usize, 2), overrides.dns_servers.?.len);
    try std.testing.expectEqualStrings("8.8.8.8", overrides.dns_servers.?[0]);
    try std.testing.expectEqualStrings("8.8.4.4", overrides.dns_servers.?[1]);
}

// ---------------------------------------------------------------------------
// FORCERENEW nonce (option 145) in ACK
// ---------------------------------------------------------------------------

test "DHCPACK contains option 145 (Forcerenew Nonce) with non-zero nonce" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // Send a REQUEST (no option 54, renewal-style) for an IP in the pool.
    var buf align(4) = [_]u8{0} ** 512;
    const len = makeRequest(
        &buf,
        [6]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 },
        [4]u8{ 192, 168, 1, 50 },
        [4]u8{ 192, 168, 1, 1 }, // our server
        null,
    );
    const resp = try server.processPacket(buf[0..len]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);
    try std.testing.expectEqual(MessageType.DHCPACK, DHCPServer.getMessageType(resp.?).?);

    // Option 145 must be present: code=145, len=17, algorithm=1, 16 nonce bytes.
    const opt145 = DHCPServer.getOption(resp.?, .ForcerenewNonce);
    try std.testing.expect(opt145 != null);
    try std.testing.expectEqual(@as(usize, 17), opt145.?.len);
    // First byte is algorithm (1 = HMAC-MD5).
    try std.testing.expectEqual(@as(u8, 1), opt145.?[0]);

    // Verify the nonce bytes are not all zero (crypto random).
    var all_zero = true;
    for (opt145.?[1..17]) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

// ---------------------------------------------------------------------------
// selectPool: null sync_mgr means all pools are always enabled
// ---------------------------------------------------------------------------

test "selectPool: null sync_mgr returns first matching pool (never null)" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig2Pool(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // With sync_mgr=null, isPoolDisabled always returns false, so selectPool
    // should always find a pool (never null).
    const zero = [4]u8{ 0, 0, 0, 0 };

    // Zero giaddr/ciaddr: falls back to server_ip match → pool[0].
    const pool0 = server.selectPool(zero, zero);
    try std.testing.expect(pool0 != null);
    try std.testing.expectEqualStrings("192.168.1.0", pool0.?.subnet);

    // giaddr in pool[1] subnet → pool[1].
    const pool1 = server.selectPool([4]u8{ 10, 0, 0, 1 }, zero);
    try std.testing.expect(pool1 != null);
    try std.testing.expectEqualStrings("10.0.0.0", pool1.?.subnet);
}

// ---------------------------------------------------------------------------
// buildLeaseQueryResponse: long hostname bounds check
// ---------------------------------------------------------------------------

test "DHCPLEASEQUERY with long hostname does not overflow" {
    const alloc = std.testing.allocator;
    var cfg = try makeTestConfig(alloc);
    defer cfg.deinit();
    const store = try makeTestStore(alloc);
    defer store.deinit();
    const server = try DHCPServer.create(alloc, &cfg, "config.yaml", store, &test_log_level, null);
    defer server.deinit();

    // Seed a lease with a 200-byte hostname.
    var long_name: [200]u8 = undefined;
    @memset(&long_name, 'h');
    try store.addLease(.{
        .mac = "aa:bb:cc:dd:ee:02",
        .ip = "192.168.1.51",
        .hostname = &long_name,
        .expires = std.time.timestamp() + 3600,
        .client_id = null,
    });

    // Query for that IP.
    var buf align(4) = [_]u8{0} ** 512;
    const len = makeLeaseQuery(&buf, [4]u8{ 192, 168, 1, 51 }, [6]u8{ 0, 0, 0, 0, 0, 0 });
    const resp = try server.processPacket(buf[0..len]);
    try std.testing.expect(resp != null);
    defer alloc.free(resp.?);

    // Must be DHCPLEASEACTIVE.
    try std.testing.expectEqual(MessageType.DHCPLEASEACTIVE, DHCPServer.getMessageType(resp.?).?);

    // Option 12 (hostname) should be present with the 200-byte name.
    const opt12 = DHCPServer.getOption(resp.?, .HostName);
    try std.testing.expect(opt12 != null);
    try std.testing.expectEqual(@as(usize, 200), opt12.?.len);

    // Verify all bytes are 'h'.
    for (opt12.?) |b| {
        try std.testing.expectEqual(@as(u8, 'h'), b);
    }
}

// ---------------------------------------------------------------------------
// matchMacClass: edge cases
// ---------------------------------------------------------------------------

test "matchMacClass: empty string matches nothing (treated as wildcard after strip)" {
    // Empty pattern → after stripping wildcards pat.len==0 → returns true.
    // This is the existing behavior: empty pattern acts as a catch-all.
    try std.testing.expect(matchMacClass("aa:bb:cc:dd:ee:ff", ""));
}

test "matchMacClass: mid-octet prefix does not match" {
    // Pattern "aa:b" should NOT match "aa:bb:cc:dd:ee:ff" because after
    // the prefix "aa:b" the next char in the MAC is 'b', not ':' or end.
    try std.testing.expect(!matchMacClass("aa:bb:cc:dd:ee:ff", "aa:b"));
}

test "matchMacClass: pattern longer than MAC returns false" {
    try std.testing.expect(!matchMacClass("aa:bb", "aa:bb:cc:dd:ee:ff"));
}

// ---------------------------------------------------------------------------
// collectOverrides: MAC class static_routes override
// ---------------------------------------------------------------------------

test "collectOverrides: MAC class static_routes override pool default" {
    const allocator = std.testing.allocator;

    var pool = config_mod.PoolConfig{
        .subnet = "192.168.1.0",
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = "192.168.1.1",
        .pool_start = "",
        .pool_end = "",
        .dns_servers = &.{},
        .domain_name = "",
        .domain_search = &.{},
        .lease_time = 3600,
        .time_offset = null,
        .time_servers = &.{},
        .log_servers = &.{},
        .ntp_servers = &.{},
        .mtu = null,
        .wins_servers = &.{},
        .tftp_servers = &.{},
        .boot_filename = "",
        .http_boot_url = "",
        .dns_update = .{ .enable = false, .server = "", .zone = "", .rev_zone = "", .key_name = "", .key_file = "", .lease_time = 3600 },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = &.{},
        .static_routes = &.{}, // pool has NO static routes
    };
    defer pool.dhcp_options.deinit();

    // MAC class defines static routes.
    var mc_routes = [_]config_mod.StaticRoute{
        .{ .destination = [4]u8{ 10, 20, 0, 0 }, .prefix_len = 16, .router = [4]u8{ 192, 168, 1, 254 } },
    };
    var mac_classes = [_]config_mod.MacClass{.{
        .name = "RoutedClass",
        .match = "aa:bb:cc",
        .static_routes = &mc_routes,
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
    }};

    var overrides = collectOverrides(allocator, &pool, "aa:bb:cc:dd:ee:ff", null, &mac_classes);
    defer overrides.dhcp_options.deinit();

    // static_routes should come from the MAC class.
    try std.testing.expect(overrides.static_routes != null);
    try std.testing.expectEqual(@as(usize, 1), overrides.static_routes.?.len);
    try std.testing.expectEqual([4]u8{ 10, 20, 0, 0 }, overrides.static_routes.?[0].destination);
    try std.testing.expectEqual(@as(u8, 16), overrides.static_routes.?[0].prefix_len);
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 254 }, overrides.static_routes.?[0].router);
}
