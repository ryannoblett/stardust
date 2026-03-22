const std = @import("std");
const yaml = @import("yaml");
const dns_mod = @import("./dns.zig");

pub const Error = error{
    ConfigNotFound,
    InvalidConfig,
    IoError,
};

pub const Reservation = struct {
    mac: []const u8,
    ip: []const u8,
    hostname: ?[]const u8,
    client_id: ?[]const u8,
};

pub const Config = struct {
    allocator: std.mem.Allocator,
    listen_address: []const u8,
    subnet: []const u8,
    subnet_mask: u32,
    router: []const u8,
    dns_servers: [][]const u8,
    domain_name: []const u8,
    domain_search: [][]const u8,
    time_offset: ?i32,           // option 2: seconds east of UTC; null = not sent
    time_servers: [][]const u8,  // option 4: RFC 868 time servers
    log_servers: [][]const u8,   // option 7: log servers
    ntp_servers: [][]const u8,   // option 42: NTP servers
    tftp_server_name: []const u8, // option 66: TFTP server hostname or IP
    boot_filename: []const u8,   // option 67: PXE boot filename
    lease_time: u32,
    state_dir: []const u8,
    pool_start: []const u8, // "" = use subnet start
    pool_end: []const u8, // "" = use subnet end
    dns_update: dns_mod.Config,
    dhcp_options: std.StringHashMap([]const u8),
    log_level: std.log.Level,
    reservations: []Reservation,

    /// Free all allocator-owned memory. Must be called when the Config is no
    /// longer needed.
    pub fn deinit(self: *Config) void {
        self.allocator.free(self.listen_address);
        self.allocator.free(self.subnet);
        self.allocator.free(self.router);
        self.allocator.free(self.pool_start);
        self.allocator.free(self.pool_end);
        for (self.dns_servers) |s| self.allocator.free(s);
        self.allocator.free(self.dns_servers);
        self.allocator.free(self.domain_name);
        for (self.domain_search) |s| self.allocator.free(s);
        self.allocator.free(self.domain_search);
        for (self.time_servers) |s| self.allocator.free(s);
        self.allocator.free(self.time_servers);
        for (self.log_servers) |s| self.allocator.free(s);
        self.allocator.free(self.log_servers);
        for (self.ntp_servers) |s| self.allocator.free(s);
        self.allocator.free(self.ntp_servers);
        self.allocator.free(self.tftp_server_name);
        self.allocator.free(self.boot_filename);
        self.allocator.free(self.state_dir);
        self.allocator.free(self.dns_update.server);
        self.allocator.free(self.dns_update.zone);
        self.allocator.free(self.dns_update.key_name);
        self.allocator.free(self.dns_update.key_file);
        var it = self.dhcp_options.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.dhcp_options.deinit();
        for (self.reservations) |r| {
            self.allocator.free(r.mac);
            self.allocator.free(r.ip);
            if (r.hostname) |h| self.allocator.free(h);
            if (r.client_id) |c| self.allocator.free(c);
        }
        self.allocator.free(self.reservations);
    }
};

// Mirror of Config used for yaml.Yaml.parse(). All fields are optional so
// that missing keys in the YAML file fall back to the defaults we apply below.
// Strings are slices into the yaml arena and must be duped before use.
const RawConfig = struct {
    listen_address: ?[]const u8 = null,
    subnet: ?[]const u8 = null,
    subnet_mask: ?[]const u8 = null, // dotted-decimal string in the YAML
    router: ?[]const u8 = null,
    dns_servers: ?[][]const u8 = null,
    domain_name: ?[]const u8 = null,
    domain_search: ?[][]const u8 = null,
    time_offset: ?i32 = null,
    time_servers: ?[][]const u8 = null,
    log_servers: ?[][]const u8 = null,
    ntp_servers: ?[][]const u8 = null,
    tftp_server_name: ?[]const u8 = null,
    boot_filename: ?[]const u8 = null,
    lease_time: ?u32 = null,
    state_dir: ?[]const u8 = null,
    pool_start: ?[]const u8 = null,
    pool_end: ?[]const u8 = null,
    log_level: ?[]const u8 = null,
    dns_update: ?struct {
        enable: ?bool = null,
        server: ?[]const u8 = null,
        zone: ?[]const u8 = null,
        key_name: ?[]const u8 = null,
        key_file: ?[]const u8 = null,
    } = null,
};

pub fn load(allocator: std.mem.Allocator, path: []const u8) !Config {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const file_size = (try file.stat()).size;
    const source = try allocator.alloc(u8, file_size);
    defer allocator.free(source);
    _ = try file.readAll(source);

    // yaml.Yaml owns its own arena internally; we deinit it after we've
    // duped all the strings we need into our own allocator.
    var doc = yaml.Yaml{ .source = source };
    try doc.load(allocator);
    defer doc.deinit(allocator);

    // Use an arena just for the parse call — Yaml.parse allocates into it
    // and we throw it away once we've duped everything into `allocator`.
    var parse_arena = std.heap.ArenaAllocator.init(allocator);
    defer parse_arena.deinit();

    const raw = try doc.parse(parse_arena.allocator(), RawConfig);

    const lease_time_val = raw.lease_time orelse 3600;

    // Build Config with owned copies of every string.
    var cfg = Config{
        .allocator = allocator,
        .listen_address = try allocator.dupe(u8, raw.listen_address orelse "0.0.0.0"),
        .subnet = try allocator.dupe(u8, raw.subnet orelse "192.168.1.0"),
        .subnet_mask = try parseMask(raw.subnet_mask orelse "255.255.255.0"),
        .router = try allocator.dupe(u8, raw.router orelse "192.168.1.1"),
        .dns_servers = try allocator.alloc([]const u8, 0),
        .domain_name = try allocator.dupe(u8, raw.domain_name orelse ""),
        .domain_search = try allocator.alloc([]const u8, 0),
        .time_offset = null,
        .time_servers = try allocator.alloc([]const u8, 0),
        .log_servers = try allocator.alloc([]const u8, 0),
        .ntp_servers = try allocator.alloc([]const u8, 0),
        .tftp_server_name = try allocator.dupe(u8, ""),
        .boot_filename = try allocator.dupe(u8, ""),
        .lease_time = lease_time_val,
        .state_dir = try allocator.dupe(u8, raw.state_dir orelse "/var/lib/stardust"),
        .pool_start = try allocator.dupe(u8, raw.pool_start orelse ""),
        .pool_end = try allocator.dupe(u8, raw.pool_end orelse ""),
        .log_level = parseLogLevel(raw.log_level orelse "info"),
        .dns_update = .{
            .enable = false,
            .server = try allocator.dupe(u8, ""),
            .zone = try allocator.dupe(u8, ""),
            .key_name = try allocator.dupe(u8, ""),
            .key_file = try allocator.dupe(u8, ""),
            .lease_time = lease_time_val,
        },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = try allocator.alloc(Reservation, 0),
    };

    if (raw.dns_servers) |servers| {
        allocator.free(cfg.dns_servers);
        cfg.dns_servers = try allocator.alloc([]const u8, servers.len);
        for (cfg.dns_servers) |*s| s.* = ""; // safe deinit if we error partway
        for (servers, 0..) |s, i| {
            cfg.dns_servers[i] = try allocator.dupe(u8, s);
        }
    }

    if (raw.domain_search) |domains| {
        allocator.free(cfg.domain_search);
        cfg.domain_search = try allocator.alloc([]const u8, domains.len);
        for (cfg.domain_search) |*s| s.* = ""; // safe deinit if we error partway
        for (domains, 0..) |s, i| {
            cfg.domain_search[i] = try allocator.dupe(u8, s);
        }
    }

    if (raw.time_offset) |v| cfg.time_offset = v;

    if (raw.time_servers) |servers| {
        allocator.free(cfg.time_servers);
        cfg.time_servers = try allocator.alloc([]const u8, servers.len);
        for (cfg.time_servers) |*s| s.* = "";
        for (servers, 0..) |s, i| {
            cfg.time_servers[i] = try allocator.dupe(u8, s);
        }
    }

    if (raw.log_servers) |servers| {
        allocator.free(cfg.log_servers);
        cfg.log_servers = try allocator.alloc([]const u8, servers.len);
        for (cfg.log_servers) |*s| s.* = "";
        for (servers, 0..) |s, i| {
            cfg.log_servers[i] = try allocator.dupe(u8, s);
        }
    }

    if (raw.ntp_servers) |servers| {
        allocator.free(cfg.ntp_servers);
        cfg.ntp_servers = try allocator.alloc([]const u8, servers.len);
        for (cfg.ntp_servers) |*s| s.* = "";
        for (servers, 0..) |s, i| {
            cfg.ntp_servers[i] = try allocator.dupe(u8, s);
        }
    }

    if (raw.tftp_server_name) |v| {
        allocator.free(cfg.tftp_server_name);
        cfg.tftp_server_name = try allocator.dupe(u8, v);
    }

    if (raw.boot_filename) |v| {
        allocator.free(cfg.boot_filename);
        cfg.boot_filename = try allocator.dupe(u8, v);
    }

    if (raw.dns_update) |du| {
        if (du.enable) |v| cfg.dns_update.enable = v;
        if (du.server) |v| {
            allocator.free(cfg.dns_update.server);
            cfg.dns_update.server = try allocator.dupe(u8, v);
        }
        if (du.zone) |v| {
            allocator.free(cfg.dns_update.zone);
            cfg.dns_update.zone = try allocator.dupe(u8, v);
        }
        if (du.key_name) |v| {
            allocator.free(cfg.dns_update.key_name);
            cfg.dns_update.key_name = try allocator.dupe(u8, v);
        }
        if (du.key_file) |v| {
            allocator.free(cfg.dns_update.key_file);
            cfg.dns_update.key_file = try allocator.dupe(u8, v);
        }
    }

    // Populate dhcp_options and reservations from the untyped YAML map.
    if (doc.docs.items.len > 0) {
        if (doc.docs.items[0].asMap()) |root_map| {
            if (root_map.get("dhcp_options")) |opts_val| {
                if (opts_val.asMap()) |opts_map| {
                    var it = opts_map.iterator();
                    while (it.next()) |entry| {
                        const key = try allocator.dupe(u8, entry.key_ptr.*);
                        errdefer allocator.free(key);
                        const val_str = entry.value_ptr.asScalar() orelse "";
                        const val = try allocator.dupe(u8, val_str);
                        errdefer allocator.free(val);
                        try cfg.dhcp_options.put(key, val);
                    }
                }
            }

            if (root_map.get("reservations")) |res_val| {
                if (res_val.asList()) |res_list| {
                    try parseReservations(allocator, &cfg, res_list);
                }
            }
        }
    }

    validatePoolRange(&cfg);

    return cfg;
}

/// Parse the reservations list from the untyped YAML walk and append valid entries to cfg.
fn parseReservations(allocator: std.mem.Allocator, cfg: *Config, list: anytype) !void {

    // Count valid entries first to allocate the right amount.
    var valid_count: usize = 0;
    for (list) |item| {
        const m = item.asMap() orelse continue;
        if (m.get("mac") == null or m.get("ip") == null) continue;
        valid_count += 1;
    }

    if (valid_count == 0) return;

    const old_len = cfg.reservations.len;
    const new_slice = try allocator.realloc(cfg.reservations, old_len + valid_count);
    cfg.reservations = new_slice;

    var idx: usize = old_len;
    for (list) |item| {
        const m = item.asMap() orelse {
            std.log.warn("config: reservation entry is not a map, skipping", .{});
            continue;
        };

        const mac_val = m.get("mac") orelse {
            std.log.warn("config: reservation missing 'mac', skipping", .{});
            continue;
        };
        const ip_val = m.get("ip") orelse {
            std.log.warn("config: reservation missing 'ip', skipping", .{});
            continue;
        };

        const mac_str = mac_val.asScalar() orelse {
            std.log.warn("config: reservation 'mac' is not a scalar, skipping", .{});
            continue;
        };
        const ip_str = ip_val.asScalar() orelse {
            std.log.warn("config: reservation 'ip' is not a scalar, skipping", .{});
            continue;
        };

        // Validate that the reservation IP is in the subnet.
        const ip_bytes = parseIpv4(ip_str) catch {
            std.log.warn("config: reservation ip '{s}' is invalid, skipping", .{ip_str});
            continue;
        };
        const ip_int = std.mem.readInt(u32, &ip_bytes, .big);
        const subnet_bytes = parseIpv4(cfg.subnet) catch [4]u8{ 0, 0, 0, 0 };
        const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
        const broadcast_int = subnet_int | ~cfg.subnet_mask;
        if ((ip_int & cfg.subnet_mask) != subnet_int or ip_int == subnet_int or ip_int == broadcast_int) {
            std.log.warn("config: reservation ip '{s}' is outside subnet {s}, skipping", .{ ip_str, cfg.subnet });
            continue;
        }

        const hostname_str: ?[]const u8 = if (m.get("hostname")) |hv| hv.asScalar() else null;
        const client_id_str: ?[]const u8 = if (m.get("client_id")) |cv| cv.asScalar() else null;

        const mac_owned = try allocator.dupe(u8, mac_str);
        errdefer allocator.free(mac_owned);
        const ip_owned = try allocator.dupe(u8, ip_str);
        errdefer allocator.free(ip_owned);
        const hostname_owned: ?[]const u8 = if (hostname_str) |h| try allocator.dupe(u8, h) else null;
        errdefer if (hostname_owned) |h| allocator.free(h);
        const client_id_owned: ?[]const u8 = if (client_id_str) |c| try allocator.dupe(u8, c) else null;
        errdefer if (client_id_owned) |c| allocator.free(c);

        cfg.reservations[idx] = .{
            .mac = mac_owned,
            .ip = ip_owned,
            .hostname = hostname_owned,
            .client_id = client_id_owned,
        };
        idx += 1;
    }

    // Trim to actual count (in case some entries were skipped).
    cfg.reservations = allocator.realloc(cfg.reservations, idx) catch cfg.reservations;
}

/// Log warnings when pool_start/pool_end are misconfigured. Does not fail load().
fn validatePoolRange(cfg: *const Config) void {
    const subnet_bytes = parseIpv4(cfg.subnet) catch return;
    const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
    const broadcast_int = subnet_int | ~cfg.subnet_mask;
    const valid_start = subnet_int + 1;
    const valid_end = broadcast_int - 1;

    var start_int: u32 = valid_start;
    var end_int: u32 = valid_end;
    var has_start = false;
    var has_end = false;

    if (cfg.pool_start.len > 0) {
        const b = parseIpv4(cfg.pool_start) catch {
            std.log.warn("config: pool_start '{s}' is not a valid IP address", .{cfg.pool_start});
            return;
        };
        start_int = std.mem.readInt(u32, &b, .big);
        has_start = true;
        if (start_int < valid_start or start_int > valid_end) {
            std.log.warn("config: pool_start {s} is outside subnet {s}", .{ cfg.pool_start, cfg.subnet });
        }
    }

    if (cfg.pool_end.len > 0) {
        const b = parseIpv4(cfg.pool_end) catch {
            std.log.warn("config: pool_end '{s}' is not a valid IP address", .{cfg.pool_end});
            return;
        };
        end_int = std.mem.readInt(u32, &b, .big);
        has_end = true;
        if (end_int < valid_start or end_int > valid_end) {
            std.log.warn("config: pool_end {s} is outside subnet {s}", .{ cfg.pool_end, cfg.subnet });
        }
    }

    if (has_start and has_end and start_int > end_int) {
        std.log.warn("config: pool_start {s} > pool_end {s}: pool is empty", .{ cfg.pool_start, cfg.pool_end });
    }
}

fn parseLogLevel(s: []const u8) std.log.Level {
    if (std.mem.eql(u8, s, "debug")) return .debug;
    if (std.mem.eql(u8, s, "warn") or std.mem.eql(u8, s, "warning")) return .warn;
    if (std.mem.eql(u8, s, "error") or std.mem.eql(u8, s, "err")) return .err;
    return .info; // default
}

/// Parse a dotted-decimal subnet mask string (e.g. "255.255.255.0") into a
/// host-order u32.
fn parseMask(s: []const u8) !u32 {
    var result: u32 = 0;
    var octet: u32 = 0;
    var dots: u8 = 0;
    for (s) |c| {
        if (c == '.') {
            if (dots >= 3) return error.InvalidConfig;
            result = (result << 8) | octet;
            octet = 0;
            dots += 1;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
            if (octet > 255) return error.InvalidConfig;
        } else {
            return error.InvalidConfig;
        }
    }
    if (dots != 3) return error.InvalidConfig;
    result = (result << 8) | octet;
    // Validate contiguous CIDR prefix: no 0→1 bit transition reading MSB→LSB.
    // Equivalently, ~mask must be of the form 0x00...0FF...F (a power-of-two minus 1 or 0).
    const inverted = ~result;
    if (inverted != 0 and (inverted & (inverted +% 1)) != 0) return error.InvalidConfig;
    return result;
}

/// Parse a dotted-decimal IPv4 address string into a 4-byte array in network
/// byte order. Used by dhcp.zig to convert config strings to wire bytes.
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
    result[idx] = @intCast(octet);
    return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseMask 255.255.255.0" {
    const mask = try parseMask("255.255.255.0");
    try std.testing.expectEqual(@as(u32, 0xFFFFFF00), mask);
}

test "parseMask 255.255.0.0" {
    const mask = try parseMask("255.255.0.0");
    try std.testing.expectEqual(@as(u32, 0xFFFF0000), mask);
}

test "parseIpv4 basic" {
    const ip = try parseIpv4("192.168.1.1");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 1 }, &ip);
}

test "parseIpv4 rejects bad input" {
    try std.testing.expectError(error.InvalidConfig, parseIpv4("192.168.1"));
    try std.testing.expectError(error.InvalidConfig, parseIpv4("256.0.0.1"));
    try std.testing.expectError(error.InvalidConfig, parseIpv4("not.an.ip.addr"));
}

test "parseLogLevel" {
    try std.testing.expectEqual(std.log.Level.debug, parseLogLevel("debug"));
    try std.testing.expectEqual(std.log.Level.warn, parseLogLevel("warn"));
    try std.testing.expectEqual(std.log.Level.warn, parseLogLevel("warning"));
    try std.testing.expectEqual(std.log.Level.err, parseLogLevel("error"));
    try std.testing.expectEqual(std.log.Level.info, parseLogLevel("info"));
    try std.testing.expectEqual(std.log.Level.info, parseLogLevel("unknown"));
}

test "parseMask rejects non-CIDR masks" {
    try std.testing.expectError(error.InvalidConfig, parseMask("255.0.255.0"));
    try std.testing.expectError(error.InvalidConfig, parseMask("255.128.255.0"));
    try std.testing.expectError(error.InvalidConfig, parseMask("255.255.255.1"));
}

test "parseMask accepts valid CIDR edge cases" {
    // /0 — all wildcard
    try std.testing.expectEqual(@as(u32, 0x00000000), try parseMask("0.0.0.0"));
    // /32 — host route
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), try parseMask("255.255.255.255"));
}
