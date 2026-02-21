const std = @import("std");
const yaml = @import("yaml");

pub const Error = error{
    ConfigNotFound,
    InvalidConfig,
    IoError,
};

pub const Config = struct {
    allocator: std.mem.Allocator,
    listen_address: []const u8,
    subnet: []const u8,
    subnet_mask: u32,
    router: []const u8,
    dns_servers: [][]const u8,
    domain_name: []const u8,
    lease_time: u32,
    state_dir: []const u8,
    dns_update: struct {
        enable: bool,
        server: []const u8,
        zone: []const u8,
        key_name: []const u8,
        key_file: []const u8,
    },
    dhcp_options: std.StringHashMap([]const u8),

    /// Free all allocator-owned memory. Must be called when the Config is no
    /// longer needed.
    pub fn deinit(self: *Config) void {
        self.allocator.free(self.listen_address);
        self.allocator.free(self.subnet);
        self.allocator.free(self.router);
        for (self.dns_servers) |s| self.allocator.free(s);
        self.allocator.free(self.dns_servers);
        self.allocator.free(self.domain_name);
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
    lease_time: ?u32 = null,
    state_dir: ?[]const u8 = null,
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

    // Build Config with owned copies of every string.
    var cfg = Config{
        .allocator = allocator,
        .listen_address = try allocator.dupe(u8, raw.listen_address orelse "0.0.0.0"),
        .subnet = try allocator.dupe(u8, raw.subnet orelse "192.168.1.0"),
        .subnet_mask = try parseMask(raw.subnet_mask orelse "255.255.255.0"),
        .router = try allocator.dupe(u8, raw.router orelse "192.168.1.1"),
        .dns_servers = try allocator.alloc([]const u8, 0),
        .domain_name = try allocator.dupe(u8, raw.domain_name orelse ""),
        .lease_time = raw.lease_time orelse 3600,
        .state_dir = try allocator.dupe(u8, raw.state_dir orelse "/var/lib/stardust"),
        .dns_update = .{
            .enable = false,
            .server = try allocator.dupe(u8, ""),
            .zone = try allocator.dupe(u8, ""),
            .key_name = try allocator.dupe(u8, ""),
            .key_file = try allocator.dupe(u8, ""),
        },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
    };

    if (raw.dns_servers) |servers| {
        allocator.free(cfg.dns_servers);
        cfg.dns_servers = try allocator.alloc([]const u8, servers.len);
        for (cfg.dns_servers) |*s| s.* = ""; // safe deinit if we error partway
        for (servers, 0..) |s, i| {
            cfg.dns_servers[i] = try allocator.dupe(u8, s);
        }
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

    return cfg;
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
