const std = @import("std");

pub const Error = error{
    ConfigNotFound,
    InvalidConfig,
    IoError,
    OutOfMemory,
};

/// DNS dynamic update configuration.
pub const DnsUpdateConfig = struct {
    enable: bool = false,
    server: []const u8 = "",
    zone: []const u8 = "",
    key_name: []const u8 = "",
    key_file: []const u8 = "",
};

/// Top-level server configuration.
/// All slice fields are owned by the allocator passed to `load`.
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
    dns_update: DnsUpdateConfig,
    dhcp_options: std.StringHashMap([]const u8),

    /// Release all memory owned by this Config.
    pub fn deinit(self: *Config) void {
        self.allocator.free(self.listen_address);
        self.allocator.free(self.subnet);
        self.allocator.free(self.router);
        for (self.dns_servers) |s| self.allocator.free(s);
        self.allocator.free(self.dns_servers);
        self.allocator.free(self.domain_name);
        self.allocator.free(self.state_dir);
        if (self.dns_update.server.len > 0) self.allocator.free(self.dns_update.server);
        if (self.dns_update.zone.len > 0) self.allocator.free(self.dns_update.zone);
        if (self.dns_update.key_name.len > 0) self.allocator.free(self.dns_update.key_name);
        if (self.dns_update.key_file.len > 0) self.allocator.free(self.dns_update.key_file);
        var it = self.dhcp_options.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.dhcp_options.deinit();
    }
};

// ---------------------------------------------------------------------------
// Minimal YAML-subset parser
//
// Handles the flat key: value and nested key:\n  subkey: value structure
// present in config.yaml. Sequences are parsed for dns_servers.
// This avoids an external yaml dependency while remaining compatible with
// the existing config.yaml format.
// ---------------------------------------------------------------------------

const ParseState = struct {
    allocator: std.mem.Allocator,
    lines: [][]const u8,
    pos: usize,
    cfg: *Config,
    // Accumulate dns servers before writing to cfg
    dns_list: std.ArrayList([]const u8),
};

/// Load and parse a YAML config file from `path`.
/// Caller must call `cfg.deinit()` when done.
pub fn load(allocator: std.mem.Allocator, path: []const u8) !Config {
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        if (err == error.FileNotFound) return Error.ConfigNotFound;
        return Error.IoError;
    };
    defer file.close();

    const contents = file.readToEndAlloc(allocator, 1024 * 1024) catch return Error.IoError;
    defer allocator.free(contents);

    return parseYaml(allocator, contents);
}

fn parseYaml(allocator: std.mem.Allocator, contents: []const u8) !Config {
    var cfg = Config{
        .allocator = allocator,
        .listen_address = try allocator.dupe(u8, "0.0.0.0"),
        .subnet = try allocator.dupe(u8, "192.168.1.0"),
        .subnet_mask = 0xFFFFFF00, // 255.255.255.0
        .router = try allocator.dupe(u8, "192.168.1.1"),
        .dns_servers = &.{},
        .domain_name = try allocator.dupe(u8, ""),
        .lease_time = 3600,
        .state_dir = try allocator.dupe(u8, "/var/lib/stardust"),
        .dns_update = .{},
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
    };
    errdefer cfg.deinit();

    var dns_list = std.ArrayList([]const u8).init(allocator);
    defer dns_list.deinit();

    var lines = std.mem.splitScalar(u8, contents, '\n');
    var in_dns_update = false;
    var in_dns_servers = false;
    var in_dhcp_options = false;

    while (lines.next()) |raw_line| {
        const line = std.mem.trimRight(u8, raw_line, " \r\t");

        // Skip comments and blank lines
        if (line.len == 0 or line[0] == '#') {
            in_dns_servers = false;
            continue;
        }

        // Detect indented blocks
        const trimmed = std.mem.trimLeft(u8, line, " \t");
        const indent = line.len - trimmed.len;

        if (indent == 0) {
            // Top-level key
            in_dns_update = false;
            in_dns_servers = false;
            in_dhcp_options = false;

            if (std.mem.startsWith(u8, trimmed, "dns_update:")) {
                in_dns_update = true;
                continue;
            }
            if (std.mem.startsWith(u8, trimmed, "dns_servers:")) {
                in_dns_servers = true;
                continue;
            }
            if (std.mem.startsWith(u8, trimmed, "dhcp_options:")) {
                in_dhcp_options = true;
                continue;
            }

            if (parseKv(trimmed)) |kv| {
                try applyTopLevel(allocator, &cfg, kv.key, kv.value);
            }
        } else {
            // Indented content
            if (in_dns_servers) {
                // Sequence item: "  - \"8.8.8.8\""
                if (std.mem.startsWith(u8, trimmed, "- ")) {
                    const val = std.mem.trim(u8, trimmed[2..], " \"'");
                    try dns_list.append(try allocator.dupe(u8, val));
                }
            } else if (in_dns_update) {
                if (parseKv(trimmed)) |kv| {
                    try applyDnsUpdate(allocator, &cfg.dns_update, kv.key, kv.value);
                }
            } else if (in_dhcp_options) {
                if (parseKv(trimmed)) |kv| {
                    const k = try allocator.dupe(u8, kv.key);
                    const v = try allocator.dupe(u8, kv.value);
                    try cfg.dhcp_options.put(k, v);
                }
            }
        }
    }

    // Transfer dns_list ownership to cfg
    cfg.dns_servers = try dns_list.toOwnedSlice();

    return cfg;
}

const KV = struct { key: []const u8, value: []const u8 };

fn parseKv(line: []const u8) ?KV {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return null;
    const key = std.mem.trim(u8, line[0..colon], " \t");
    const raw_val = std.mem.trim(u8, line[colon + 1 ..], " \t\"'");
    // Skip lines that are just "key:" with no value (block headers)
    if (raw_val.len == 0) return null;
    return .{ .key = key, .value = raw_val };
}

fn applyTopLevel(allocator: std.mem.Allocator, cfg: *Config, key: []const u8, value: []const u8) !void {
    if (std.mem.eql(u8, key, "listen_address")) {
        allocator.free(cfg.listen_address);
        cfg.listen_address = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "subnet")) {
        allocator.free(cfg.subnet);
        cfg.subnet = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "subnet_mask")) {
        cfg.subnet_mask = try parseMask(value);
    } else if (std.mem.eql(u8, key, "router")) {
        allocator.free(cfg.router);
        cfg.router = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "domain_name")) {
        allocator.free(cfg.domain_name);
        cfg.domain_name = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "lease_time")) {
        cfg.lease_time = std.fmt.parseInt(u32, value, 10) catch return Error.InvalidConfig;
    } else if (std.mem.eql(u8, key, "state_dir")) {
        allocator.free(cfg.state_dir);
        cfg.state_dir = try allocator.dupe(u8, value);
    }
}

fn applyDnsUpdate(allocator: std.mem.Allocator, dns: *DnsUpdateConfig, key: []const u8, value: []const u8) !void {
    if (std.mem.eql(u8, key, "enable")) {
        dns.enable = std.mem.eql(u8, value, "true");
    } else if (std.mem.eql(u8, key, "server")) {
        if (dns.server.len > 0) allocator.free(dns.server);
        dns.server = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "zone")) {
        if (dns.zone.len > 0) allocator.free(dns.zone);
        dns.zone = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "key_name")) {
        if (dns.key_name.len > 0) allocator.free(dns.key_name);
        dns.key_name = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "key_file")) {
        if (dns.key_file.len > 0) allocator.free(dns.key_file);
        dns.key_file = try allocator.dupe(u8, value);
    }
}

/// Parse a dotted-decimal subnet mask ("255.255.255.0") into a u32 (host byte order).
fn parseMask(s: []const u8) !u32 {
    var result: u32 = 0;
    var parts = std.mem.splitScalar(u8, s, '.');
    var shift: u5 = 24;
    var count: usize = 0;
    while (parts.next()) |part| : (count += 1) {
        if (count >= 4) return Error.InvalidConfig;
        const byte = std.fmt.parseInt(u8, part, 10) catch return Error.InvalidConfig;
        result |= @as(u32, byte) << shift;
        if (shift >= 8) shift -= 8;
    }
    if (count != 4) return Error.InvalidConfig;
    return result;
}

/// Parse a dotted-decimal IPv4 address into 4 bytes (network byte order).
pub fn parseIpv4(s: []const u8) ![4]u8 {
    var result: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (parts.next()) |part| : (i += 1) {
        if (i >= 4) return Error.InvalidConfig;
        result[i] = std.fmt.parseInt(u8, std.mem.trim(u8, part, " "), 10) catch return Error.InvalidConfig;
    }
    if (i != 4) return Error.InvalidConfig;
    return result;
}

test "parseIpv4" {
    const addr = try parseIpv4("192.168.1.1");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 1 }, &addr);
}

test "parseMask" {
    const mask = try parseMask("255.255.255.0");
    try std.testing.expectEqual(@as(u32, 0xFFFFFF00), mask);
}

test "load config" {
    // Write a temp config file and parse it
    const allocator = std.testing.allocator;
    const tmp_path = "/tmp/stardust_test_config.yaml";
    const yaml =
        \\listen_address: "0.0.0.0"
        \\subnet: "192.168.1.0"
        \\router: "192.168.1.1"
        \\subnet_mask: 255.255.255.0
        \\lease_time: 7200
        \\state_dir: "/tmp/stardust"
        \\domain_name: "test.local"
        \\dns_servers:
        \\  - "8.8.8.8"
        \\  - "8.8.4.4"
        \\dns_update:
        \\  enable: false
        \\  server: "127.0.0.1"
        \\  zone: "test.local"
        \\  key_name: "dhcp-update"
        \\  key_file: "/etc/bind/key.key"
        \\dhcp_options:
    ;
    {
        const f = try std.fs.cwd().createFile(tmp_path, .{});
        defer f.close();
        try f.writeAll(yaml);
    }
    defer std.fs.cwd().deleteFile(tmp_path) catch {};

    var cfg = try load(allocator, tmp_path);
    defer cfg.deinit();

    try std.testing.expectEqualStrings("0.0.0.0", cfg.listen_address);
    try std.testing.expectEqualStrings("192.168.1.1", cfg.router);
    try std.testing.expectEqual(@as(u32, 7200), cfg.lease_time);
    try std.testing.expectEqual(@as(usize, 2), cfg.dns_servers.len);
    try std.testing.expectEqualStrings("8.8.8.8", cfg.dns_servers[0]);
}
