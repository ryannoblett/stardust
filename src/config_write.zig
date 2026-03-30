/// YAML serializer for the Stardust Config struct.
///
/// Produces clean YAML that can be round-tripped through config.load().
/// Note: comments and manual formatting from the original file are NOT preserved.
/// This is the expected trade-off when using the TUI to edit configuration.
const std = @import("std");
const config_mod = @import("./config.zig");

pub const Error = error{
    IoError,
    OutOfMemory,
};

/// Write the Config to `path` atomically (temp file + rename).
/// The file is overwritten completely; original comments are lost.
pub fn writeConfig(allocator: std.mem.Allocator, cfg: *const config_mod.Config, path: []const u8) !void {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    const w = buf.writer(allocator);

    try renderConfig(w, cfg);

    // Atomic write: write to a temp file, then rename
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{path});
    defer allocator.free(tmp_path);

    const file = std.fs.cwd().createFile(tmp_path, .{ .truncate = true }) catch return Error.IoError;
    errdefer std.fs.cwd().deleteFile(tmp_path) catch {};
    file.writeAll(buf.items) catch {
        file.close();
        return Error.IoError;
    };
    file.close();

    std.fs.rename(std.fs.cwd(), tmp_path, std.fs.cwd(), path) catch return Error.IoError;
}

/// Render the full Config as YAML into the given writer.
pub fn renderConfig(w: anytype, cfg: *const config_mod.Config) !void {
    try w.print("listen_address: {s}\n", .{cfg.listen_address});
    try w.print("state_dir: {s}\n", .{cfg.state_dir});
    try w.print("log_level: {s}\n", .{@tagName(cfg.log_level)});
    try w.print("pool_allocation_random: {s}\n\n", .{if (cfg.pool_allocation_random) "true" else "false"});

    // admin_ssh section
    try w.writeAll("admin_ssh:\n");
    try w.print("  enable: {s}\n", .{if (cfg.admin_ssh.enable) "true" else "false"});
    try w.print("  port: {d}\n", .{cfg.admin_ssh.port});
    try w.print("  bind: {s}\n", .{cfg.admin_ssh.bind});
    try w.print("  read_only: {s}\n", .{if (cfg.admin_ssh.read_only) "true" else "false"});
    try w.print("  host_key: {s}\n", .{cfg.admin_ssh.host_key});
    try w.print("  authorized_keys: {s}\n\n", .{cfg.admin_ssh.authorized_keys});

    // metrics section
    try w.writeAll("metrics:\n");
    try w.print("  collect: {s}\n", .{if (cfg.metrics.collect) "true" else "false"});
    try w.print("  http_enable: {s}\n", .{if (cfg.metrics.http_enable) "true" else "false"});
    try w.print("  http_port: {d}\n", .{cfg.metrics.http_port});
    try w.print("  http_bind: {s}\n\n", .{cfg.metrics.http_bind});

    // sync section (only if configured)
    if (cfg.sync) |s| {
        try w.writeAll("sync:\n");
        try w.print("  enable: {s}\n", .{if (s.enable) "true" else "false"});
        try w.print("  group_name: {s}\n", .{s.group_name});
        try w.print("  key_file: {s}\n", .{s.key_file});
        try w.print("  port: {d}\n", .{s.port});
        try w.print("  full_sync_interval: {d}\n", .{s.full_sync_interval});
        if (s.multicast) |mc| {
            try w.print("  multicast: {s}\n", .{mc});
        }
        if (s.peers.len > 0) {
            try w.writeAll("  peers:\n");
            for (s.peers) |p| {
                try w.print("    - {s}\n", .{p});
            }
        }
        try w.writeAll("\n");
    }

    // pools section
    try w.writeAll("pools:\n");
    for (cfg.pools) |pool| {
        try renderPool(w, &pool);
    }
}

fn renderPool(w: anytype, pool: *const config_mod.PoolConfig) !void {
    // subnet in CIDR notation
    try w.print("  - subnet: {s}/{d}\n", .{ pool.subnet, pool.prefix_len });
    try w.print("    router: {s}\n", .{pool.router});
    if (pool.pool_start.len > 0) {
        try w.print("    pool_start: {s}\n", .{pool.pool_start});
    }
    if (pool.pool_end.len > 0) {
        try w.print("    pool_end: {s}\n", .{pool.pool_end});
    }
    try w.print("    lease_time: {d}\n", .{pool.lease_time});

    if (pool.dns_servers.len > 0) {
        try w.writeAll("    dns_servers:\n");
        for (pool.dns_servers) |s| {
            try w.print("      - {s}\n", .{s});
        }
    }
    if (pool.domain_name.len > 0) {
        try w.print("    domain_name: {s}\n", .{pool.domain_name});
    }
    if (pool.domain_search.len > 0) {
        try w.writeAll("    domain_search:\n");
        for (pool.domain_search) |s| {
            try w.print("      - {s}\n", .{s});
        }
    }
    if (pool.time_offset) |off| {
        try w.print("    time_offset: {d}\n", .{off});
    }
    if (pool.time_servers.len > 0) {
        try w.writeAll("    time_servers:\n");
        for (pool.time_servers) |s| {
            try w.print("      - {s}\n", .{s});
        }
    }
    if (pool.log_servers.len > 0) {
        try w.writeAll("    log_servers:\n");
        for (pool.log_servers) |s| {
            try w.print("      - {s}\n", .{s});
        }
    }
    if (pool.ntp_servers.len > 0) {
        try w.writeAll("    ntp_servers:\n");
        for (pool.ntp_servers) |s| {
            try w.print("      - {s}\n", .{s});
        }
    }
    if (pool.tftp_server_name.len > 0) {
        try w.print("    tftp_server_name: {s}\n", .{pool.tftp_server_name});
    }
    if (pool.boot_filename.len > 0) {
        try w.print("    boot_filename: {s}\n", .{pool.boot_filename});
    }
    if (pool.http_boot_url.len > 0) {
        try w.print("    http_boot_url: {s}\n", .{pool.http_boot_url});
    }

    if (pool.dns_update.enable) {
        try w.writeAll("    dns_update:\n");
        try w.print("      enable: true\n", .{});
        if (pool.dns_update.server.len > 0) {
            try w.print("      server: {s}\n", .{pool.dns_update.server});
        }
        if (pool.dns_update.zone.len > 0) {
            try w.print("      zone: {s}\n", .{pool.dns_update.zone});
        }
        if (pool.dns_update.key_name.len > 0) {
            try w.print("      key_name: {s}\n", .{pool.dns_update.key_name});
        }
        if (pool.dns_update.key_file.len > 0) {
            try w.print("      key_file: {s}\n", .{pool.dns_update.key_file});
        }
    }

    // dhcp_options (custom options map)
    if (pool.dhcp_options.count() > 0) {
        try w.writeAll("    dhcp_options:\n");
        var it = pool.dhcp_options.iterator();
        while (it.next()) |entry| {
            try w.print("      {s}: {s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }
    }

    // static_routes
    if (pool.static_routes.len > 0) {
        try w.writeAll("    static_routes:\n");
        for (pool.static_routes) |sr| {
            try w.print("      - destination: {d}.{d}.{d}.{d}/{d}\n", .{
                sr.destination[0], sr.destination[1], sr.destination[2], sr.destination[3], sr.prefix_len,
            });
            try w.print("        router: {d}.{d}.{d}.{d}\n", .{
                sr.router[0], sr.router[1], sr.router[2], sr.router[3],
            });
        }
    }

    // reservations
    if (pool.reservations.len > 0) {
        try w.writeAll("    reservations:\n");
        for (pool.reservations) |r| {
            try w.print("      - mac: {s}\n", .{r.mac});
            try w.print("        ip: {s}\n", .{r.ip});
            if (r.hostname) |h| {
                try w.print("        hostname: {s}\n", .{h});
            }
            if (r.client_id) |c| {
                try w.print("        client_id: {s}\n", .{c});
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers for in-memory reservation mutations (used by SSH TUI + sync)
// ---------------------------------------------------------------------------

/// Add or update a reservation in the given pool's reservations slice.
/// The pool must be the one matching the reservation's subnet.
/// Returns true if a new entry was added, false if an existing one was updated.
/// Caller must free the old Config after calling config_mod.load() with the new file.
pub fn upsertReservation(
    allocator: std.mem.Allocator,
    pool: *config_mod.PoolConfig,
    mac: []const u8,
    ip: []const u8,
    hostname: ?[]const u8,
    client_id: ?[]const u8,
) !bool {
    // Check if MAC already exists in reservations
    for (pool.reservations) |*r| {
        if (std.mem.eql(u8, r.mac, mac)) {
            // Update in place: free old strings, replace
            allocator.free(r.ip);
            r.ip = try allocator.dupe(u8, ip);
            if (r.hostname) |h| allocator.free(h);
            r.hostname = if (hostname) |h| try allocator.dupe(u8, h) else null;
            if (r.client_id) |c| allocator.free(c);
            r.client_id = if (client_id) |c| try allocator.dupe(u8, c) else null;
            return false;
        }
    }

    // Append new entry
    const new_res = config_mod.Reservation{
        .mac = try allocator.dupe(u8, mac),
        .ip = try allocator.dupe(u8, ip),
        .hostname = if (hostname) |h| try allocator.dupe(u8, h) else null,
        .client_id = if (client_id) |c| try allocator.dupe(u8, c) else null,
    };
    const new_slice = try allocator.realloc(pool.reservations, pool.reservations.len + 1);
    pool.reservations = new_slice;
    pool.reservations[pool.reservations.len - 1] = new_res;
    return true;
}

/// Remove a reservation from a pool by MAC address.
/// Returns true if found and removed, false if not found.
pub fn removeReservation(
    allocator: std.mem.Allocator,
    pool: *config_mod.PoolConfig,
    mac: []const u8,
) bool {
    for (pool.reservations, 0..) |r, i| {
        if (std.mem.eql(u8, r.mac, mac)) {
            allocator.free(r.mac);
            allocator.free(r.ip);
            if (r.hostname) |h| allocator.free(h);
            if (r.client_id) |c| allocator.free(c);
            // Shift remaining elements down
            for (i + 1..pool.reservations.len) |j| {
                pool.reservations[j - 1] = pool.reservations[j];
            }
            pool.reservations = allocator.realloc(pool.reservations, pool.reservations.len - 1) catch pool.reservations[0 .. pool.reservations.len - 1];
            return true;
        }
    }
    return false;
}

/// Find the pool containing the given IP address. Returns null if none match.
pub fn findPoolForIp(cfg: *const config_mod.Config, ip_str: []const u8) ?*config_mod.PoolConfig {
    const ip_bytes = parseIpv4Local(ip_str) catch return null;
    const ip_int = std.mem.readInt(u32, &ip_bytes, .big);
    for (cfg.pools) |*pool| {
        const subnet_bytes = parseIpv4Local(pool.subnet) catch continue;
        const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
        if ((ip_int & pool.subnet_mask) == subnet_int) return pool;
    }
    return null;
}

fn parseIpv4Local(s: []const u8) ![4]u8 {
    var result: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i >= 4) return error.InvalidAddress;
        result[i] = std.fmt.parseInt(u8, part, 10) catch return error.InvalidAddress;
    }
    if (i != 4) return error.InvalidAddress;
    return result;
}

// ---------------------------------------------------------------------------
// Pool-level mutations (used by SSH TUI pool config tab)
// ---------------------------------------------------------------------------

/// Append a new pool to the Config's pools slice.
/// The caller must have allocated all strings in `pool` with `allocator`.
pub fn addPool(allocator: std.mem.Allocator, cfg: *config_mod.Config, pool: config_mod.PoolConfig) !void {
    const new_len = cfg.pools.len + 1;
    const new_pools = try allocator.realloc(cfg.pools, new_len);
    cfg.pools = new_pools;
    cfg.pools[new_len - 1] = pool;
}

/// Remove a pool by index. Calls deinit on the pool and shrinks the slice.
pub fn removePool(allocator: std.mem.Allocator, cfg: *config_mod.Config, index: usize) void {
    if (index >= cfg.pools.len) return;
    cfg.pools[index].deinit(allocator);
    // Shift remaining elements down.
    for (index + 1..cfg.pools.len) |j| {
        cfg.pools[j - 1] = cfg.pools[j];
    }
    cfg.pools = allocator.realloc(cfg.pools, cfg.pools.len - 1) catch cfg.pools[0 .. cfg.pools.len - 1];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "renderConfig round-trips global fields" {
    const allocator = std.testing.allocator;

    var dns_servers = [_][]const u8{"8.8.8.8"};
    var reservations = [_]config_mod.Reservation{};
    var static_routes = [_]config_mod.StaticRoute{};

    var dhcp_options = std.StringHashMap([]const u8).init(allocator);
    defer dhcp_options.deinit();

    var pools = [_]config_mod.PoolConfig{
        config_mod.PoolConfig{
            .subnet = "192.168.1.0",
            .subnet_mask = 0xFFFFFF00,
            .prefix_len = 24,
            .router = "192.168.1.1",
            .pool_start = "192.168.1.100",
            .pool_end = "192.168.1.200",
            .dns_servers = &dns_servers,
            .domain_name = "home.local",
            .domain_search = &.{},
            .lease_time = 3600,
            .time_offset = null,
            .time_servers = &.{},
            .log_servers = &.{},
            .ntp_servers = &.{},
            .tftp_server_name = "",
            .boot_filename = "",
            .http_boot_url = "",
            .dns_update = .{
                .enable = false,
                .server = "",
                .zone = "",
                .rev_zone = "",
                .key_name = "",
                .key_file = "",
                .lease_time = 3600,
            },
            .dhcp_options = dhcp_options,
            .reservations = &reservations,
            .static_routes = &static_routes,
        },
    };

    const cfg = config_mod.Config{
        .allocator = allocator,
        .listen_address = "0.0.0.0",
        .state_dir = "/var/lib/stardust",
        .log_level = .info,
        .pool_allocation_random = false,
        .sync = null,
        .pools = &pools,
        .admin_ssh = .{
            .enable = false,
            .port = 2267,
            .bind = "0.0.0.0",
            .read_only = false,
            .host_key = "/etc/stardust/ssh_host_key",
            .authorized_keys = "/etc/stardust/authorized_keys",
        },
        .metrics = .{
            .collect = true,
            .http_enable = false,
            .http_port = 9167,
            .http_bind = "127.0.0.1",
        },
    };

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    try renderConfig(buf.writer(allocator), &cfg);

    const out = buf.items;
    try std.testing.expect(std.mem.indexOf(u8, out, "listen_address: 0.0.0.0") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "state_dir: /var/lib/stardust") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "log_level: info") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "subnet: 192.168.1.0/24") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "router: 192.168.1.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "domain_name: home.local") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "http_port: 9167") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "port: 2267") != null);
}

test "upsertReservation adds new entry" {
    const allocator = std.testing.allocator;

    var reservations = try allocator.alloc(config_mod.Reservation, 0);
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
        .tftp_server_name = "",
        .boot_filename = "",
        .dns_update = .{ .enable = false, .server = "", .zone = "", .rev_zone = "", .key_name = "", .key_file = "", .lease_time = 3600 },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = reservations,
        .static_routes = &.{},
    };
    defer {
        for (pool.reservations) |r| {
            allocator.free(r.mac);
            allocator.free(r.ip);
            if (r.hostname) |h| allocator.free(h);
            if (r.client_id) |c| allocator.free(c);
        }
        allocator.free(pool.reservations);
        pool.dhcp_options.deinit();
    }
    reservations = pool.reservations;

    const added = try upsertReservation(allocator, &pool, "aa:bb:cc:dd:ee:ff", "192.168.1.50", "myhost", null);
    try std.testing.expect(added == true);
    try std.testing.expectEqual(@as(usize, 1), pool.reservations.len);
    try std.testing.expectEqualStrings("aa:bb:cc:dd:ee:ff", pool.reservations[0].mac);
    try std.testing.expectEqualStrings("192.168.1.50", pool.reservations[0].ip);
    try std.testing.expectEqualStrings("myhost", pool.reservations[0].hostname.?);
}

test "upsertReservation updates existing entry" {
    const allocator = std.testing.allocator;

    var initial = [_]config_mod.Reservation{.{
        .mac = try allocator.dupe(u8, "aa:bb:cc:dd:ee:ff"),
        .ip = try allocator.dupe(u8, "192.168.1.50"),
        .hostname = null,
        .client_id = null,
    }};
    const res_slice = try allocator.dupe(config_mod.Reservation, &initial);
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
        .tftp_server_name = "",
        .boot_filename = "",
        .dns_update = .{ .enable = false, .server = "", .zone = "", .rev_zone = "", .key_name = "", .key_file = "", .lease_time = 3600 },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = res_slice,
        .static_routes = &.{},
    };
    defer {
        for (pool.reservations) |r| {
            allocator.free(r.mac);
            allocator.free(r.ip);
            if (r.hostname) |h| allocator.free(h);
            if (r.client_id) |c| allocator.free(c);
        }
        allocator.free(pool.reservations);
        pool.dhcp_options.deinit();
    }

    const added = try upsertReservation(allocator, &pool, "aa:bb:cc:dd:ee:ff", "192.168.1.55", "newhost", null);
    try std.testing.expect(added == false); // updated, not added
    try std.testing.expectEqual(@as(usize, 1), pool.reservations.len);
    try std.testing.expectEqualStrings("192.168.1.55", pool.reservations[0].ip);
    try std.testing.expectEqualStrings("newhost", pool.reservations[0].hostname.?);
}

test "removeReservation removes by MAC" {
    const allocator = std.testing.allocator;

    var initial = [_]config_mod.Reservation{.{
        .mac = try allocator.dupe(u8, "aa:bb:cc:dd:ee:ff"),
        .ip = try allocator.dupe(u8, "192.168.1.50"),
        .hostname = null,
        .client_id = null,
    }};
    const res_slice = try allocator.dupe(config_mod.Reservation, &initial);
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
        .tftp_server_name = "",
        .boot_filename = "",
        .dns_update = .{ .enable = false, .server = "", .zone = "", .rev_zone = "", .key_name = "", .key_file = "", .lease_time = 3600 },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = res_slice,
        .static_routes = &.{},
    };
    defer {
        for (pool.reservations) |r| {
            allocator.free(r.mac);
            allocator.free(r.ip);
            if (r.hostname) |h| allocator.free(h);
            if (r.client_id) |c| allocator.free(c);
        }
        allocator.free(pool.reservations);
        pool.dhcp_options.deinit();
    }

    const removed = removeReservation(allocator, &pool, "aa:bb:cc:dd:ee:ff");
    try std.testing.expect(removed == true);
    try std.testing.expectEqual(@as(usize, 0), pool.reservations.len);
}

test "addPool appends to pools slice" {
    const allocator = std.testing.allocator;

    const pools = try allocator.alloc(config_mod.PoolConfig, 0);
    var cfg = config_mod.Config{
        .allocator = allocator,
        .listen_address = try allocator.dupe(u8, "0.0.0.0"),
        .state_dir = try allocator.dupe(u8, "/tmp"),
        .log_level = .info,
        .pool_allocation_random = false,
        .sync = null,
        .pools = pools,
        .admin_ssh = .{
            .enable = false,
            .port = 2267,
            .bind = try allocator.dupe(u8, "0.0.0.0"),
            .read_only = false,
            .host_key = try allocator.dupe(u8, ""),
            .authorized_keys = try allocator.dupe(u8, ""),
        },
        .metrics = .{
            .collect = false,
            .http_enable = false,
            .http_port = 9167,
            .http_bind = try allocator.dupe(u8, "127.0.0.1"),
        },
    };
    defer cfg.deinit();

    const new_pool = config_mod.PoolConfig{
        .subnet = try allocator.dupe(u8, "10.0.0.0"),
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = try allocator.dupe(u8, "10.0.0.1"),
        .pool_start = try allocator.dupe(u8, "10.0.0.100"),
        .pool_end = try allocator.dupe(u8, "10.0.0.200"),
        .dns_servers = try allocator.alloc([]const u8, 0),
        .domain_name = try allocator.dupe(u8, ""),
        .domain_search = try allocator.alloc([]const u8, 0),
        .lease_time = 7200,
        .time_offset = null,
        .time_servers = try allocator.alloc([]const u8, 0),
        .log_servers = try allocator.alloc([]const u8, 0),
        .ntp_servers = try allocator.alloc([]const u8, 0),
        .tftp_server_name = try allocator.dupe(u8, ""),
        .boot_filename = try allocator.dupe(u8, ""),
        .http_boot_url = try allocator.dupe(u8, ""),
        .dns_update = .{ .enable = false, .server = try allocator.dupe(u8, ""), .zone = try allocator.dupe(u8, ""), .rev_zone = try allocator.dupe(u8, ""), .key_name = try allocator.dupe(u8, ""), .key_file = try allocator.dupe(u8, ""), .lease_time = 7200 },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = try allocator.alloc(config_mod.Reservation, 0),
        .static_routes = try allocator.alloc(config_mod.StaticRoute, 0),
    };

    try addPool(allocator, &cfg, new_pool);
    try std.testing.expectEqual(@as(usize, 1), cfg.pools.len);
    try std.testing.expectEqualStrings("10.0.0.0", cfg.pools[0].subnet);
    try std.testing.expectEqual(@as(u32, 7200), cfg.pools[0].lease_time);
}

test "removePool removes by index and frees resources" {
    const allocator = std.testing.allocator;

    const pool0 = config_mod.PoolConfig{
        .subnet = try allocator.dupe(u8, "10.0.0.0"),
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = try allocator.dupe(u8, "10.0.0.1"),
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
        .tftp_server_name = try allocator.dupe(u8, ""),
        .boot_filename = try allocator.dupe(u8, ""),
        .http_boot_url = try allocator.dupe(u8, ""),
        .dns_update = .{ .enable = false, .server = try allocator.dupe(u8, ""), .zone = try allocator.dupe(u8, ""), .rev_zone = try allocator.dupe(u8, ""), .key_name = try allocator.dupe(u8, ""), .key_file = try allocator.dupe(u8, ""), .lease_time = 3600 },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = try allocator.alloc(config_mod.Reservation, 0),
        .static_routes = try allocator.alloc(config_mod.StaticRoute, 0),
    };

    const pool1 = config_mod.PoolConfig{
        .subnet = try allocator.dupe(u8, "172.16.0.0"),
        .subnet_mask = 0xFFFF0000,
        .prefix_len = 16,
        .router = try allocator.dupe(u8, "172.16.0.1"),
        .pool_start = try allocator.dupe(u8, ""),
        .pool_end = try allocator.dupe(u8, ""),
        .dns_servers = try allocator.alloc([]const u8, 0),
        .domain_name = try allocator.dupe(u8, ""),
        .domain_search = try allocator.alloc([]const u8, 0),
        .lease_time = 1800,
        .time_offset = null,
        .time_servers = try allocator.alloc([]const u8, 0),
        .log_servers = try allocator.alloc([]const u8, 0),
        .ntp_servers = try allocator.alloc([]const u8, 0),
        .tftp_server_name = try allocator.dupe(u8, ""),
        .boot_filename = try allocator.dupe(u8, ""),
        .http_boot_url = try allocator.dupe(u8, ""),
        .dns_update = .{ .enable = false, .server = try allocator.dupe(u8, ""), .zone = try allocator.dupe(u8, ""), .rev_zone = try allocator.dupe(u8, ""), .key_name = try allocator.dupe(u8, ""), .key_file = try allocator.dupe(u8, ""), .lease_time = 1800 },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = try allocator.alloc(config_mod.Reservation, 0),
        .static_routes = try allocator.alloc(config_mod.StaticRoute, 0),
    };

    var pools_arr = [_]config_mod.PoolConfig{ pool0, pool1 };
    const pools = try allocator.dupe(config_mod.PoolConfig, &pools_arr);

    var cfg = config_mod.Config{
        .allocator = allocator,
        .listen_address = try allocator.dupe(u8, "0.0.0.0"),
        .state_dir = try allocator.dupe(u8, "/tmp"),
        .log_level = .info,
        .pool_allocation_random = false,
        .sync = null,
        .pools = pools,
        .admin_ssh = .{
            .enable = false,
            .port = 2267,
            .bind = try allocator.dupe(u8, "0.0.0.0"),
            .read_only = false,
            .host_key = try allocator.dupe(u8, ""),
            .authorized_keys = try allocator.dupe(u8, ""),
        },
        .metrics = .{
            .collect = false,
            .http_enable = false,
            .http_port = 9167,
            .http_bind = try allocator.dupe(u8, "127.0.0.1"),
        },
    };
    defer cfg.deinit();

    // Remove pool 0 (10.0.0.0/24) — pool 1 (172.16.0.0/16) should remain
    removePool(allocator, &cfg, 0);
    try std.testing.expectEqual(@as(usize, 1), cfg.pools.len);
    try std.testing.expectEqualStrings("172.16.0.0", cfg.pools[0].subnet);
    try std.testing.expectEqual(@as(u32, 1800), cfg.pools[0].lease_time);
}
