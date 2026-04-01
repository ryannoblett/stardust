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

    // mac_classes section (only if any are defined)
    if (cfg.mac_classes.len > 0) {
        try w.writeAll("mac_classes:\n");
        for (cfg.mac_classes) |mc| {
            try w.print("  - name: {s}\n", .{mc.name});
            try w.print("    match: \"{s}\"\n", .{mc.match});
            if (mc.dhcp_options.count() > 0) {
                try w.writeAll("    dhcp_options:\n");
                var it = mc.dhcp_options.iterator();
                while (it.next()) |entry| {
                    try w.print("      {s}: {s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
                }
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
    // time_servers (option 4) is deprecated — option 4 is now served from
    // ntp_servers automatically when requested. Existing configs with
    // time_servers are still parsed for backward compatibility.
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
    if (pool.mtu) |mtu| {
        try w.print("    mtu: {d}\n", .{mtu});
    }
    if (pool.wins_servers.len > 0) {
        try w.writeAll("    wins_servers:\n");
        for (pool.wins_servers) |s| {
            try w.print("      - {s}\n", .{s});
        }
    }
    if (pool.tftp_server_name.len > 0) {
        try w.print("    tftp_server_name: {s}\n", .{pool.tftp_server_name});
    }
    if (pool.boot_filename.len > 0) {
        try w.print("    boot_filename: {s}\n", .{pool.boot_filename});
    }
    if (pool.cisco_tftp_servers.len > 0) {
        try w.writeAll("    cisco_tftp_servers:\n");
        for (pool.cisco_tftp_servers) |s| {
            try w.print("      - {s}\n", .{s});
        }
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
            if (r.dhcp_options) |opts| {
                if (opts.count() > 0) {
                    try w.writeAll("        dhcp_options:\n");
                    var oit = opts.iterator();
                    while (oit.next()) |entry| {
                        try w.print("          {s}: {s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
                    }
                }
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
    dhcp_options: ?std.StringHashMap([]const u8),
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
            // Replace dhcp_options: free old, set new
            if (r.dhcp_options) |*old_opts| {
                var oit = old_opts.iterator();
                while (oit.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    allocator.free(entry.value_ptr.*);
                }
                old_opts.deinit();
            }
            r.dhcp_options = if (dhcp_options) |opts| try dupeOptionsMap(allocator, opts) else null;
            return false;
        }
    }

    // Append new entry — allocate each field with errdefer so realloc failure doesn't leak.
    const new_mac = try allocator.dupe(u8, mac);
    errdefer allocator.free(new_mac);
    const new_ip = try allocator.dupe(u8, ip);
    errdefer allocator.free(new_ip);
    const new_hostname = if (hostname) |h| try allocator.dupe(u8, h) else null;
    errdefer if (new_hostname) |h| allocator.free(h);
    const new_client_id = if (client_id) |c| try allocator.dupe(u8, c) else null;
    errdefer if (new_client_id) |c| allocator.free(c);
    const new_opts = if (dhcp_options) |opts| try dupeOptionsMap(allocator, opts) else null;
    errdefer if (new_opts) |*o| {
        var oit = @constCast(o).iterator();
        while (oit.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        @constCast(o).deinit();
    };
    const new_slice = try allocator.realloc(pool.reservations, pool.reservations.len + 1);
    pool.reservations = new_slice;
    pool.reservations[pool.reservations.len - 1] = .{
        .mac = new_mac,
        .ip = new_ip,
        .hostname = new_hostname,
        .client_id = new_client_id,
        .dhcp_options = new_opts,
    };
    return true;
}

/// Deep-copy a StringHashMap([]const u8), duplicating all keys and values.
fn dupeOptionsMap(allocator: std.mem.Allocator, src: std.StringHashMap([]const u8)) !std.StringHashMap([]const u8) {
    var dst = std.StringHashMap([]const u8).init(allocator);
    errdefer {
        var it = dst.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        dst.deinit();
    }
    var it = src.iterator();
    while (it.next()) |entry| {
        const k = try allocator.dupe(u8, entry.key_ptr.*);
        errdefer allocator.free(k);
        const v = try allocator.dupe(u8, entry.value_ptr.*);
        errdefer allocator.free(v);
        try dst.put(k, v);
    }
    return dst;
}

/// Remove a reservation from a pool by MAC address.
/// Returns true if found and removed, false if not found.
pub fn removeReservation(
    allocator: std.mem.Allocator,
    pool: *config_mod.PoolConfig,
    mac: []const u8,
) bool {
    for (pool.reservations, 0..) |*r, i| {
        if (std.mem.eql(u8, r.mac, mac)) {
            allocator.free(r.mac);
            allocator.free(r.ip);
            if (r.hostname) |h| allocator.free(h);
            if (r.client_id) |c| allocator.free(c);
            if (r.dhcp_options) |*opts| {
                var oit = opts.iterator();
                while (oit.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    allocator.free(entry.value_ptr.*);
                }
                opts.deinit();
            }
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

test "renderConfig includes mac_classes" {
    const allocator = std.testing.allocator;

    var mc_opts = std.StringHashMap([]const u8).init(allocator);
    try mc_opts.put(
        try allocator.dupe(u8, "66"),
        try allocator.dupe(u8, "tftp.phones.local"),
    );
    var mac_classes_arr = [_]config_mod.MacClass{.{
        .name = try allocator.dupe(u8, "IP Phones"),
        .match = try allocator.dupe(u8, "64:16:7f"),
        .dhcp_options = mc_opts,
    }};
    const mac_classes_slice = try allocator.dupe(config_mod.MacClass, &mac_classes_arr);

    var pool_opts = std.StringHashMap([]const u8).init(allocator);
    var pools = [_]config_mod.PoolConfig{.{
        .subnet = "10.0.0.0",
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = "10.0.0.1",
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
        .tftp_server_name = "",
        .boot_filename = "",
        .cisco_tftp_servers = &.{},
        .http_boot_url = "",
        .dns_update = .{ .enable = false, .server = "", .zone = "", .rev_zone = "", .key_name = "", .key_file = "", .lease_time = 3600 },
        .dhcp_options = pool_opts,
        .reservations = &.{},
        .static_routes = &.{},
    }};

    var cfg = config_mod.Config{
        .allocator = allocator,
        .listen_address = "0.0.0.0",
        .state_dir = "/tmp",
        .log_level = .info,
        .pool_allocation_random = false,
        .sync = null,
        .pools = &pools,
        .mac_classes = mac_classes_slice,
        .admin_ssh = .{ .enable = false, .port = 2267, .bind = "0.0.0.0", .read_only = false, .host_key = "", .authorized_keys = "" },
        .metrics = .{ .collect = false, .http_enable = false, .http_port = 9167, .http_bind = "127.0.0.1" },
    };
    defer {
        for (cfg.mac_classes) |*mc| mc.deinit(allocator);
        allocator.free(cfg.mac_classes);
        pool_opts.deinit();
    }

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    try renderConfig(buf.writer(allocator), &cfg);
    const out = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, out, "mac_classes:") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "  - name: IP Phones") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "    match: \"64:16:7f\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "    dhcp_options:") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "      66: tftp.phones.local") != null);
}

test "renderConfig includes reservation dhcp_options" {
    const allocator = std.testing.allocator;

    var res_opts = std.StringHashMap([]const u8).init(allocator);
    try res_opts.put(
        try allocator.dupe(u8, "67"),
        try allocator.dupe(u8, "custom-boot.img"),
    );
    var reservations = [_]config_mod.Reservation{.{
        .mac = try allocator.dupe(u8, "aa:bb:cc:dd:ee:ff"),
        .ip = try allocator.dupe(u8, "10.0.0.50"),
        .hostname = try allocator.dupe(u8, "myhost"),
        .client_id = null,
        .dhcp_options = res_opts,
    }};
    const res_slice = try allocator.dupe(config_mod.Reservation, &reservations);

    var pool_opts = std.StringHashMap([]const u8).init(allocator);
    var pools = [_]config_mod.PoolConfig{.{
        .subnet = "10.0.0.0",
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = "10.0.0.1",
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
        .tftp_server_name = "",
        .boot_filename = "",
        .cisco_tftp_servers = &.{},
        .http_boot_url = "",
        .dns_update = .{ .enable = false, .server = "", .zone = "", .rev_zone = "", .key_name = "", .key_file = "", .lease_time = 3600 },
        .dhcp_options = pool_opts,
        .reservations = res_slice,
        .static_routes = &.{},
    }};

    const cfg = config_mod.Config{
        .allocator = allocator,
        .listen_address = "0.0.0.0",
        .state_dir = "/tmp",
        .log_level = .info,
        .pool_allocation_random = false,
        .sync = null,
        .pools = &pools,
        .admin_ssh = .{ .enable = false, .port = 2267, .bind = "0.0.0.0", .read_only = false, .host_key = "", .authorized_keys = "" },
        .metrics = .{ .collect = false, .http_enable = false, .http_port = 9167, .http_bind = "127.0.0.1" },
    };
    defer {
        for (res_slice) |*r| {
            allocator.free(r.mac);
            allocator.free(r.ip);
            if (r.hostname) |h| allocator.free(h);
            if (r.dhcp_options) |*o| {
                var oit = o.iterator();
                while (oit.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    allocator.free(entry.value_ptr.*);
                }
                o.deinit();
            }
        }
        allocator.free(res_slice);
        pool_opts.deinit();
    }

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    try renderConfig(buf.writer(allocator), &cfg);
    const out = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, out, "    reservations:") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "      - mac: aa:bb:cc:dd:ee:ff") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "        ip: 10.0.0.50") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "        hostname: myhost") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "        dhcp_options:") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "          67: custom-boot.img") != null);
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
        .mtu = null,
        .wins_servers = &.{},
        .tftp_server_name = "",
        .boot_filename = "",
        .cisco_tftp_servers = &.{},
        .dns_update = .{ .enable = false, .server = "", .zone = "", .rev_zone = "", .key_name = "", .key_file = "", .lease_time = 3600 },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = reservations,
        .static_routes = &.{},
    };
    defer {
        for (pool.reservations) |*r| {
            allocator.free(r.mac);
            allocator.free(r.ip);
            if (r.hostname) |h| allocator.free(h);
            if (r.client_id) |c| allocator.free(c);
            if (r.dhcp_options) |*opts| {
                var oit = opts.iterator();
                while (oit.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    allocator.free(entry.value_ptr.*);
                }
                opts.deinit();
            }
        }
        allocator.free(pool.reservations);
        pool.dhcp_options.deinit();
    }
    reservations = pool.reservations;

    const added = try upsertReservation(allocator, &pool, "aa:bb:cc:dd:ee:ff", "192.168.1.50", "myhost", null, null);
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
        .mtu = null,
        .wins_servers = &.{},
        .tftp_server_name = "",
        .boot_filename = "",
        .cisco_tftp_servers = &.{},
        .dns_update = .{ .enable = false, .server = "", .zone = "", .rev_zone = "", .key_name = "", .key_file = "", .lease_time = 3600 },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = res_slice,
        .static_routes = &.{},
    };
    defer {
        for (pool.reservations) |*r| {
            allocator.free(r.mac);
            allocator.free(r.ip);
            if (r.hostname) |h| allocator.free(h);
            if (r.client_id) |c| allocator.free(c);
            if (r.dhcp_options) |*opts| {
                var oit = opts.iterator();
                while (oit.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    allocator.free(entry.value_ptr.*);
                }
                opts.deinit();
            }
        }
        allocator.free(pool.reservations);
        pool.dhcp_options.deinit();
    }

    const added = try upsertReservation(allocator, &pool, "aa:bb:cc:dd:ee:ff", "192.168.1.55", "newhost", null, null);
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
        .mtu = null,
        .wins_servers = &.{},
        .tftp_server_name = "",
        .boot_filename = "",
        .cisco_tftp_servers = &.{},
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
        .mtu = null,
        .wins_servers = try allocator.alloc([]const u8, 0),
        .tftp_server_name = try allocator.dupe(u8, ""),
        .boot_filename = try allocator.dupe(u8, ""),
        .cisco_tftp_servers = try allocator.alloc([]const u8, 0),
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
        .mtu = null,
        .wins_servers = try allocator.alloc([]const u8, 0),
        .tftp_server_name = try allocator.dupe(u8, ""),
        .boot_filename = try allocator.dupe(u8, ""),
        .cisco_tftp_servers = try allocator.alloc([]const u8, 0),
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
        .mtu = null,
        .wins_servers = try allocator.alloc([]const u8, 0),
        .tftp_server_name = try allocator.dupe(u8, ""),
        .boot_filename = try allocator.dupe(u8, ""),
        .cisco_tftp_servers = try allocator.alloc([]const u8, 0),
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

test "upsertReservation with dhcp_options" {
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
        .mtu = null,
        .wins_servers = &.{},
        .tftp_server_name = "",
        .boot_filename = "",
        .cisco_tftp_servers = &.{},
        .dns_update = .{ .enable = false, .server = "", .zone = "", .rev_zone = "", .key_name = "", .key_file = "", .lease_time = 3600 },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = reservations,
        .static_routes = &.{},
    };
    defer {
        for (pool.reservations) |*r| {
            allocator.free(r.mac);
            allocator.free(r.ip);
            if (r.hostname) |h| allocator.free(h);
            if (r.client_id) |c| allocator.free(c);
            if (r.dhcp_options) |*opts| {
                var oit = opts.iterator();
                while (oit.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    allocator.free(entry.value_ptr.*);
                }
                opts.deinit();
            }
        }
        allocator.free(pool.reservations);
        pool.dhcp_options.deinit();
    }
    reservations = pool.reservations;

    // Build source options map
    var src_opts = std.StringHashMap([]const u8).init(allocator);
    defer src_opts.deinit();
    try src_opts.put("66", "tftp.local");
    try src_opts.put("67", "boot.img");

    // Add reservation with options
    const added = try upsertReservation(allocator, &pool, "aa:bb:cc:dd:ee:ff", "192.168.1.50", "myhost", null, src_opts);
    try std.testing.expect(added == true);
    try std.testing.expectEqual(@as(usize, 1), pool.reservations.len);
    const r = pool.reservations[0];
    try std.testing.expect(r.dhcp_options != null);
    try std.testing.expectEqualStrings("tftp.local", r.dhcp_options.?.get("66").?);
    try std.testing.expectEqualStrings("boot.img", r.dhcp_options.?.get("67").?);

    // Update reservation with different options — old options freed, new stored
    var new_opts = std.StringHashMap([]const u8).init(allocator);
    defer new_opts.deinit();
    try new_opts.put("66", "tftp2.local");

    const updated = try upsertReservation(allocator, &pool, "aa:bb:cc:dd:ee:ff", "192.168.1.51", "newhost", null, new_opts);
    try std.testing.expect(updated == false);
    const r2 = pool.reservations[0];
    try std.testing.expect(r2.dhcp_options != null);
    try std.testing.expectEqualStrings("tftp2.local", r2.dhcp_options.?.get("66").?);
    try std.testing.expect(r2.dhcp_options.?.get("67") == null); // old key gone

    // Update with null options — clears options
    const updated2 = try upsertReservation(allocator, &pool, "aa:bb:cc:dd:ee:ff", "192.168.1.51", "newhost", null, null);
    try std.testing.expect(updated2 == false);
    try std.testing.expect(pool.reservations[0].dhcp_options == null);
}

test "removeReservation frees dhcp_options" {
    const allocator = std.testing.allocator;

    // Create a reservation with dhcp_options
    var opts = std.StringHashMap([]const u8).init(allocator);
    try opts.put(try allocator.dupe(u8, "66"), try allocator.dupe(u8, "tftp.local"));

    var initial = [_]config_mod.Reservation{.{
        .mac = try allocator.dupe(u8, "aa:bb:cc:dd:ee:ff"),
        .ip = try allocator.dupe(u8, "192.168.1.50"),
        .hostname = null,
        .client_id = null,
        .dhcp_options = opts,
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
        .mtu = null,
        .wins_servers = &.{},
        .tftp_server_name = "",
        .boot_filename = "",
        .cisco_tftp_servers = &.{},
        .dns_update = .{ .enable = false, .server = "", .zone = "", .rev_zone = "", .key_name = "", .key_file = "", .lease_time = 3600 },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = res_slice,
        .static_routes = &.{},
    };
    defer {
        allocator.free(pool.reservations);
        pool.dhcp_options.deinit();
    }

    // removeReservation should free the dhcp_options map without leaking
    const removed = removeReservation(allocator, &pool, "aa:bb:cc:dd:ee:ff");
    try std.testing.expect(removed == true);
    try std.testing.expectEqual(@as(usize, 0), pool.reservations.len);
}

test "renderConfig includes mtu, wins_servers, and cisco_tftp_servers" {
    const allocator = std.testing.allocator;

    var wins = [_][]const u8{"10.0.0.5"};
    var cisco = [_][]const u8{ "10.0.0.6", "10.0.0.7" };
    var pool_opts = std.StringHashMap([]const u8).init(allocator);
    var pools = [_]config_mod.PoolConfig{.{
        .subnet = "10.0.0.0",
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = "10.0.0.1",
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
        .mtu = 9000,
        .wins_servers = &wins,
        .tftp_server_name = "",
        .boot_filename = "",
        .cisco_tftp_servers = &cisco,
        .http_boot_url = "",
        .dns_update = .{ .enable = false, .server = "", .zone = "", .rev_zone = "", .key_name = "", .key_file = "", .lease_time = 3600 },
        .dhcp_options = pool_opts,
        .reservations = &.{},
        .static_routes = &.{},
    }};

    const cfg = config_mod.Config{
        .allocator = allocator,
        .listen_address = "0.0.0.0",
        .state_dir = "/tmp",
        .log_level = .info,
        .pool_allocation_random = false,
        .sync = null,
        .pools = &pools,
        .admin_ssh = .{ .enable = false, .port = 2267, .bind = "0.0.0.0", .read_only = false, .host_key = "", .authorized_keys = "" },
        .metrics = .{ .collect = false, .http_enable = false, .http_port = 9167, .http_bind = "127.0.0.1" },
    };
    defer pool_opts.deinit();

    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    try renderConfig(buf.writer(allocator), &cfg);
    const out = buf.items;

    try std.testing.expect(std.mem.indexOf(u8, out, "    mtu: 9000") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "    wins_servers:") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "      - 10.0.0.5") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "    cisco_tftp_servers:") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "      - 10.0.0.6") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "      - 10.0.0.7") != null);
}
