const std = @import("std");
const yaml = @import("yaml");
const dns_mod = @import("./dns.zig");

pub const Error = error{
    ConfigNotFound,
    InvalidConfig,
    IoError,
    OutOfMemory,
};

pub const SyncConfig = struct {
    enable: bool,
    group_name: []const u8,
    key_file: []const u8,
    port: u16, // default 647
    full_sync_interval: u32, // seconds, default 300
    multicast: ?[]const u8, // null if using peers mode
    peers: [][]const u8, // empty if using multicast mode
    config_sync: bool = false, // accept config pushes from peers (also requires global config_writable)
};

/// SSH admin interface configuration.
pub const AdminSSHConfig = struct {
    enable: bool = false,
    port: u16 = 2267, // DHCP(67) + SSH(22) concatenated
    bind: []const u8,
    read_only: bool = false, // if true: viewing only, all writes blocked
    host_key: []const u8, // path to SSH host private key (Ed25519 recommended)
    authorized_keys: []const u8, // path to authorized_keys file
};

/// Prometheus metrics configuration.
pub const MetricsConfig = struct {
    collect: bool = true, // enable in-process counters (used by SSH stats page)
    http_enable: bool = false, // expose via HTTP endpoint
    http_port: u16 = 9167, // Prometheus convention 91xx + DHCP port 67
    http_bind: []const u8, // bind address for HTTP server
};

pub const Reservation = struct {
    mac: []const u8,
    ip: []const u8,
    hostname: ?[]const u8,
    client_id: ?[]const u8,
    dhcp_options: ?std.StringHashMap([]const u8) = null,
    config_modified: i64 = 0, // unix timestamp; 0 = unknown/never modified via TUI/sync
};

/// MAC class rule: matches client MACs by prefix pattern and overrides DHCP options
/// and/or first-class pool fields. Applied after pool defaults, before per-reservation
/// overrides. First-class fields (router, dns_servers, etc.) allow structured overrides
/// without needing raw option codes; dhcp_options provides escape-hatch for any code.
pub const MacClass = struct {
    name: []const u8,
    match: []const u8, // MAC prefix, e.g. "64:16:7f" or "aa:bb:cc:dd:*"
    // Optional first-class field overrides (null/empty = use pool default)
    router: ?[]const u8 = null,
    domain_name: ?[]const u8 = null,
    domain_search: [][]const u8 = &.{},
    dns_servers: [][]const u8 = &.{},
    ntp_servers: [][]const u8 = &.{},
    log_servers: [][]const u8 = &.{},
    wins_servers: [][]const u8 = &.{},
    time_offset: ?i32 = null,
    tftp_servers: [][]const u8 = &.{},
    boot_filename: ?[]const u8 = null,
    http_boot_url: ?[]const u8 = null,
    static_routes: []StaticRoute = &.{},
    dhcp_options: std.StringHashMap([]const u8),

    pub fn deinit(self: *MacClass, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.match);
        if (self.router) |r| allocator.free(r);
        if (self.domain_name) |d| allocator.free(d);
        for (self.domain_search) |s| allocator.free(s);
        if (self.domain_search.len > 0) allocator.free(self.domain_search);
        for (self.dns_servers) |s| allocator.free(s);
        if (self.dns_servers.len > 0) allocator.free(self.dns_servers);
        for (self.ntp_servers) |s| allocator.free(s);
        if (self.ntp_servers.len > 0) allocator.free(self.ntp_servers);
        for (self.log_servers) |s| allocator.free(s);
        if (self.log_servers.len > 0) allocator.free(self.log_servers);
        for (self.wins_servers) |s| allocator.free(s);
        if (self.wins_servers.len > 0) allocator.free(self.wins_servers);
        for (self.tftp_servers) |s| allocator.free(s);
        if (self.tftp_servers.len > 0) allocator.free(self.tftp_servers);
        if (self.boot_filename) |b| allocator.free(b);
        if (self.http_boot_url) |h| allocator.free(h);
        if (self.static_routes.len > 0) allocator.free(self.static_routes);
        var it = self.dhcp_options.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.dhcp_options.deinit();
    }
};

pub const StaticRoute = struct {
    destination: [4]u8, // masked network address
    prefix_len: u8, // 0–32
    router: [4]u8,
};

/// Per-pool configuration. Each pool represents one subnet served by the daemon.
pub const PoolConfig = struct {
    subnet: []const u8, // dotted-decimal network address, e.g. "192.168.1.0"
    subnet_mask: u32, // host-order mask
    prefix_len: u8, // CIDR prefix length (for display)
    router: []const u8,
    pool_start: []const u8, // "" = subnet+1
    pool_end: []const u8, // "" = broadcast-1
    dns_servers: [][]const u8,
    domain_name: []const u8,
    domain_search: [][]const u8,
    lease_time: u32,
    time_offset: ?i32, // seconds east of UTC; null = not sent
    time_servers: [][]const u8,
    log_servers: [][]const u8,
    ntp_servers: [][]const u8,
    mtu: ?u16 = null, // interface MTU (option 26); null = not sent
    wins_servers: [][]const u8, // NetBIOS/WINS name servers (option 44)
    tftp_servers: [][]const u8, // TFTP server addresses (option 66 uses [0], option 150 uses all)
    boot_filename: []const u8,
    /// HTTP/HTTPS URL served as option 67 when the client identifies as a
    /// UEFI HTTP boot client (option 60 = "HTTPClient…").  When non-empty and
    /// the client sends the "HTTPClient" vendor class, this URL overrides
    /// boot_filename and option 60 is echoed back to the client.
    http_boot_url: []const u8,
    dns_update: dns_mod.Config,
    dhcp_options: std.StringHashMap([]const u8),
    reservations: []Reservation,
    static_routes: []StaticRoute,
    mac_classes: []MacClass = &.{},

    pub fn deinit(self: *PoolConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.subnet);
        allocator.free(self.router);
        allocator.free(self.pool_start);
        allocator.free(self.pool_end);
        for (self.dns_servers) |s| allocator.free(s);
        allocator.free(self.dns_servers);
        allocator.free(self.domain_name);
        for (self.domain_search) |s| allocator.free(s);
        allocator.free(self.domain_search);
        for (self.time_servers) |s| allocator.free(s);
        allocator.free(self.time_servers);
        for (self.log_servers) |s| allocator.free(s);
        allocator.free(self.log_servers);
        for (self.ntp_servers) |s| allocator.free(s);
        allocator.free(self.ntp_servers);
        for (self.wins_servers) |s| allocator.free(s);
        allocator.free(self.wins_servers);
        for (self.tftp_servers) |s| allocator.free(s);
        allocator.free(self.tftp_servers);
        allocator.free(self.boot_filename);
        allocator.free(self.http_boot_url);
        allocator.free(self.dns_update.server);
        allocator.free(self.dns_update.zone);
        allocator.free(self.dns_update.rev_zone);
        allocator.free(self.dns_update.key_name);
        allocator.free(self.dns_update.key_file);
        var it = self.dhcp_options.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.dhcp_options.deinit();
        for (self.reservations) |*r| {
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
        allocator.free(self.reservations);
        allocator.free(self.static_routes);
        for (self.mac_classes) |*mc| @constCast(mc).deinit(allocator);
        if (self.mac_classes.len > 0) allocator.free(self.mac_classes);
    }
};

/// Global server configuration. Subnet-specific settings live in pools[].
/// Runtime log level. Extends std.log.Level with a "verbose" level between
/// info and debug for per-event DHCP summaries (one line per lease/release/NAK).
pub const LogLevel = enum { err, warn, info, verbose, debug };

pub const Config = struct {
    allocator: std.mem.Allocator,
    listen_address: []const u8,
    state_dir: []const u8,
    log_level: LogLevel,
    pool_allocation_random: bool, // false = sequential (default), true = random start offset
    config_writable: bool = false, // global gate: allow any feature (TUI, sync) to write config
    sync: ?SyncConfig,
    pools: []PoolConfig, // at least one required
    admin_ssh: AdminSSHConfig,
    metrics: MetricsConfig,

    pub fn deinit(self: *Config) void {
        self.allocator.free(self.listen_address);
        self.allocator.free(self.state_dir);
        for (self.pools) |*pool| pool.deinit(self.allocator);
        self.allocator.free(self.pools);
        if (self.sync) |*s| {
            self.allocator.free(s.group_name);
            self.allocator.free(s.key_file);
            if (s.multicast) |m| self.allocator.free(m);
            for (s.peers) |p| self.allocator.free(p);
            self.allocator.free(s.peers);
        }
        self.allocator.free(self.admin_ssh.bind);
        self.allocator.free(self.admin_ssh.host_key);
        self.allocator.free(self.admin_ssh.authorized_keys);
        self.allocator.free(self.metrics.http_bind);
    }
};

// Typed parse target for global (non-pool) fields only.
const RawConfig = struct {
    listen_address: ?[]const u8 = null,
    state_dir: ?[]const u8 = null,
    log_level: ?[]const u8 = null,
};

/// Load and parse a YAML config file from `path`.
/// Caller must call `cfg.deinit()` when done.
pub fn load(allocator: std.mem.Allocator, path: []const u8) !Config {
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        if (err == error.FileNotFound) return Error.ConfigNotFound;
        return Error.IoError;
    };
    defer file.close();

    const file_size = (try file.stat()).size;
    const source = try allocator.alloc(u8, file_size);
    defer allocator.free(source);
    _ = try file.readAll(source);

    var doc = yaml.Yaml{ .source = source };
    doc.load(allocator) catch |err| {
        if (err == error.ParseFailure) {
            doc.parse_errors.renderToStdErr(.{ .ttyconf = .no_color });
        }
        return err;
    };
    defer doc.deinit(allocator);

    var parse_arena = std.heap.ArenaAllocator.init(allocator);
    defer parse_arena.deinit();

    const raw = doc.parse(parse_arena.allocator(), RawConfig) catch |err| {
        std.log.err("config: failed to parse '{s}': {s}", .{ path, @errorName(err) });
        return err;
    };

    var cfg = Config{
        .allocator = allocator,
        .listen_address = try allocator.dupe(u8, raw.listen_address orelse "0.0.0.0"),
        .state_dir = try allocator.dupe(u8, raw.state_dir orelse "/var/lib/stardust"),
        .log_level = parseLogLevel(raw.log_level orelse "info"),
        .pool_allocation_random = false,
        .config_writable = false,
        .sync = null,
        .pools = try allocator.alloc(PoolConfig, 0),
        .admin_ssh = .{
            .enable = false,
            .port = 2267,
            .bind = try allocator.dupe(u8, "0.0.0.0"),
            .read_only = false,
            .host_key = try allocator.dupe(u8, "/etc/stardust/ssh_host_key"),
            .authorized_keys = try allocator.dupe(u8, "/etc/stardust/authorized_keys"),
        },
        .metrics = .{
            .collect = true,
            .http_enable = false,
            .http_port = 9167,
            .http_bind = try allocator.dupe(u8, "127.0.0.1"),
        },
    };
    errdefer cfg.deinit();

    if (doc.docs.items.len > 0) {
        if (doc.docs.items[0].asMap()) |root_map| {
            if (root_map.get("pool_allocation_random")) |par_val| {
                if (par_val.asScalar()) |s| {
                    if (std.mem.eql(u8, s, "true")) cfg.pool_allocation_random = true;
                }
            }
            if (root_map.get("config_writable")) |cw_val| {
                if (cw_val.asScalar()) |s| {
                    if (std.mem.eql(u8, s, "true")) cfg.config_writable = true;
                }
            }

            if (root_map.get("sync")) |sync_val| {
                if (sync_val.asMap()) |sync_map| {
                    cfg.sync = try parseSyncConfig(allocator, sync_map);
                }
            }

            if (root_map.get("mac_classes")) |_| {
                std.log.warn("config: global mac_classes is deprecated, move them into each pool", .{});
            }

            if (root_map.get("admin_ssh")) |ssh_val| {
                if (ssh_val.asMap()) |ssh_map| {
                    if (ssh_map.get("enable")) |v| {
                        if (v.asScalar()) |s| cfg.admin_ssh.enable = std.mem.eql(u8, s, "true");
                    }
                    if (ssh_map.get("port")) |v| {
                        if (v.asScalar()) |s| cfg.admin_ssh.port = std.fmt.parseInt(u16, s, 10) catch 2267;
                    }
                    if (ssh_map.get("bind")) |v| {
                        if (v.asScalar()) |s| {
                            allocator.free(cfg.admin_ssh.bind);
                            cfg.admin_ssh.bind = try allocator.dupe(u8, s);
                        }
                    }
                    if (ssh_map.get("read_only")) |v| {
                        if (v.asScalar()) |s| cfg.admin_ssh.read_only = std.mem.eql(u8, s, "true");
                    }
                    if (ssh_map.get("host_key")) |v| {
                        if (v.asScalar()) |s| {
                            allocator.free(cfg.admin_ssh.host_key);
                            cfg.admin_ssh.host_key = try allocator.dupe(u8, s);
                        }
                    }
                    if (ssh_map.get("authorized_keys")) |v| {
                        if (v.asScalar()) |s| {
                            allocator.free(cfg.admin_ssh.authorized_keys);
                            cfg.admin_ssh.authorized_keys = try allocator.dupe(u8, s);
                        }
                    }
                }
            }

            if (root_map.get("metrics")) |met_val| {
                if (met_val.asMap()) |met_map| {
                    if (met_map.get("collect")) |v| {
                        if (v.asScalar()) |s| cfg.metrics.collect = !std.mem.eql(u8, s, "false");
                    }
                    if (met_map.get("http_enable")) |v| {
                        if (v.asScalar()) |s| cfg.metrics.http_enable = std.mem.eql(u8, s, "true");
                    }
                    if (met_map.get("http_port")) |v| {
                        if (v.asScalar()) |s| cfg.metrics.http_port = std.fmt.parseInt(u16, s, 10) catch 9167;
                    }
                    if (met_map.get("http_bind")) |v| {
                        if (v.asScalar()) |s| {
                            allocator.free(cfg.metrics.http_bind);
                            cfg.metrics.http_bind = try allocator.dupe(u8, s);
                        }
                    }
                }
            }

            if (root_map.get("pools")) |pools_val| {
                if (pools_val.asList()) |pools_list| {
                    try parsePools(allocator, &cfg, pools_list);
                }
            }
        }
    }

    if (cfg.pools.len == 0) {
        std.log.err("config: 'pools' is required and must contain at least one subnet", .{});
        return Error.InvalidConfig;
    }

    return cfg;
}

fn parsePools(allocator: std.mem.Allocator, cfg: *Config, list: anytype) !void {
    var pool_list = std.ArrayListUnmanaged(PoolConfig){};
    errdefer {
        for (pool_list.items) |*p| p.deinit(allocator);
        pool_list.deinit(allocator);
    }

    for (list) |item| {
        const m = item.asMap() orelse {
            std.log.warn("config: pool entry is not a map, skipping", .{});
            continue;
        };
        if (try parseOnePool(allocator, m)) |pool| {
            errdefer {
                var p = pool;
                p.deinit(allocator);
            }
            try pool_list.append(allocator, pool);
        }
    }

    const new_slice = try pool_list.toOwnedSlice(allocator);
    allocator.free(cfg.pools);
    cfg.pools = new_slice;
}

fn parseOnePool(allocator: std.mem.Allocator, pool_map: anytype) !?PoolConfig {
    // Required: subnet in CIDR notation.
    const subnet_val = pool_map.get("subnet") orelse {
        std.log.err("config: pool missing 'subnet' (expected CIDR e.g. 192.168.1.0/24), skipping", .{});
        return null;
    };
    const subnet_str = subnet_val.asScalar() orelse {
        std.log.err("config: pool 'subnet' is not a scalar, skipping", .{});
        return null;
    };

    const cidr = parseCidr(subnet_str) catch {
        std.log.err("config: pool subnet '{s}' is not valid CIDR notation, skipping", .{subnet_str});
        return null;
    };

    var subnet_buf: [15]u8 = undefined;
    const subnet_dotted = std.fmt.bufPrint(&subnet_buf, "{d}.{d}.{d}.{d}", .{
        cidr.ip[0], cidr.ip[1], cidr.ip[2], cidr.ip[3],
    }) catch return null;

    const lease_time_val: u32 = if (pool_map.get("lease_time")) |v|
        if (v.asScalar()) |s| std.fmt.parseInt(u32, s, 10) catch 3600 else 3600
    else
        3600;

    var pool = PoolConfig{
        .subnet = try allocator.dupe(u8, subnet_dotted),
        .subnet_mask = cidr.mask,
        .prefix_len = cidr.prefix_len,
        .router = try allocator.dupe(u8, ""),
        .pool_start = try allocator.dupe(u8, ""),
        .pool_end = try allocator.dupe(u8, ""),
        .dns_servers = try allocator.alloc([]const u8, 0),
        .domain_name = try allocator.dupe(u8, ""),
        .domain_search = try allocator.alloc([]const u8, 0),
        .lease_time = lease_time_val,
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
            .rev_zone = try reverseZoneForSubnet(allocator, cidr.ip, cidr.prefix_len),
            .key_name = try allocator.dupe(u8, ""),
            .key_file = try allocator.dupe(u8, ""),
            .lease_time = lease_time_val,
        },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = try allocator.alloc(Reservation, 0),
        .static_routes = try allocator.alloc(StaticRoute, 0),
    };
    errdefer pool.deinit(allocator);

    if (pool_map.get("router")) |v| {
        if (v.asScalar()) |s| {
            allocator.free(pool.router);
            pool.router = try allocator.dupe(u8, s);
        }
    }

    if (pool_map.get("pool_start")) |v| {
        if (v.asScalar()) |s| {
            allocator.free(pool.pool_start);
            pool.pool_start = try allocator.dupe(u8, s);
        }
    }

    if (pool_map.get("pool_end")) |v| {
        if (v.asScalar()) |s| {
            allocator.free(pool.pool_end);
            pool.pool_end = try allocator.dupe(u8, s);
        }
    }

    if (pool_map.get("domain_name")) |v| {
        if (v.asScalar()) |s| {
            allocator.free(pool.domain_name);
            pool.domain_name = try allocator.dupe(u8, s);
        }
    }

    if (pool_map.get("tftp_servers")) |v| {
        if (v.asList()) |list| {
            allocator.free(pool.tftp_servers);
            pool.tftp_servers = try allocator.alloc([]const u8, list.len);
            for (pool.tftp_servers) |*s| s.* = allocator.alloc(u8, 0) catch unreachable;
            for (list, 0..) |item, i| {
                pool.tftp_servers[i] = try allocator.dupe(u8, item.asScalar() orelse "");
            }
        }
    } else {
        // Backward compat: merge deprecated tftp_server_name + cisco_tftp_servers into tftp_servers.
        var legacy_count: usize = 0;
        var legacy_name: ?[]const u8 = null;
        var has_cisco = false;

        if (pool_map.get("tftp_server_name")) |v| {
            if (v.asScalar()) |s| {
                if (s.len > 0) {
                    legacy_name = s;
                    legacy_count += 1;
                    std.log.warn("config: tftp_server_name is deprecated, use tftp_servers list", .{});
                }
            }
        }
        if (pool_map.get("cisco_tftp_servers")) |v| {
            if (v.asList()) |list| {
                has_cisco = true;
                legacy_count += list.len;
                std.log.warn("config: cisco_tftp_servers is deprecated, use tftp_servers list", .{});
            }
        }
        if (legacy_count > 0) {
            allocator.free(pool.tftp_servers);
            pool.tftp_servers = try allocator.alloc([]const u8, legacy_count);
            for (pool.tftp_servers) |*s| s.* = allocator.alloc(u8, 0) catch unreachable;
            var idx: usize = 0;
            if (legacy_name) |name| {
                pool.tftp_servers[idx] = try allocator.dupe(u8, name);
                idx += 1;
            }
            if (has_cisco) {
                if (pool_map.get("cisco_tftp_servers")) |v| {
                    if (v.asList()) |list| {
                        for (list) |item| {
                            pool.tftp_servers[idx] = try allocator.dupe(u8, item.asScalar() orelse "");
                            idx += 1;
                        }
                    }
                }
            }
        }
    }

    if (pool_map.get("boot_filename")) |v| {
        if (v.asScalar()) |s| {
            allocator.free(pool.boot_filename);
            pool.boot_filename = try allocator.dupe(u8, s);
        }
    }

    if (pool_map.get("http_boot_url")) |v| {
        if (v.asScalar()) |s| {
            allocator.free(pool.http_boot_url);
            pool.http_boot_url = try allocator.dupe(u8, s);
        }
    }

    if (pool_map.get("time_offset")) |v| {
        if (v.asScalar()) |s| {
            pool.time_offset = std.fmt.parseInt(i32, s, 10) catch null;
        }
    }

    if (pool_map.get("dns_servers")) |v| {
        if (v.asList()) |list| {
            allocator.free(pool.dns_servers);
            pool.dns_servers = try allocator.alloc([]const u8, list.len);
            for (pool.dns_servers) |*s| s.* = allocator.alloc(u8, 0) catch unreachable;
            for (list, 0..) |item, i| {
                pool.dns_servers[i] = try allocator.dupe(u8, item.asScalar() orelse "");
            }
        }
    }

    if (pool_map.get("domain_search")) |v| {
        if (v.asList()) |list| {
            allocator.free(pool.domain_search);
            pool.domain_search = try allocator.alloc([]const u8, list.len);
            for (pool.domain_search) |*s| s.* = allocator.alloc(u8, 0) catch unreachable;
            for (list, 0..) |item, i| {
                pool.domain_search[i] = try allocator.dupe(u8, item.asScalar() orelse "");
            }
        }
    }

    if (pool_map.get("time_servers")) |v| {
        if (v.asList()) |list| {
            allocator.free(pool.time_servers);
            pool.time_servers = try allocator.alloc([]const u8, list.len);
            for (pool.time_servers) |*s| s.* = allocator.alloc(u8, 0) catch unreachable;
            for (list, 0..) |item, i| {
                pool.time_servers[i] = try allocator.dupe(u8, item.asScalar() orelse "");
            }
        }
    }

    if (pool_map.get("log_servers")) |v| {
        if (v.asList()) |list| {
            allocator.free(pool.log_servers);
            pool.log_servers = try allocator.alloc([]const u8, list.len);
            for (pool.log_servers) |*s| s.* = allocator.alloc(u8, 0) catch unreachable;
            for (list, 0..) |item, i| {
                pool.log_servers[i] = try allocator.dupe(u8, item.asScalar() orelse "");
            }
        }
    }

    if (pool_map.get("ntp_servers")) |v| {
        if (v.asList()) |list| {
            allocator.free(pool.ntp_servers);
            pool.ntp_servers = try allocator.alloc([]const u8, list.len);
            for (pool.ntp_servers) |*s| s.* = allocator.alloc(u8, 0) catch unreachable;
            for (list, 0..) |item, i| {
                pool.ntp_servers[i] = try allocator.dupe(u8, item.asScalar() orelse "");
            }
        }
    }

    if (pool_map.get("mtu")) |v| {
        if (v.asScalar()) |s| {
            pool.mtu = std.fmt.parseInt(u16, s, 10) catch null;
        }
    }

    if (pool_map.get("wins_servers")) |v| {
        if (v.asList()) |list| {
            allocator.free(pool.wins_servers);
            pool.wins_servers = try allocator.alloc([]const u8, list.len);
            for (pool.wins_servers) |*s| s.* = allocator.alloc(u8, 0) catch unreachable;
            for (list, 0..) |item, i| {
                pool.wins_servers[i] = try allocator.dupe(u8, item.asScalar() orelse "");
            }
        }
    }

    if (pool_map.get("dns_update")) |v| {
        if (v.asMap()) |m| {
            if (m.get("enable")) |ev| {
                if (ev.asScalar()) |s| pool.dns_update.enable = std.mem.eql(u8, s, "true");
            }
            if (m.get("server")) |sv| {
                if (sv.asScalar()) |s| {
                    allocator.free(pool.dns_update.server);
                    pool.dns_update.server = try allocator.dupe(u8, s);
                }
            }
            if (m.get("zone")) |sv| {
                if (sv.asScalar()) |s| {
                    allocator.free(pool.dns_update.zone);
                    pool.dns_update.zone = try allocator.dupe(u8, s);
                }
            }
            if (m.get("key_name")) |sv| {
                if (sv.asScalar()) |s| {
                    allocator.free(pool.dns_update.key_name);
                    pool.dns_update.key_name = try allocator.dupe(u8, s);
                }
            }
            if (m.get("key_file")) |sv| {
                if (sv.asScalar()) |s| {
                    allocator.free(pool.dns_update.key_file);
                    pool.dns_update.key_file = try allocator.dupe(u8, s);
                }
            }
            pool.dns_update.lease_time = pool.lease_time;
        }
    }

    if (pool_map.get("dhcp_options")) |opts_val| {
        if (opts_val.asMap()) |opts_map| {
            var it = opts_map.iterator();
            while (it.next()) |entry| {
                const key = try allocator.dupe(u8, entry.key_ptr.*);
                errdefer allocator.free(key);
                const val_str = entry.value_ptr.asScalar() orelse "";
                const val = try allocator.dupe(u8, val_str);
                errdefer allocator.free(val);
                try pool.dhcp_options.put(key, val);
            }
        }
    }

    if (pool_map.get("reservations")) |res_val| {
        if (res_val.asList()) |res_list| {
            try parseReservations(allocator, &pool, res_list);
        }
    }

    if (pool_map.get("static_routes")) |sr_val| {
        if (sr_val.asList()) |sr_list| {
            try parseStaticRoutes(allocator, &pool, sr_list);
        }
    }

    if (pool_map.get("mac_classes")) |mc_val| {
        if (mc_val.asList()) |mc_list| {
            pool.mac_classes = try parseMacClasses(allocator, mc_list);
        }
    }

    if (!validatePoolFields(allocator, &pool)) return null;

    return pool;
}

/// Parse the reservations list from the untyped YAML walk and append valid entries to pool.
fn parseReservations(allocator: std.mem.Allocator, pool: *PoolConfig, list: anytype) !void {
    var valid_count: usize = 0;
    for (list) |item| {
        const m = item.asMap() orelse continue;
        if (m.get("mac") == null or m.get("ip") == null) continue;
        valid_count += 1;
    }

    if (valid_count == 0) return;

    const old_len = pool.reservations.len;
    const new_slice = try allocator.realloc(pool.reservations, old_len + valid_count);
    pool.reservations = new_slice;

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

        // Validate that the reservation IP is in the pool's subnet.
        const ip_bytes = parseIpv4(ip_str) catch {
            std.log.warn("config: reservation ip '{s}' is invalid, skipping", .{ip_str});
            continue;
        };
        const ip_int = std.mem.readInt(u32, &ip_bytes, .big);
        const subnet_bytes = parseIpv4(pool.subnet) catch [4]u8{ 0, 0, 0, 0 };
        const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
        const broadcast_int = subnet_int | ~pool.subnet_mask;
        if ((ip_int & pool.subnet_mask) != subnet_int or ip_int == subnet_int or ip_int == broadcast_int) {
            std.log.warn("config: reservation ip '{s}' is outside subnet {s}/{d}, skipping", .{
                ip_str, pool.subnet, pool.prefix_len,
            });
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

        // Parse optional per-reservation dhcp_options.
        var res_opts: ?std.StringHashMap([]const u8) = null;
        errdefer if (res_opts) |*opts| {
            var oit = opts.iterator();
            while (oit.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                allocator.free(entry.value_ptr.*);
            }
            opts.deinit();
        };
        if (m.get("dhcp_options")) |opts_val| {
            if (opts_val.asMap()) |opts_map| {
                res_opts = std.StringHashMap([]const u8).init(allocator);
                var oit = opts_map.iterator();
                while (oit.next()) |entry| {
                    const ok = try allocator.dupe(u8, entry.key_ptr.*);
                    errdefer allocator.free(ok);
                    const ov = try allocator.dupe(u8, entry.value_ptr.asScalar() orelse "");
                    errdefer allocator.free(ov);
                    try res_opts.?.put(ok, ov);
                }
            }
        }

        // Parse optional config_modified timestamp.
        var config_modified_val: i64 = 0;
        if (m.get("config_modified")) |cm_val| {
            if (cm_val.asScalar()) |cm_str| {
                config_modified_val = std.fmt.parseInt(i64, cm_str, 10) catch 0;
            }
        }

        pool.reservations[idx] = .{
            .mac = mac_owned,
            .ip = ip_owned,
            .hostname = hostname_owned,
            .client_id = client_id_owned,
            .dhcp_options = res_opts,
            .config_modified = config_modified_val,
        };
        idx += 1;
    }

    pool.reservations = allocator.realloc(pool.reservations, idx) catch pool.reservations;
}

/// Parse a single static route from destination and router strings.
fn parseOneStaticRoute(dest_str: []const u8, router_str: []const u8) ?StaticRoute {
    var prefix_len: u8 = 32;
    var ip_str: []const u8 = dest_str;
    if (std.mem.indexOfScalar(u8, dest_str, '/')) |slash| {
        ip_str = dest_str[0..slash];
        const pl = std.fmt.parseInt(u8, dest_str[slash + 1 ..], 10) catch {
            std.log.warn("config: static_route destination '{s}' has invalid prefix length, skipping", .{dest_str});
            return null;
        };
        if (pl > 32) {
            std.log.warn("config: static_route destination '{s}' prefix_len out of range, skipping", .{dest_str});
            return null;
        }
        prefix_len = @intCast(pl);
    }

    if (prefix_len == 0) {
        std.log.warn("config: static_route '{s}' is a default route (0.0.0.0/0); use the 'router' option instead, skipping", .{dest_str});
        return null;
    }

    const dest_bytes = parseIpv4(ip_str) catch {
        std.log.warn("config: static_route destination '{s}' is invalid, skipping", .{dest_str});
        return null;
    };
    const router_bytes = parseIpv4(router_str) catch {
        std.log.warn("config: static_route router '{s}' is invalid, skipping", .{router_str});
        return null;
    };

    const mask: u32 = @as(u32, 0xFFFFFFFF) << @intCast(32 - prefix_len);
    var dest_int = std.mem.readInt(u32, &dest_bytes, .big);
    dest_int &= mask;
    var masked_dest: [4]u8 = undefined;
    std.mem.writeInt(u32, &masked_dest, dest_int, .big);

    return StaticRoute{
        .destination = masked_dest,
        .prefix_len = prefix_len,
        .router = router_bytes,
    };
}

/// Parse the static_routes list from the untyped YAML walk and append valid entries to pool.
fn parseStaticRoutes(allocator: std.mem.Allocator, pool: *PoolConfig, list: anytype) !void {
    const old_len = pool.static_routes.len;
    var count: usize = 0;

    for (list) |item| {
        const m = item.asMap() orelse {
            std.log.warn("config: static_route entry is not a map, skipping", .{});
            continue;
        };
        const dest_val = m.get("destination") orelse {
            std.log.warn("config: static_route missing 'destination', skipping", .{});
            continue;
        };
        const router_val = m.get("router") orelse {
            std.log.warn("config: static_route missing 'router', skipping", .{});
            continue;
        };
        const dest_str = dest_val.asScalar() orelse {
            std.log.warn("config: static_route 'destination' is not a scalar, skipping", .{});
            continue;
        };
        const router_str = router_val.asScalar() orelse {
            std.log.warn("config: static_route 'router' is not a scalar, skipping", .{});
            continue;
        };

        const route = parseOneStaticRoute(dest_str, router_str) orelse continue;

        const new_slice = try allocator.realloc(pool.static_routes, old_len + count + 1);
        pool.static_routes = new_slice;
        pool.static_routes[old_len + count] = route;
        count += 1;
    }
}

/// Parse the sync section from the untyped YAML map into a SyncConfig.
fn parseSyncConfig(allocator: std.mem.Allocator, sync_map: anytype) !?SyncConfig {
    const enable_val = sync_map.get("enable") orelse return null;
    const enable_str = enable_val.asScalar() orelse return null;
    if (!std.mem.eql(u8, enable_str, "true")) return null;

    const group_name = if (sync_map.get("group_name")) |v|
        if (v.asScalar()) |s| try allocator.dupe(u8, s) else try allocator.dupe(u8, "default")
    else
        try allocator.dupe(u8, "default");
    errdefer allocator.free(group_name);

    const key_file = if (sync_map.get("key_file")) |v|
        if (v.asScalar()) |s| try allocator.dupe(u8, s) else try allocator.dupe(u8, "")
    else
        try allocator.dupe(u8, "");
    errdefer allocator.free(key_file);

    var port: u16 = 647;
    if (sync_map.get("port")) |v| {
        if (v.asScalar()) |s| {
            port = std.fmt.parseInt(u16, s, 10) catch 647;
        }
    }

    var full_sync_interval: u32 = 300;
    if (sync_map.get("full_sync_interval")) |v| {
        if (v.asScalar()) |s| {
            full_sync_interval = std.fmt.parseInt(u32, s, 10) catch 300;
        }
    }

    var multicast: ?[]const u8 = null;
    errdefer if (multicast) |m| allocator.free(m);
    if (sync_map.get("multicast")) |v| {
        if (v.asScalar()) |s| {
            multicast = try allocator.dupe(u8, s);
        }
    }

    var peers = try allocator.alloc([]const u8, 0);
    errdefer {
        for (peers) |p| allocator.free(p);
        allocator.free(peers);
    }
    if (sync_map.get("peers")) |v| {
        if (v.asList()) |list| {
            peers = try allocator.realloc(peers, list.len);
            for (peers) |*p| p.* = "";
            var count: usize = 0;
            for (list) |item| {
                if (item.asScalar()) |s| {
                    peers[count] = try allocator.dupe(u8, s);
                    count += 1;
                }
            }
            peers = allocator.realloc(peers, count) catch peers;
        }
    }

    var config_sync: bool = false;
    if (sync_map.get("config_sync")) |v| {
        if (v.asScalar()) |s| {
            config_sync = std.mem.eql(u8, s, "true");
        }
    }

    return SyncConfig{
        .enable = true,
        .group_name = group_name,
        .key_file = key_file,
        .port = port,
        .full_sync_interval = full_sync_interval,
        .multicast = multicast,
        .peers = peers,
        .config_sync = config_sync,
    };
}

fn parseMacClasses(allocator: std.mem.Allocator, list: anytype) ![]MacClass {
    var classes = try allocator.alloc(MacClass, list.len);
    var idx: usize = 0;
    errdefer {
        for (classes[0..idx]) |*mc| mc.deinit(allocator);
        allocator.free(classes);
    }
    for (list) |item| {
        const m = item.asMap() orelse continue;
        const name_str = if (m.get("name")) |v| (v.asScalar() orelse "") else "";
        const match_str = if (m.get("match")) |v| (v.asScalar() orelse "") else "";
        if (match_str.len == 0) {
            std.log.warn("config: mac_class missing 'match', skipping", .{});
            continue;
        }

        // --- dhcp_options map ---
        var opts = std.StringHashMap([]const u8).init(allocator);
        errdefer {
            var oit = opts.iterator();
            while (oit.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                allocator.free(entry.value_ptr.*);
            }
            opts.deinit();
        }
        if (m.get("dhcp_options")) |opts_val| {
            if (opts_val.asMap()) |opts_map| {
                var oit = opts_map.iterator();
                while (oit.next()) |entry| {
                    const k = try allocator.dupe(u8, entry.key_ptr.*);
                    errdefer allocator.free(k);
                    const v = try allocator.dupe(u8, entry.value_ptr.asScalar() orelse "");
                    errdefer allocator.free(v);
                    try opts.put(k, v);
                }
            }
        }

        // --- name + match ---
        const name_duped = try allocator.dupe(u8, name_str);
        errdefer allocator.free(name_duped);
        const match_duped = try allocator.dupe(u8, match_str);
        errdefer allocator.free(match_duped);

        // --- Optional scalar fields ---
        const mc_router: ?[]const u8 = if (m.get("router")) |v| blk: {
            if (v.asScalar()) |s| {
                if (s.len > 0) break :blk try allocator.dupe(u8, s);
            }
            break :blk null;
        } else null;
        errdefer if (mc_router) |r| allocator.free(r);

        const mc_domain_name: ?[]const u8 = if (m.get("domain_name")) |v| blk: {
            if (v.asScalar()) |s| {
                if (s.len > 0) break :blk try allocator.dupe(u8, s);
            }
            break :blk null;
        } else null;
        errdefer if (mc_domain_name) |d| allocator.free(d);

        const mc_boot_filename: ?[]const u8 = if (m.get("boot_filename")) |v| blk: {
            if (v.asScalar()) |s| {
                if (s.len > 0) break :blk try allocator.dupe(u8, s);
            }
            break :blk null;
        } else null;
        errdefer if (mc_boot_filename) |b| allocator.free(b);

        const mc_http_boot_url: ?[]const u8 = if (m.get("http_boot_url")) |v| blk: {
            if (v.asScalar()) |s| {
                if (s.len > 0) break :blk try allocator.dupe(u8, s);
            }
            break :blk null;
        } else null;
        errdefer if (mc_http_boot_url) |h| allocator.free(h);

        // --- Optional integer fields ---
        const mc_time_offset: ?i32 = if (m.get("time_offset")) |v| blk: {
            if (v.asScalar()) |s| break :blk std.fmt.parseInt(i32, s, 10) catch null;
            break :blk null;
        } else null;

        // --- String list fields ---
        const mc_domain_search = try parseMacClassStringList(allocator, m, "domain_search");
        errdefer {
            for (mc_domain_search) |s| allocator.free(s);
            if (mc_domain_search.len > 0) allocator.free(mc_domain_search);
        }
        const mc_dns_servers = try parseMacClassStringList(allocator, m, "dns_servers");
        errdefer {
            for (mc_dns_servers) |s| allocator.free(s);
            if (mc_dns_servers.len > 0) allocator.free(mc_dns_servers);
        }
        const mc_ntp_servers = try parseMacClassStringList(allocator, m, "ntp_servers");
        errdefer {
            for (mc_ntp_servers) |s| allocator.free(s);
            if (mc_ntp_servers.len > 0) allocator.free(mc_ntp_servers);
        }
        const mc_log_servers = try parseMacClassStringList(allocator, m, "log_servers");
        errdefer {
            for (mc_log_servers) |s| allocator.free(s);
            if (mc_log_servers.len > 0) allocator.free(mc_log_servers);
        }
        const mc_wins_servers = try parseMacClassStringList(allocator, m, "wins_servers");
        errdefer {
            for (mc_wins_servers) |s| allocator.free(s);
            if (mc_wins_servers.len > 0) allocator.free(mc_wins_servers);
        }
        const mc_tftp_servers = try parseMacClassStringList(allocator, m, "tftp_servers");
        errdefer {
            for (mc_tftp_servers) |s| allocator.free(s);
            if (mc_tftp_servers.len > 0) allocator.free(mc_tftp_servers);
        }

        // --- Static routes ---
        var mc_static_routes: []StaticRoute = &.{};
        errdefer if (mc_static_routes.len > 0) allocator.free(mc_static_routes);
        if (m.get("static_routes")) |sr_val| {
            if (sr_val.asList()) |sr_list| {
                var routes = std.ArrayListUnmanaged(StaticRoute){};
                errdefer routes.deinit(allocator);
                for (sr_list) |sr_item| {
                    const sr_map = sr_item.asMap() orelse continue;
                    const dest_val = sr_map.get("destination") orelse continue;
                    const rtr_val = sr_map.get("router") orelse continue;
                    const dest_str = dest_val.asScalar() orelse continue;
                    const rtr_str = rtr_val.asScalar() orelse continue;
                    const route = parseOneStaticRoute(dest_str, rtr_str) orelse continue;
                    try routes.append(allocator, route);
                }
                mc_static_routes = try routes.toOwnedSlice(allocator);
            }
        }

        classes[idx] = .{
            .name = name_duped,
            .match = match_duped,
            .router = mc_router,
            .domain_name = mc_domain_name,
            .domain_search = mc_domain_search,
            .dns_servers = mc_dns_servers,
            .ntp_servers = mc_ntp_servers,
            .log_servers = mc_log_servers,
            .wins_servers = mc_wins_servers,
            .time_offset = mc_time_offset,
            .tftp_servers = mc_tftp_servers,
            .boot_filename = mc_boot_filename,
            .http_boot_url = mc_http_boot_url,
            .static_routes = mc_static_routes,
            .dhcp_options = opts,
        };
        idx += 1;
    }
    return allocator.realloc(classes, idx) catch classes[0..idx];
}

/// Parse a string list from a mac_class map entry. Returns &.{} if not present.
fn parseMacClassStringList(allocator: std.mem.Allocator, m: anytype, key: []const u8) ![][]const u8 {
    const val = m.get(key) orelse return try allocator.alloc([]const u8, 0);
    const list = val.asList() orelse return try allocator.alloc([]const u8, 0);
    if (list.len == 0) return try allocator.alloc([]const u8, 0);
    const result = try allocator.alloc([]const u8, list.len);
    var count: usize = 0;
    errdefer {
        for (result[0..count]) |s| allocator.free(s);
        allocator.free(result);
    }
    for (list) |item| {
        const s = item.asScalar() orelse "";
        if (s.len > 0) {
            result[count] = try allocator.dupe(u8, s);
            count += 1;
        }
    }
    if (count == 0) {
        allocator.free(result);
        return try allocator.alloc([]const u8, 0);
    }
    return allocator.realloc(result, count) catch result[0..count];
}

/// Compute a SHA-256 pool hash over all pool configuration fields and their
/// per-pool MAC classes. Used by SyncManager to verify peer config compatibility.
pub fn computePoolHash(cfg: *const Config) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});

    // Hash pool count to distinguish configs with different numbers of pools.
    var pc_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &pc_bytes, @intCast(cfg.pools.len), .big);
    h.update(&pc_bytes);

    for (cfg.pools) |*pool| {
        hashPoolIntoSha256(&h, pool);
        // Hash per-pool MAC classes (sorted by name for determinism).
        hashMacClasses(&h, pool.mac_classes);
    }

    var digest: [32]u8 = undefined;
    h.final(&digest);
    return digest;
}

/// Compute a SHA-256 hash for a single pool (including its per-pool mac_classes).
/// Used by the per-pool sync protocol to identify individual pool configs.
pub fn computePerPoolHash(pool: *const PoolConfig) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    hashPoolIntoSha256(&h, pool);
    hashMacClasses(&h, pool.mac_classes);
    return h.finalResult();
}

const Sha256 = std.crypto.hash.sha2.Sha256;

/// Insertion-sort indices by comparing the strings they reference.
fn sortIndicesByString(indices: []usize, strings: []const []const u8) void {
    if (indices.len <= 1) return;
    for (1..indices.len) |i| {
        const key = indices[i];
        var j = i;
        while (j > 0 and std.mem.lessThan(u8, strings[key], strings[indices[j - 1]])) {
            indices[j] = indices[j - 1];
            j -= 1;
        }
        indices[j] = key;
    }
}

/// Hash a string slice in sorted (alphabetical) order. Uses a stack buffer for indices.
fn hashSortedStringList(h: *Sha256, list: []const []const u8) void {
    var idx_buf: [256]usize = undefined;
    const count = @min(list.len, idx_buf.len);
    for (0..count) |i| idx_buf[i] = i;
    sortIndicesByString(idx_buf[0..count], list);
    for (idx_buf[0..count]) |si| {
        h.update(list[si]);
    }
}

/// Hash a string list in config order (no sorting).
fn hashStringListOrdered(h: *Sha256, list: []const []const u8) void {
    for (list) |entry| {
        h.update(entry);
    }
}

/// Hash a StringHashMap([]const u8) with keys sorted alphabetically.
fn hashSortedStringMap(h: *Sha256, map: std.StringHashMap([]const u8)) void {
    var key_buf: [256][]const u8 = undefined;
    var ki: usize = 0;
    var it = map.iterator();
    while (it.next()) |entry| {
        if (ki < key_buf.len) {
            key_buf[ki] = entry.key_ptr.*;
            ki += 1;
        }
    }
    // Insertion sort the keys.
    if (ki > 1) for (1..ki) |i| {
        const key = key_buf[i];
        var j = i;
        while (j > 0 and std.mem.lessThan(u8, key, key_buf[j - 1])) {
            key_buf[j] = key_buf[j - 1];
            j -= 1;
        }
        key_buf[j] = key;
    };
    for (key_buf[0..ki]) |k| {
        h.update(k);
        h.update(map.get(k).?);
    }
}

/// Hash an optional nullable string with a marker byte (0x00 for null, 0x01 + bytes for set).
fn hashOptionalString(h: *Sha256, val: ?[]const u8) void {
    if (val) |v| {
        h.update(&[1]u8{0x01});
        h.update(v);
    } else {
        h.update(&[1]u8{0x00});
    }
}

/// Hash per-pool MAC classes sorted by name.
fn hashMacClasses(h: *Sha256, classes: []const MacClass) void {
    var mc_count: [4]u8 = undefined;
    std.mem.writeInt(u32, &mc_count, @intCast(classes.len), .big);
    h.update(&mc_count);

    var idx_buf: [256]usize = undefined;
    const count = @min(classes.len, idx_buf.len);
    for (0..count) |i| idx_buf[i] = i;
    // Insertion sort by name.
    if (count > 1) for (1..count) |i| {
        const key = idx_buf[i];
        var j = i;
        while (j > 0 and std.mem.lessThan(u8, classes[key].name, classes[idx_buf[j - 1]].name)) {
            idx_buf[j] = idx_buf[j - 1];
            j -= 1;
        }
        idx_buf[j] = key;
    };
    for (idx_buf[0..count]) |ci| {
        const mc = &classes[ci];
        h.update(mc.name);
        h.update(mc.match);
        // First-class scalar fields
        hashOptionalString(h, mc.router);
        hashOptionalString(h, mc.domain_name);
        hashOptionalString(h, mc.boot_filename);
        hashOptionalString(h, mc.http_boot_url);
        // time_offset: nullable i32, marker byte + big-endian value
        if (mc.time_offset) |to| {
            h.update(&[1]u8{0x01});
            var to_bytes: [4]u8 = undefined;
            std.mem.writeInt(i32, &to_bytes, to, .big);
            h.update(&to_bytes);
        } else {
            h.update(&[1]u8{0x00});
        }
        // String list fields (sorted)
        hashSortedStringList(h, mc.domain_search);
        hashSortedStringList(h, mc.dns_servers);
        hashSortedStringList(h, mc.ntp_servers);
        hashSortedStringList(h, mc.log_servers);
        hashSortedStringList(h, mc.wins_servers);
        // TFTP servers: order matters, do NOT sort (same as pool level).
        hashStringListOrdered(h, mc.tftp_servers);
        // Static routes (sorted by destination)
        hashStaticRoutes(h, mc.static_routes);
        // dhcp_options map (sorted by key)
        hashSortedStringMap(h, mc.dhcp_options);
    }
}

/// Hash a slice of StaticRoute sorted by destination address.
fn hashStaticRoutes(h: *Sha256, routes: []const StaticRoute) void {
    var src_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &src_bytes, @intCast(routes.len), .big);
    h.update(&src_bytes);

    var sr_indices: [256]usize = undefined;
    const sr_count = @min(routes.len, sr_indices.len);
    for (0..sr_count) |i| sr_indices[i] = i;
    if (sr_count > 1) for (1..sr_count) |i| {
        const key = sr_indices[i];
        var j = i;
        while (j > 0) {
            const a = &routes[key];
            const b2 = &routes[sr_indices[j - 1]];
            const dest_a = std.mem.readInt(u32, &a.destination, .big);
            const dest_b = std.mem.readInt(u32, &b2.destination, .big);
            if (dest_a >= dest_b) break;
            sr_indices[j] = sr_indices[j - 1];
            j -= 1;
        }
        sr_indices[j] = key;
    };
    for (sr_indices[0..sr_count]) |sri| {
        const r = &routes[sri];
        h.update(&r.destination);
        h.update(&[1]u8{r.prefix_len});
        h.update(&r.router);
    }
}

fn hashPoolIntoSha256(h: *Sha256, pool: *const PoolConfig) void {
    // -- Structural / addressing fields --
    const subnet_bytes = parseIpv4(pool.subnet) catch [4]u8{ 0, 0, 0, 0 };
    h.update(&subnet_bytes);

    var mask_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &mask_bytes, pool.subnet_mask, .big);
    h.update(&mask_bytes);

    const pool_start_bytes = if (pool.pool_start.len > 0)
        parseIpv4(pool.pool_start) catch [4]u8{ 0, 0, 0, 0 }
    else blk: {
        const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
        var b: [4]u8 = undefined;
        // Degenerate /32 of 255.255.255.255 has no usable range; use subnet itself.
        const start = if (subnet_int == std.math.maxInt(u32)) subnet_int else subnet_int + 1;
        std.mem.writeInt(u32, &b, start, .big);
        break :blk b;
    };
    h.update(&pool_start_bytes);

    const pool_end_bytes = if (pool.pool_end.len > 0)
        parseIpv4(pool.pool_end) catch [4]u8{ 255, 255, 255, 255 }
    else blk: {
        const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
        const broadcast_int = subnet_int | ~pool.subnet_mask;
        var b: [4]u8 = undefined;
        // Degenerate /32 of 0.0.0.0 has no usable range; use broadcast itself.
        const end = if (broadcast_int == 0) broadcast_int else broadcast_int - 1;
        std.mem.writeInt(u32, &b, end, .big);
        break :blk b;
    };
    h.update(&pool_end_bytes);

    var lt_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &lt_bytes, pool.lease_time, .big);
    h.update(&lt_bytes);

    // -- Scalar fields --
    h.update(pool.domain_name);
    h.update(pool.boot_filename);
    h.update(pool.http_boot_url);

    // time_offset: nullable i32, marker byte + big-endian value
    if (pool.time_offset) |to| {
        h.update(&[1]u8{0x01});
        var to_bytes: [4]u8 = undefined;
        std.mem.writeInt(i32, &to_bytes, to, .big);
        h.update(&to_bytes);
    } else {
        h.update(&[1]u8{0x00});
    }

    // mtu: nullable u16, marker byte + big-endian value
    if (pool.mtu) |mtu| {
        h.update(&[1]u8{0x01});
        var mtu_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &mtu_bytes, mtu, .big);
        h.update(&mtu_bytes);
    } else {
        h.update(&[1]u8{0x00});
    }

    // -- String list fields (sorted alphabetically) --
    hashSortedStringList(h, pool.dns_servers);
    hashSortedStringList(h, pool.domain_search);
    hashSortedStringList(h, pool.time_servers);
    hashSortedStringList(h, pool.log_servers);
    hashSortedStringList(h, pool.ntp_servers);
    hashSortedStringList(h, pool.wins_servers);

    // TFTP servers: order matters, do NOT sort.
    hashStringListOrdered(h, pool.tftp_servers);

    // -- DNS Update config --
    h.update(&[1]u8{@intFromBool(pool.dns_update.enable)});
    h.update(pool.dns_update.server);
    h.update(pool.dns_update.zone);
    h.update(pool.dns_update.key_name);
    h.update(pool.dns_update.key_file);
    var dns_lt_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &dns_lt_bytes, pool.dns_update.lease_time, .big);
    h.update(&dns_lt_bytes);

    // -- Pool-level DHCP options (sorted by key) --
    hashSortedStringMap(h, pool.dhcp_options);

    // -- Reservations (sorted by MAC) --
    var rc_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &rc_bytes, @intCast(pool.reservations.len), .big);
    h.update(&rc_bytes);

    var res_indices: [256]usize = undefined;
    const res_count = @min(pool.reservations.len, res_indices.len);
    for (0..res_count) |i| res_indices[i] = i;
    // res_count == 0: for (1..0) underflows usize; guard is required.
    if (res_count > 0) for (1..res_count) |i| {
        const key = res_indices[i];
        var j = i;
        while (j > 0 and std.mem.lessThan(u8, pool.reservations[key].mac, pool.reservations[res_indices[j - 1]].mac)) {
            res_indices[j] = res_indices[j - 1];
            j -= 1;
        }
        res_indices[j] = key;
    };
    for (res_indices[0..res_count]) |ri| {
        const r = &pool.reservations[ri];
        var mac_bytes: [6]u8 = [_]u8{0} ** 6;
        var bi: usize = 0;
        var pos: usize = 0;
        while (bi < 6 and pos + 1 < r.mac.len) : (bi += 1) {
            const hi_nib = std.fmt.charToDigit(r.mac[pos], 16) catch 0;
            const lo_nib = std.fmt.charToDigit(r.mac[pos + 1], 16) catch 0;
            mac_bytes[bi] = (hi_nib << 4) | lo_nib;
            pos += 3;
        }
        h.update(&mac_bytes);
        const ip_bytes = parseIpv4(r.ip) catch [4]u8{ 0, 0, 0, 0 };
        h.update(&ip_bytes);
        // Reservation hostname and client_id
        hashOptionalString(h, r.hostname);
        hashOptionalString(h, r.client_id);
        // Reservation DHCP options (sorted by key)
        if (r.dhcp_options) |opts| {
            h.update(&[1]u8{0x01});
            hashSortedStringMap(h, opts);
        } else {
            h.update(&[1]u8{0x00});
        }
    }

    // -- Static routes (sorted by destination) --
    var src_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &src_bytes, @intCast(pool.static_routes.len), .big);
    h.update(&src_bytes);

    var sr_indices: [256]usize = undefined;
    const sr_count = @min(pool.static_routes.len, sr_indices.len);
    for (0..sr_count) |i| sr_indices[i] = i;
    // sr_count == 0: for (1..0) underflows usize; guard is required.
    if (sr_count > 0) for (1..sr_count) |i| {
        const key = sr_indices[i];
        var j = i;
        while (j > 0) {
            const a = &pool.static_routes[key];
            const b2 = &pool.static_routes[sr_indices[j - 1]];
            const dest_a = std.mem.readInt(u32, &a.destination, .big);
            const dest_b = std.mem.readInt(u32, &b2.destination, .big);
            if (dest_a >= dest_b) break;
            sr_indices[j] = sr_indices[j - 1];
            j -= 1;
        }
        sr_indices[j] = key;
    };
    for (sr_indices[0..sr_count]) |sri| {
        const r = &pool.static_routes[sri];
        h.update(&r.destination);
        h.update(&[1]u8{r.prefix_len});
        h.update(&r.router);
    }
}

/// Log warnings when pool_start/pool_end are misconfigured. Does not fail load().
// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Check whether a string is a valid domain name: starts with a letter or
/// digit, contains only a-z 0-9 . - _ (lowercase).
fn isValidDomainName(val: []const u8) bool {
    if (val.len == 0) return false;
    const first = val[0];
    if (!((first >= 'a' and first <= 'z') or (first >= '0' and first <= '9'))) return false;
    for (val) |ch| {
        if (!((ch >= 'a' and ch <= 'z') or (ch >= '0' and ch <= '9') or ch == '.' or ch == '-' or ch == '_')) return false;
    }
    return true;
}

/// Check whether a string is a valid IPv4 address or a valid domain name.
fn isValidIpOrDomain(val: []const u8) bool {
    if (val.len == 0) return false;
    if (parseIpv4(val)) |_| return true else |_| {}
    return isValidDomainName(val);
}

/// Check whether a string contains only valid file path characters:
/// a-z A-Z 0-9 . _ - / + =
fn isValidFilePath(val: []const u8) bool {
    if (val.len == 0) return false;
    for (val) |ch| {
        if (!((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or
            ch == '.' or ch == '_' or ch == '-' or ch == '/' or ch == '+' or ch == '=')) return false;
    }
    return true;
}

/// Auto-lowercase a mutable allocator-owned string in-place.
fn lowercaseInPlace(s: []u8) void {
    for (s) |*ch| {
        if (ch.* >= 'A' and ch.* <= 'Z') ch.* = ch.* - 'A' + 'a';
    }
}

/// Validate all pool fields after parsing. Returns true if the pool is valid
/// (possibly with corrected values), false if the pool must be skipped.
fn validatePoolFields(allocator: std.mem.Allocator, pool: *PoolConfig) bool {
    const subnet_bytes = parseIpv4(pool.subnet) catch return false;
    const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);

    // --- Strict checks (skip pool on failure) ---

    // Router: required, valid IPv4, inside subnet.
    if (pool.router.len == 0) {
        std.log.err("config: pool {s}/{d}: router is required, skipping pool", .{ pool.subnet, pool.prefix_len });
        return false;
    }
    const router_ip = parseIpv4(pool.router) catch {
        std.log.err("config: pool {s}/{d}: router '{s}' is not a valid IPv4 address, skipping pool", .{
            pool.subnet, pool.prefix_len, pool.router,
        });
        return false;
    };
    {
        const r_int = std.mem.readInt(u32, &router_ip, .big);
        if (r_int & pool.subnet_mask != subnet_int & pool.subnet_mask) {
            std.log.err("config: pool {s}/{d}: router {s} is not inside the subnet, skipping pool", .{
                pool.subnet, pool.prefix_len, pool.router,
            });
            return false;
        }
        // Reject router at the network or broadcast address (except /32 where there is only one address).
        if (pool.subnet_mask != 0xFFFFFFFF) {
            const broadcast_r = subnet_int | ~pool.subnet_mask;
            if (r_int == subnet_int) {
                std.log.err("config: pool {s}/{d}: router {s} is the network address, skipping pool", .{
                    pool.subnet, pool.prefix_len, pool.router,
                });
                return false;
            }
            if (r_int == broadcast_r) {
                std.log.err("config: pool {s}/{d}: router {s} is the broadcast address, skipping pool", .{
                    pool.subnet, pool.prefix_len, pool.router,
                });
                return false;
            }
        }
    }

    // Lease time: required, > 0, max 1,209,600.
    if (pool.lease_time == 0) {
        std.log.err("config: pool {s}/{d}: lease_time must be > 0, skipping pool", .{ pool.subnet, pool.prefix_len });
        return false;
    }
    if (pool.lease_time > 1_209_600) {
        std.log.err("config: pool {s}/{d}: lease_time {d} exceeds maximum 1209600 (2 weeks), skipping pool", .{
            pool.subnet, pool.prefix_len, pool.lease_time,
        });
        return false;
    }

    // --- Warn-and-fix checks ---

    const broadcast_int = subnet_int | ~pool.subnet_mask;
    // Guard degenerate subnets.
    const has_host_range = subnet_int != std.math.maxInt(u32) and broadcast_int != 0;
    const valid_start: u32 = if (has_host_range) subnet_int + 1 else subnet_int;
    const valid_end: u32 = if (has_host_range) broadcast_int - 1 else broadcast_int;

    // Pool start: if set, must be valid IPv4 inside subnet.
    var ps_int_opt: ?u32 = null;
    if (pool.pool_start.len > 0) {
        const ps_valid = blk: {
            const ps_ip = parseIpv4(pool.pool_start) catch break :blk false;
            const ps_int = std.mem.readInt(u32, &ps_ip, .big);
            if (ps_int < valid_start or ps_int > valid_end) break :blk false;
            ps_int_opt = ps_int;
            break :blk true;
        };
        if (!ps_valid) {
            std.log.err("config: pool {s}/{d}: pool_start '{s}' is invalid or outside subnet, skipping pool", .{
                pool.subnet, pool.prefix_len, pool.pool_start,
            });
            return false;
        }
    }

    // Pool end: if set, must be valid IPv4 inside subnet.
    var pe_int_opt: ?u32 = null;
    if (pool.pool_end.len > 0) {
        const pe_valid = blk: {
            const pe_ip = parseIpv4(pool.pool_end) catch break :blk false;
            const pe_int = std.mem.readInt(u32, &pe_ip, .big);
            if (pe_int < valid_start or pe_int > valid_end) break :blk false;
            pe_int_opt = pe_int;
            break :blk true;
        };
        if (!pe_valid) {
            std.log.err("config: pool {s}/{d}: pool_end '{s}' is invalid or outside subnet, skipping pool", .{
                pool.subnet, pool.prefix_len, pool.pool_end,
            });
            return false;
        }
    }

    // If both set, start must be <= end.
    if (ps_int_opt != null and pe_int_opt != null) {
        if (ps_int_opt.? > pe_int_opt.?) {
            std.log.err("config: pool {s}/{d}: pool_start {s} > pool_end {s}, skipping pool", .{
                pool.subnet, pool.prefix_len, pool.pool_start, pool.pool_end,
            });
            return false;
        }
    }

    // MTU: if set, must be 68-65535.
    if (pool.mtu) |mtu| {
        if (mtu < 68) {
            std.log.warn("config: pool {s}/{d}: mtu {d} is below minimum 68, clearing", .{
                pool.subnet, pool.prefix_len, mtu,
            });
            pool.mtu = null;
        }
    }

    // Domain name: auto-lowercase, validate.
    if (pool.domain_name.len > 0) {
        lowercaseInPlace(@constCast(pool.domain_name));
        if (!isValidDomainName(pool.domain_name)) {
            std.log.warn("config: pool {s}/{d}: domain_name '{s}' is invalid, clearing", .{
                pool.subnet, pool.prefix_len, pool.domain_name,
            });
            allocator.free(pool.domain_name);
            pool.domain_name = allocator.dupe(u8, "") catch return false;
        }
    }

    // Domain search: validate each entry, skip invalid, auto-lowercase.
    if (pool.domain_search.len > 0) {
        var valid_count: usize = 0;
        for (pool.domain_search) |*entry| {
            lowercaseInPlace(@constCast(entry.*));
            if (isValidDomainName(entry.*)) {
                valid_count += 1;
            } else {
                std.log.warn("config: pool {s}/{d}: domain_search entry '{s}' is invalid, skipping", .{
                    pool.subnet, pool.prefix_len, entry.*,
                });
            }
        }
        if (valid_count != pool.domain_search.len) {
            const new = allocator.alloc([]const u8, valid_count) catch return false;
            var idx: usize = 0;
            for (pool.domain_search) |entry| {
                if (isValidDomainName(entry)) {
                    new[idx] = entry;
                    idx += 1;
                } else {
                    allocator.free(entry);
                }
            }
            allocator.free(pool.domain_search);
            pool.domain_search = new;
        }
    }

    // DNS servers: valid IP or domain, max 8.
    validateAndTrimServerList(allocator, &pool.dns_servers, 8, "dns_servers", pool.subnet, pool.prefix_len);

    // NTP servers: valid IP or domain, max 4.
    validateAndTrimServerList(allocator, &pool.ntp_servers, 4, "ntp_servers", pool.subnet, pool.prefix_len);

    // Log servers: valid IP or domain, max 4.
    validateAndTrimServerList(allocator, &pool.log_servers, 4, "log_servers", pool.subnet, pool.prefix_len);

    // WINS servers: valid IP or domain, max 2.
    validateAndTrimServerList(allocator, &pool.wins_servers, 2, "wins_servers", pool.subnet, pool.prefix_len);

    // TFTP servers: valid IP or domain, max 4.
    validateAndTrimServerList(allocator, &pool.tftp_servers, 4, "tftp_servers", pool.subnet, pool.prefix_len);

    // Time servers: valid IP or domain, max 4.
    validateAndTrimServerList(allocator, &pool.time_servers, 4, "time_servers", pool.subnet, pool.prefix_len);

    // Boot filename: valid file path chars.
    if (pool.boot_filename.len > 0) {
        if (!isValidFilePath(pool.boot_filename)) {
            std.log.warn("config: pool {s}/{d}: boot_filename '{s}' has invalid characters, clearing", .{
                pool.subnet, pool.prefix_len, pool.boot_filename,
            });
            allocator.free(pool.boot_filename);
            pool.boot_filename = allocator.dupe(u8, "") catch return false;
        }
    }

    // HTTP Boot URL: must start with http:// or https://, valid hostname.
    if (pool.http_boot_url.len > 0) {
        const url = pool.http_boot_url;
        const has_https = std.mem.startsWith(u8, url, "https://");
        const has_http = std.mem.startsWith(u8, url, "http://");
        const url_valid = blk: {
            if (!has_https and !has_http) break :blk false;
            const after_scheme = if (has_https) url[8..] else url[7..];
            if (after_scheme.len == 0) break :blk false;
            const host_end = std.mem.indexOfScalar(u8, after_scheme, '/') orelse after_scheme.len;
            const hostname = after_scheme[0..host_end];
            if (hostname.len == 0) break :blk false;
            if (!((hostname[0] >= 'a' and hostname[0] <= 'z') or (hostname[0] >= 'A' and hostname[0] <= 'Z') or
                (hostname[0] >= '0' and hostname[0] <= '9')))
                break :blk false;
            for (hostname) |ch| {
                if (!((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or
                    ch == '.' or ch == '-' or ch == ':'))
                    break :blk false;
            }
            break :blk true;
        };
        if (!url_valid) {
            std.log.warn("config: pool {s}/{d}: http_boot_url '{s}' is invalid, clearing", .{
                pool.subnet, pool.prefix_len, pool.http_boot_url,
            });
            allocator.free(pool.http_boot_url);
            pool.http_boot_url = allocator.dupe(u8, "") catch return false;
        }
    }

    // DNS Update fields.
    if (pool.dns_update.server.len > 0) {
        if (!isValidIpOrDomain(pool.dns_update.server)) {
            std.log.warn("config: pool {s}/{d}: dns_update.server '{s}' is invalid, clearing", .{
                pool.subnet, pool.prefix_len, pool.dns_update.server,
            });
            allocator.free(pool.dns_update.server);
            pool.dns_update.server = allocator.dupe(u8, "") catch return false;
        }
    }
    if (pool.dns_update.zone.len > 0) {
        lowercaseInPlace(@constCast(pool.dns_update.zone));
        if (!isValidDomainName(pool.dns_update.zone)) {
            std.log.warn("config: pool {s}/{d}: dns_update.zone '{s}' is invalid, clearing", .{
                pool.subnet, pool.prefix_len, pool.dns_update.zone,
            });
            allocator.free(pool.dns_update.zone);
            pool.dns_update.zone = allocator.dupe(u8, "") catch return false;
        }
    }
    if (pool.dns_update.key_name.len > 0) {
        const kn = pool.dns_update.key_name;
        const kn_valid = blk: {
            const first = kn[0];
            if (!((first >= 'a' and first <= 'z') or (first >= 'A' and first <= 'Z') or (first >= '0' and first <= '9')))
                break :blk false;
            for (kn) |ch| {
                if (!((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or
                    ch == '_' or ch == '-'))
                    break :blk false;
            }
            break :blk true;
        };
        if (!kn_valid) {
            std.log.warn("config: pool {s}/{d}: dns_update.key_name '{s}' is invalid, clearing", .{
                pool.subnet, pool.prefix_len, pool.dns_update.key_name,
            });
            allocator.free(pool.dns_update.key_name);
            pool.dns_update.key_name = allocator.dupe(u8, "") catch return false;
        }
    }
    if (pool.dns_update.key_file.len > 0) {
        if (!isValidFilePath(pool.dns_update.key_file)) {
            std.log.warn("config: pool {s}/{d}: dns_update.key_file '{s}' has invalid characters, clearing", .{
                pool.subnet, pool.prefix_len, pool.dns_update.key_file,
            });
            allocator.free(pool.dns_update.key_file);
            pool.dns_update.key_file = allocator.dupe(u8, "") catch return false;
        }
    }

    return true;
}

/// Validate entries in a server list (must be valid IP or domain name),
/// remove invalid entries, and trim to max_count with warnings.
fn validateAndTrimServerList(
    allocator: std.mem.Allocator,
    list: *[][]const u8,
    max_count: usize,
    field_name: []const u8,
    subnet: []const u8,
    prefix_len: u8,
) void {
    // First pass: filter out invalid entries.
    var valid_count: usize = 0;
    for (list.*) |entry| {
        if (isValidIpOrDomain(entry)) {
            valid_count += 1;
        } else {
            std.log.warn("config: pool {s}/{d}: {s} entry '{s}' is not a valid IP or domain, skipping", .{
                subnet, prefix_len, field_name, entry,
            });
        }
    }

    if (valid_count != list.len) {
        const trimmed = max_count;
        const keep = if (valid_count > trimmed) trimmed else valid_count;
        const new = allocator.alloc([]const u8, keep) catch return;
        var idx: usize = 0;
        for (list.*) |entry| {
            if (isValidIpOrDomain(entry)) {
                if (idx < keep) {
                    new[idx] = entry;
                    idx += 1;
                } else {
                    allocator.free(entry);
                }
            } else {
                allocator.free(entry);
            }
        }
        if (valid_count > max_count) {
            std.log.warn("config: pool {s}/{d}: {s} has {d} entries, trimming to max {d}", .{
                subnet, prefix_len, field_name, valid_count, max_count,
            });
        }
        allocator.free(list.*);
        list.* = new;
        return;
    }

    // All valid — just check max count.
    if (list.len > max_count) {
        std.log.warn("config: pool {s}/{d}: {s} has {d} entries, trimming to max {d}", .{
            subnet, prefix_len, field_name, list.len, max_count,
        });
        const new = allocator.alloc([]const u8, max_count) catch return;
        for (list.*[0..max_count], 0..) |entry, i| {
            new[i] = entry;
        }
        // Free the excess entries.
        for (list.*[max_count..]) |entry| {
            allocator.free(entry);
        }
        allocator.free(list.*);
        list.* = new;
    }
}

fn parseLogLevel(s: []const u8) LogLevel {
    if (std.mem.eql(u8, s, "debug")) return .debug;
    if (std.mem.eql(u8, s, "verbose")) return .verbose;
    if (std.mem.eql(u8, s, "warn") or std.mem.eql(u8, s, "warning")) return .warn;
    if (std.mem.eql(u8, s, "error") or std.mem.eql(u8, s, "err")) return .err;
    return .info;
}

/// Derive the in-addr.arpa reverse zone name from a subnet.
/// Uses classful octet boundaries: /1–8 → 1 octet, /9–16 → 2 octets, /17–32 → 3 octets.
/// Sub-/24 delegations (RFC 2317) are not supported; they use the /24 boundary.
fn reverseZoneForSubnet(allocator: std.mem.Allocator, ip: [4]u8, prefix_len: u8) ![]u8 {
    return if (prefix_len <= 8)
        std.fmt.allocPrint(allocator, "{d}.in-addr.arpa", .{ip[0]})
    else if (prefix_len <= 16)
        std.fmt.allocPrint(allocator, "{d}.{d}.in-addr.arpa", .{ ip[1], ip[0] })
    else
        std.fmt.allocPrint(allocator, "{d}.{d}.{d}.in-addr.arpa", .{ ip[2], ip[1], ip[0] });
}

/// Parse a CIDR notation string (e.g. "192.168.1.0/24") into a network address,
/// mask, and prefix length. The host bits are masked to zero.
pub fn parseCidr(s: []const u8) !struct { ip: [4]u8, mask: u32, prefix_len: u8 } {
    const slash = std.mem.indexOfScalar(u8, s, '/') orelse return error.InvalidConfig;
    const raw_ip = try parseIpv4(s[0..slash]);
    const prefix = std.fmt.parseInt(u8, s[slash + 1 ..], 10) catch return error.InvalidConfig;
    if (prefix > 32) return error.InvalidConfig;
    const mask: u32 = if (prefix == 0) 0 else @as(u32, 0xFFFFFFFF) << @intCast(32 - prefix);
    // Mask to network address
    const ip_int = std.mem.readInt(u32, &raw_ip, .big);
    const net_int = ip_int & mask;
    var net_ip: [4]u8 = undefined;
    std.mem.writeInt(u32, &net_ip, net_int, .big);
    return .{ .ip = net_ip, .mask = mask, .prefix_len = prefix };
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
    // Reject trailing dot (e.g. "192.168.1.") — the last octet would be implicitly 0.
    if (s.len > 0 and s[s.len - 1] == '.') return error.InvalidConfig;
    result[idx] = @intCast(octet);
    return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
    try std.testing.expectEqual(LogLevel.debug, parseLogLevel("debug"));
    try std.testing.expectEqual(LogLevel.verbose, parseLogLevel("verbose"));
    try std.testing.expectEqual(LogLevel.warn, parseLogLevel("warn"));
    try std.testing.expectEqual(LogLevel.warn, parseLogLevel("warning"));
    try std.testing.expectEqual(LogLevel.err, parseLogLevel("error"));
    try std.testing.expectEqual(LogLevel.info, parseLogLevel("info"));
    try std.testing.expectEqual(LogLevel.info, parseLogLevel("unknown"));
}

test "reverseZoneForSubnet: /24 produces 3-octet zone" {
    const zone = try reverseZoneForSubnet(std.testing.allocator, .{ 192, 168, 1, 0 }, 24);
    defer std.testing.allocator.free(zone);
    try std.testing.expectEqualStrings("1.168.192.in-addr.arpa", zone);
}

test "reverseZoneForSubnet: /16 produces 2-octet zone" {
    const zone = try reverseZoneForSubnet(std.testing.allocator, .{ 192, 168, 0, 0 }, 16);
    defer std.testing.allocator.free(zone);
    try std.testing.expectEqualStrings("168.192.in-addr.arpa", zone);
}

test "reverseZoneForSubnet: /8 produces 1-octet zone" {
    const zone = try reverseZoneForSubnet(std.testing.allocator, .{ 10, 0, 0, 0 }, 8);
    defer std.testing.allocator.free(zone);
    try std.testing.expectEqualStrings("10.in-addr.arpa", zone);
}

test "reverseZoneForSubnet: prefix > 24 uses 3-octet boundary" {
    const zone = try reverseZoneForSubnet(std.testing.allocator, .{ 10, 0, 2, 0 }, 25);
    defer std.testing.allocator.free(zone);
    try std.testing.expectEqualStrings("2.0.10.in-addr.arpa", zone);
}

test "parseStaticRoutes: CIDR destination parsed and masked" {
    const r = parseOneStaticRoute("10.10.10.5/24", "192.168.1.1");
    try std.testing.expect(r != null);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 10, 10, 0 }, &r.?.destination);
    try std.testing.expectEqual(@as(u8, 24), r.?.prefix_len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 1 }, &r.?.router);
}

test "parseStaticRoutes: plain IP = /32 host route" {
    const r = parseOneStaticRoute("10.10.10.1", "192.168.1.254");
    try std.testing.expect(r != null);
    try std.testing.expectEqual(@as(u8, 32), r.?.prefix_len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 10, 10, 1 }, &r.?.destination);
}

test "parseStaticRoutes: /0 default route is rejected" {
    const r = parseOneStaticRoute("0.0.0.0/0", "192.168.1.1");
    try std.testing.expect(r == null);
}

test "parseIpv4: empty string rejected" {
    try std.testing.expectError(error.InvalidConfig, parseIpv4(""));
}

test "parseIpv4: too many octets rejected" {
    try std.testing.expectError(error.InvalidConfig, parseIpv4("1.2.3.4.5"));
}

test "parseIpv4: trailing dot rejected" {
    try std.testing.expectError(error.InvalidConfig, parseIpv4("192.168.1."));
}

test "parseIpv4: leading dot rejected" {
    try std.testing.expectError(error.InvalidConfig, parseIpv4(".192.168.1.1"));
}

test "parseStaticRoutes: invalid destination IP is skipped" {
    const r = parseOneStaticRoute("not.an.ip/24", "192.168.1.1");
    try std.testing.expect(r == null);
}

test "parseStaticRoutes: invalid router IP is skipped" {
    const r = parseOneStaticRoute("10.0.0.0/8", "not.a.router");
    try std.testing.expect(r == null);
}

test "parseStaticRoutes: prefix_len > 32 is rejected" {
    const r = parseOneStaticRoute("10.0.0.0/33", "192.168.1.1");
    try std.testing.expect(r == null);
}

test "parseCidr: basic /24" {
    const r = try parseCidr("192.168.1.0/24");
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 0 }, &r.ip);
    try std.testing.expectEqual(@as(u32, 0xFFFFFF00), r.mask);
    try std.testing.expectEqual(@as(u8, 24), r.prefix_len);
}

test "parseCidr: host bits masked to zero" {
    // 192.168.1.100/24 → network = 192.168.1.0
    const r = try parseCidr("192.168.1.100/24");
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 0 }, &r.ip);
}

test "parseCidr: /16" {
    const r = try parseCidr("10.0.0.0/16");
    try std.testing.expectEqualSlices(u8, &[4]u8{ 10, 0, 0, 0 }, &r.ip);
    try std.testing.expectEqual(@as(u32, 0xFFFF0000), r.mask);
    try std.testing.expectEqual(@as(u8, 16), r.prefix_len);
}

test "parseCidr: /32 host route" {
    const r = try parseCidr("10.1.2.3/32");
    try std.testing.expectEqualSlices(u8, &[4]u8{ 10, 1, 2, 3 }, &r.ip);
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), r.mask);
}

test "parseCidr: /0 all-hosts" {
    const r = try parseCidr("0.0.0.0/0");
    try std.testing.expectEqual(@as(u32, 0), r.mask);
    try std.testing.expectEqual(@as(u8, 0), r.prefix_len);
}

test "parseCidr: prefix > 32 rejected" {
    try std.testing.expectError(error.InvalidConfig, parseCidr("10.0.0.0/33"));
}

test "parseCidr: no slash rejected" {
    try std.testing.expectError(error.InvalidConfig, parseCidr("192.168.1.0"));
}

test "parseCidr: bad IP rejected" {
    try std.testing.expectError(error.InvalidConfig, parseCidr("bad.ip/24"));
}

// ---------------------------------------------------------------------------
// computePoolHash tests
// ---------------------------------------------------------------------------

/// Build a minimal Config with one pool suitable for pool-hash tests.
fn makeHashTestConfig(alloc: std.mem.Allocator) Config {
    const pools = alloc.alloc(PoolConfig, 1) catch unreachable;
    pools[0] = PoolConfig{
        .subnet = alloc.dupe(u8, "192.168.1.0") catch unreachable,
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = alloc.dupe(u8, "192.168.1.1") catch unreachable,
        .pool_start = alloc.dupe(u8, "192.168.1.10") catch unreachable,
        .pool_end = alloc.dupe(u8, "192.168.1.200") catch unreachable,
        .dns_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .domain_name = alloc.dupe(u8, "") catch unreachable,
        .domain_search = alloc.alloc([]const u8, 0) catch unreachable,
        .lease_time = 3600,
        .time_offset = null,
        .time_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .log_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .ntp_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .mtu = null,
        .wins_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .tftp_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .boot_filename = alloc.dupe(u8, "") catch unreachable,
        .http_boot_url = alloc.dupe(u8, "") catch unreachable,
        .dns_update = .{
            .enable = false,
            .server = alloc.dupe(u8, "") catch unreachable,
            .zone = alloc.dupe(u8, "") catch unreachable,
            .rev_zone = alloc.dupe(u8, "") catch unreachable,
            .key_name = alloc.dupe(u8, "") catch unreachable,
            .key_file = alloc.dupe(u8, "") catch unreachable,
            .lease_time = 3600,
        },
        .dhcp_options = std.StringHashMap([]const u8).init(alloc),
        .reservations = alloc.alloc(Reservation, 0) catch unreachable,
        .static_routes = alloc.alloc(StaticRoute, 0) catch unreachable,
    };
    return Config{
        .allocator = alloc,
        .listen_address = alloc.dupe(u8, "0.0.0.0") catch unreachable,
        .state_dir = alloc.dupe(u8, "/tmp") catch unreachable,
        .log_level = .info,
        .pool_allocation_random = false,
        .sync = null,
        .pools = pools,
        .admin_ssh = .{ .enable = false, .port = 2267, .bind = alloc.dupe(u8, "0.0.0.0") catch unreachable, .read_only = false, .host_key = alloc.dupe(u8, "") catch unreachable, .authorized_keys = alloc.dupe(u8, "") catch unreachable },
        .metrics = .{ .collect = false, .http_enable = false, .http_port = 9167, .http_bind = alloc.dupe(u8, "127.0.0.1") catch unreachable },
    };
}

test "computePoolHash: identical configs hash identically" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    try std.testing.expectEqualSlices(u8, &computePoolHash(&c1), &computePoolHash(&c2));
}

test "computePoolHash: different subnet produces different hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    alloc.free(c2.pools[0].subnet);
    c2.pools[0].subnet = try alloc.dupe(u8, "10.0.0.0");

    try std.testing.expect(!std.mem.eql(u8, &computePoolHash(&c1), &computePoolHash(&c2)));
}

test "computePoolHash: different subnet_mask produces different hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    c2.pools[0].subnet_mask = 0xFFFF0000;

    try std.testing.expect(!std.mem.eql(u8, &computePoolHash(&c1), &computePoolHash(&c2)));
}

test "computePoolHash: different pool_end produces different hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    alloc.free(c2.pools[0].pool_end);
    c2.pools[0].pool_end = try alloc.dupe(u8, "192.168.1.150");

    try std.testing.expect(!std.mem.eql(u8, &computePoolHash(&c1), &computePoolHash(&c2)));
}

test "computePoolHash: different lease_time produces different hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    c2.pools[0].lease_time = 7200;

    try std.testing.expect(!std.mem.eql(u8, &computePoolHash(&c1), &computePoolHash(&c2)));
}

test "computePoolHash: adding a reservation changes the hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    alloc.free(c2.pools[0].reservations);
    const res = try alloc.alloc(Reservation, 1);
    res[0] = .{
        .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff"),
        .ip = try alloc.dupe(u8, "192.168.1.50"),
        .hostname = null,
        .client_id = null,
    };
    c2.pools[0].reservations = res;

    try std.testing.expect(!std.mem.eql(u8, &computePoolHash(&c1), &computePoolHash(&c2)));
}

test "computePoolHash: reservation insertion order does not affect hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    alloc.free(c1.pools[0].reservations);
    const res1 = try alloc.alloc(Reservation, 2);
    res1[0] = .{ .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:01"), .ip = try alloc.dupe(u8, "192.168.1.50"), .hostname = null, .client_id = null };
    res1[1] = .{ .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:02"), .ip = try alloc.dupe(u8, "192.168.1.51"), .hostname = null, .client_id = null };
    c1.pools[0].reservations = res1;

    alloc.free(c2.pools[0].reservations);
    const res2 = try alloc.alloc(Reservation, 2);
    res2[0] = .{ .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:02"), .ip = try alloc.dupe(u8, "192.168.1.51"), .hostname = null, .client_id = null };
    res2[1] = .{ .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:01"), .ip = try alloc.dupe(u8, "192.168.1.50"), .hostname = null, .client_id = null };
    c2.pools[0].reservations = res2;

    try std.testing.expectEqualSlices(u8, &computePoolHash(&c1), &computePoolHash(&c2));
}

test "computePoolHash: adding a static route changes the hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    alloc.free(c2.pools[0].static_routes);
    const routes = try alloc.alloc(StaticRoute, 1);
    routes[0] = .{
        .destination = .{ 10, 0, 0, 0 },
        .prefix_len = 8,
        .router = .{ 192, 168, 1, 254 },
    };
    c2.pools[0].static_routes = routes;

    try std.testing.expect(!std.mem.eql(u8, &computePoolHash(&c1), &computePoolHash(&c2)));
}

test "computePoolHash: different pool count produces different hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();

    // c2 has two pools
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();
    const extra = try alloc.realloc(c2.pools, 2);
    extra[1] = PoolConfig{
        .subnet = alloc.dupe(u8, "10.0.0.0") catch unreachable,
        .subnet_mask = 0xFF000000,
        .prefix_len = 8,
        .router = alloc.dupe(u8, "10.0.0.1") catch unreachable,
        .pool_start = alloc.dupe(u8, "") catch unreachable,
        .pool_end = alloc.dupe(u8, "") catch unreachable,
        .dns_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .domain_name = alloc.dupe(u8, "") catch unreachable,
        .domain_search = alloc.alloc([]const u8, 0) catch unreachable,
        .lease_time = 3600,
        .time_offset = null,
        .time_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .log_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .ntp_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .mtu = null,
        .wins_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .tftp_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .boot_filename = alloc.dupe(u8, "") catch unreachable,
        .http_boot_url = alloc.dupe(u8, "") catch unreachable,
        .dns_update = .{
            .enable = false,
            .server = alloc.dupe(u8, "") catch unreachable,
            .zone = alloc.dupe(u8, "") catch unreachable,
            .rev_zone = alloc.dupe(u8, "") catch unreachable,
            .key_name = alloc.dupe(u8, "") catch unreachable,
            .key_file = alloc.dupe(u8, "") catch unreachable,
            .lease_time = 3600,
        },
        .dhcp_options = std.StringHashMap([]const u8).init(alloc),
        .reservations = alloc.alloc(Reservation, 0) catch unreachable,
        .static_routes = alloc.alloc(StaticRoute, 0) catch unreachable,
    };
    c2.pools = extra;

    try std.testing.expect(!std.mem.eql(u8, &computePoolHash(&c1), &computePoolHash(&c2)));
}

test "computePoolHash: different domain_name produces different hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    alloc.free(c2.pools[0].domain_name);
    c2.pools[0].domain_name = try alloc.dupe(u8, "example.com");

    try std.testing.expect(!std.mem.eql(u8, &computePoolHash(&c1), &computePoolHash(&c2)));
}

test "computePoolHash: different mtu produces different hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    c2.pools[0].mtu = 1400;

    try std.testing.expect(!std.mem.eql(u8, &computePoolHash(&c1), &computePoolHash(&c2)));
}

test "computePoolHash: different time_offset produces different hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    c2.pools[0].time_offset = -18000;

    try std.testing.expect(!std.mem.eql(u8, &computePoolHash(&c1), &computePoolHash(&c2)));
}

test "computePoolHash: dns_servers order does not affect hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    alloc.free(c1.pools[0].dns_servers);
    const dns1 = try alloc.alloc([]const u8, 2);
    dns1[0] = try alloc.dupe(u8, "8.8.8.8");
    dns1[1] = try alloc.dupe(u8, "1.1.1.1");
    c1.pools[0].dns_servers = dns1;

    alloc.free(c2.pools[0].dns_servers);
    const dns2 = try alloc.alloc([]const u8, 2);
    dns2[0] = try alloc.dupe(u8, "1.1.1.1");
    dns2[1] = try alloc.dupe(u8, "8.8.8.8");
    c2.pools[0].dns_servers = dns2;

    try std.testing.expectEqualSlices(u8, &computePoolHash(&c1), &computePoolHash(&c2));
}

test "computePoolHash: different dns_update config produces different hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    c2.pools[0].dns_update.enable = true;

    try std.testing.expect(!std.mem.eql(u8, &computePoolHash(&c1), &computePoolHash(&c2)));
}

test "computePoolHash: different pool dhcp_options produces different hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    try c2.pools[0].dhcp_options.put(try alloc.dupe(u8, "66"), try alloc.dupe(u8, "tftp.example.com"));

    try std.testing.expect(!std.mem.eql(u8, &computePoolHash(&c1), &computePoolHash(&c2)));
}

test "computePoolHash: reservation hostname changes hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    alloc.free(c1.pools[0].reservations);
    const res1 = try alloc.alloc(Reservation, 1);
    res1[0] = .{ .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff"), .ip = try alloc.dupe(u8, "192.168.1.50"), .hostname = null, .client_id = null };
    c1.pools[0].reservations = res1;

    alloc.free(c2.pools[0].reservations);
    const res2 = try alloc.alloc(Reservation, 1);
    res2[0] = .{ .mac = try alloc.dupe(u8, "aa:bb:cc:dd:ee:ff"), .ip = try alloc.dupe(u8, "192.168.1.50"), .hostname = try alloc.dupe(u8, "myhost"), .client_id = null };
    c2.pools[0].reservations = res2;

    try std.testing.expect(!std.mem.eql(u8, &computePoolHash(&c1), &computePoolHash(&c2)));
}

test "computePoolHash: mac_classes change produces different hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    const classes = try alloc.alloc(MacClass, 1);
    classes[0] = .{
        .name = try alloc.dupe(u8, "printers"),
        .match = try alloc.dupe(u8, "aa:bb:cc"),
        .dhcp_options = std.StringHashMap([]const u8).init(alloc),
    };
    c2.pools[0].mac_classes = classes;

    try std.testing.expect(!std.mem.eql(u8, &computePoolHash(&c1), &computePoolHash(&c2)));
}

test "computePoolHash: tftp_servers order matters" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    alloc.free(c1.pools[0].tftp_servers);
    const tftp1 = try alloc.alloc([]const u8, 2);
    tftp1[0] = try alloc.dupe(u8, "10.0.0.1");
    tftp1[1] = try alloc.dupe(u8, "10.0.0.2");
    c1.pools[0].tftp_servers = tftp1;

    alloc.free(c2.pools[0].tftp_servers);
    const tftp2 = try alloc.alloc([]const u8, 2);
    tftp2[0] = try alloc.dupe(u8, "10.0.0.2");
    tftp2[1] = try alloc.dupe(u8, "10.0.0.1");
    c2.pools[0].tftp_servers = tftp2;

    // TFTP order matters, so different order = different hash
    try std.testing.expect(!std.mem.eql(u8, &computePoolHash(&c1), &computePoolHash(&c2)));
}

// ---------------------------------------------------------------------------
// computePerPoolHash tests
// ---------------------------------------------------------------------------

test "computePerPoolHash: same pool produces same hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    const h1 = computePerPoolHash(&c1.pools[0]);
    const h2 = computePerPoolHash(&c2.pools[0]);
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "computePerPoolHash: different pool produces different hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    alloc.free(c2.pools[0].subnet);
    c2.pools[0].subnet = alloc.dupe(u8, "10.0.0.0") catch unreachable;

    const h1 = computePerPoolHash(&c1.pools[0]);
    const h2 = computePerPoolHash(&c2.pools[0]);
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "computePerPoolHash: different mac_classes produces different hash" {
    const alloc = std.testing.allocator;
    var c1 = makeHashTestConfig(alloc);
    defer c1.deinit();
    var c2 = makeHashTestConfig(alloc);
    defer c2.deinit();

    const classes = try alloc.alloc(MacClass, 1);
    classes[0] = .{
        .name = try alloc.dupe(u8, "printers"),
        .match = try alloc.dupe(u8, "00:11:22"),
        .dhcp_options = std.StringHashMap([]const u8).init(alloc),
    };
    c2.pools[0].mac_classes = classes;

    const h1 = computePerPoolHash(&c1.pools[0]);
    const h2 = computePerPoolHash(&c2.pools[0]);
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

// ---------------------------------------------------------------------------
// Validation helper tests
// ---------------------------------------------------------------------------

test "isValidDomainName: valid domains" {
    try std.testing.expect(isValidDomainName("example.com"));
    try std.testing.expect(isValidDomainName("my-host.example.com"));
    try std.testing.expect(isValidDomainName("a"));
    try std.testing.expect(isValidDomainName("test_domain.local"));
    try std.testing.expect(isValidDomainName("1host.example.com"));
}

test "isValidDomainName: invalid domains" {
    try std.testing.expect(!isValidDomainName(""));
    try std.testing.expect(!isValidDomainName("-start.com"));
    try std.testing.expect(!isValidDomainName(".start.com"));
    try std.testing.expect(!isValidDomainName("has space.com"));
    try std.testing.expect(!isValidDomainName("UPPER.COM")); // must be lowercase
}

test "isValidIpOrDomain: valid entries" {
    try std.testing.expect(isValidIpOrDomain("192.168.1.1"));
    try std.testing.expect(isValidIpOrDomain("dns.example.com"));
    try std.testing.expect(isValidIpOrDomain("8.8.8.8"));
}

test "isValidIpOrDomain: invalid entries" {
    try std.testing.expect(!isValidIpOrDomain(""));
    try std.testing.expect(!isValidIpOrDomain("not an ip or domain"));
    try std.testing.expect(!isValidIpOrDomain("!invalid"));
}

test "isValidFilePath: valid paths" {
    try std.testing.expect(isValidFilePath("/tftpboot/pxelinux.0"));
    try std.testing.expect(isValidFilePath("boot/grub/grubx64.efi"));
    try std.testing.expect(isValidFilePath("Kdhcp-key.+165+12345.key"));
}

test "isValidFilePath: invalid paths" {
    try std.testing.expect(!isValidFilePath(""));
    try std.testing.expect(!isValidFilePath("path with spaces"));
    try std.testing.expect(!isValidFilePath("/etc/keys/my key$"));
}

// ---------------------------------------------------------------------------
// validatePoolFields tests
// ---------------------------------------------------------------------------

/// Build a minimal valid PoolConfig for validation tests.
fn makeValidTestPool(alloc: std.mem.Allocator) PoolConfig {
    return PoolConfig{
        .subnet = alloc.dupe(u8, "192.168.1.0") catch unreachable,
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = alloc.dupe(u8, "192.168.1.1") catch unreachable,
        .pool_start = alloc.dupe(u8, "") catch unreachable,
        .pool_end = alloc.dupe(u8, "") catch unreachable,
        .dns_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .domain_name = alloc.dupe(u8, "") catch unreachable,
        .domain_search = alloc.alloc([]const u8, 0) catch unreachable,
        .lease_time = 3600,
        .time_offset = null,
        .time_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .log_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .ntp_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .mtu = null,
        .wins_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .tftp_servers = alloc.alloc([]const u8, 0) catch unreachable,
        .boot_filename = alloc.dupe(u8, "") catch unreachable,
        .http_boot_url = alloc.dupe(u8, "") catch unreachable,
        .dns_update = .{
            .enable = false,
            .server = alloc.dupe(u8, "") catch unreachable,
            .zone = alloc.dupe(u8, "") catch unreachable,
            .rev_zone = alloc.dupe(u8, "") catch unreachable,
            .key_name = alloc.dupe(u8, "") catch unreachable,
            .key_file = alloc.dupe(u8, "") catch unreachable,
            .lease_time = 3600,
        },
        .dhcp_options = std.StringHashMap([]const u8).init(alloc),
        .reservations = alloc.alloc(Reservation, 0) catch unreachable,
        .static_routes = alloc.alloc(StaticRoute, 0) catch unreachable,
    };
}

test "validatePoolFields: valid pool passes" {
    const alloc = std.testing.allocator;
    var pool = makeValidTestPool(alloc);
    defer pool.deinit(alloc);
    try std.testing.expect(validatePoolFields(alloc, &pool));
}

// Note: strict-rejection tests (missing router, router outside subnet,
// lease_time 0, lease_time > 2 weeks, invalid pool_start, invalid pool_end,
// pool_start > pool_end) are not included as unit tests because they emit
// std.log.err which the Zig 0.15 test runner treats as failures.
// Those paths are covered by integration / config-load testing.

test "validatePoolFields: MTU below 68 cleared" {
    const alloc = std.testing.allocator;
    var pool = makeValidTestPool(alloc);
    defer pool.deinit(alloc);
    pool.mtu = 50;
    try std.testing.expect(validatePoolFields(alloc, &pool));
    try std.testing.expectEqual(@as(?u16, null), pool.mtu);
}

test "validatePoolFields: invalid domain_name cleared" {
    const alloc = std.testing.allocator;
    var pool = makeValidTestPool(alloc);
    defer pool.deinit(alloc);
    alloc.free(pool.domain_name);
    pool.domain_name = alloc.dupe(u8, "-bad.domain") catch unreachable;
    try std.testing.expect(validatePoolFields(alloc, &pool));
    try std.testing.expectEqualStrings("", pool.domain_name);
}

test "validatePoolFields: domain_name auto-lowercased" {
    const alloc = std.testing.allocator;
    var pool = makeValidTestPool(alloc);
    defer pool.deinit(alloc);
    alloc.free(pool.domain_name);
    pool.domain_name = alloc.dupe(u8, "Example.COM") catch unreachable;
    try std.testing.expect(validatePoolFields(alloc, &pool));
    try std.testing.expectEqualStrings("example.com", pool.domain_name);
}

test "validatePoolFields: invalid boot_filename cleared" {
    const alloc = std.testing.allocator;
    var pool = makeValidTestPool(alloc);
    defer pool.deinit(alloc);
    alloc.free(pool.boot_filename);
    pool.boot_filename = alloc.dupe(u8, "file with spaces") catch unreachable;
    try std.testing.expect(validatePoolFields(alloc, &pool));
    try std.testing.expectEqualStrings("", pool.boot_filename);
}

test "validatePoolFields: invalid http_boot_url cleared" {
    const alloc = std.testing.allocator;
    var pool = makeValidTestPool(alloc);
    defer pool.deinit(alloc);
    alloc.free(pool.http_boot_url);
    pool.http_boot_url = alloc.dupe(u8, "ftp://bad.example.com") catch unreachable;
    try std.testing.expect(validatePoolFields(alloc, &pool));
    try std.testing.expectEqualStrings("", pool.http_boot_url);
}

test "validatePoolFields: valid http_boot_url preserved" {
    const alloc = std.testing.allocator;
    var pool = makeValidTestPool(alloc);
    defer pool.deinit(alloc);
    alloc.free(pool.http_boot_url);
    pool.http_boot_url = alloc.dupe(u8, "http://boot.example.com/grub.efi") catch unreachable;
    try std.testing.expect(validatePoolFields(alloc, &pool));
    try std.testing.expectEqualStrings("http://boot.example.com/grub.efi", pool.http_boot_url);
}

test "validatePoolFields: dns_update fields validated" {
    const alloc = std.testing.allocator;
    var pool = makeValidTestPool(alloc);
    defer pool.deinit(alloc);
    alloc.free(pool.dns_update.server);
    pool.dns_update.server = alloc.dupe(u8, "not valid!") catch unreachable;
    alloc.free(pool.dns_update.zone);
    pool.dns_update.zone = alloc.dupe(u8, "-bad") catch unreachable;
    alloc.free(pool.dns_update.key_name);
    pool.dns_update.key_name = alloc.dupe(u8, ".bad") catch unreachable;
    alloc.free(pool.dns_update.key_file);
    pool.dns_update.key_file = alloc.dupe(u8, "path with spaces") catch unreachable;
    try std.testing.expect(validatePoolFields(alloc, &pool));
    try std.testing.expectEqualStrings("", pool.dns_update.server);
    try std.testing.expectEqualStrings("", pool.dns_update.zone);
    try std.testing.expectEqualStrings("", pool.dns_update.key_name);
    try std.testing.expectEqualStrings("", pool.dns_update.key_file);
}

test "validatePoolFields: server list trimmed to max" {
    const alloc = std.testing.allocator;
    var pool = makeValidTestPool(alloc);
    defer pool.deinit(alloc);

    // Set 5 WINS servers (max 2).
    alloc.free(pool.wins_servers);
    pool.wins_servers = alloc.alloc([]const u8, 5) catch unreachable;
    pool.wins_servers[0] = alloc.dupe(u8, "192.168.1.10") catch unreachable;
    pool.wins_servers[1] = alloc.dupe(u8, "192.168.1.11") catch unreachable;
    pool.wins_servers[2] = alloc.dupe(u8, "192.168.1.12") catch unreachable;
    pool.wins_servers[3] = alloc.dupe(u8, "192.168.1.13") catch unreachable;
    pool.wins_servers[4] = alloc.dupe(u8, "192.168.1.14") catch unreachable;

    try std.testing.expect(validatePoolFields(alloc, &pool));
    try std.testing.expectEqual(@as(usize, 2), pool.wins_servers.len);
    try std.testing.expectEqualStrings("192.168.1.10", pool.wins_servers[0]);
    try std.testing.expectEqualStrings("192.168.1.11", pool.wins_servers[1]);
}

test "validatePoolFields: invalid server entries removed" {
    const alloc = std.testing.allocator;
    var pool = makeValidTestPool(alloc);
    defer pool.deinit(alloc);

    alloc.free(pool.dns_servers);
    pool.dns_servers = alloc.alloc([]const u8, 3) catch unreachable;
    pool.dns_servers[0] = alloc.dupe(u8, "8.8.8.8") catch unreachable;
    pool.dns_servers[1] = alloc.dupe(u8, "not valid!") catch unreachable;
    pool.dns_servers[2] = alloc.dupe(u8, "dns.example.com") catch unreachable;

    try std.testing.expect(validatePoolFields(alloc, &pool));
    try std.testing.expectEqual(@as(usize, 2), pool.dns_servers.len);
    try std.testing.expectEqualStrings("8.8.8.8", pool.dns_servers[0]);
    try std.testing.expectEqualStrings("dns.example.com", pool.dns_servers[1]);
}

test "validatePoolFields: domain_search invalid entries removed" {
    const alloc = std.testing.allocator;
    var pool = makeValidTestPool(alloc);
    defer pool.deinit(alloc);

    alloc.free(pool.domain_search);
    pool.domain_search = alloc.alloc([]const u8, 3) catch unreachable;
    pool.domain_search[0] = alloc.dupe(u8, "example.com") catch unreachable;
    pool.domain_search[1] = alloc.dupe(u8, "-bad.com") catch unreachable;
    pool.domain_search[2] = alloc.dupe(u8, "local.lan") catch unreachable;

    try std.testing.expect(validatePoolFields(alloc, &pool));
    try std.testing.expectEqual(@as(usize, 2), pool.domain_search.len);
    try std.testing.expectEqualStrings("example.com", pool.domain_search[0]);
    try std.testing.expectEqualStrings("local.lan", pool.domain_search[1]);
}
