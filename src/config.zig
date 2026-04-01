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
};

/// MAC class rule: matches client MACs by prefix pattern and overrides DHCP options.
/// Applied after pool defaults, before per-reservation overrides.
pub const MacClass = struct {
    name: []const u8,
    match: []const u8, // MAC prefix, e.g. "64:16:7f" or "aa:bb:cc:dd:*"
    dhcp_options: std.StringHashMap([]const u8),

    pub fn deinit(self: *MacClass, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.match);
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
    tftp_server_name: []const u8,
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
        allocator.free(self.tftp_server_name);
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
    sync: ?SyncConfig,
    mac_classes: []MacClass = &.{},
    pools: []PoolConfig, // at least one required
    admin_ssh: AdminSSHConfig,
    metrics: MetricsConfig,

    pub fn deinit(self: *Config) void {
        self.allocator.free(self.listen_address);
        self.allocator.free(self.state_dir);
        for (self.mac_classes) |*mc| mc.deinit(self.allocator);
        self.allocator.free(self.mac_classes);
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
    try doc.load(allocator);
    defer doc.deinit(allocator);

    var parse_arena = std.heap.ArenaAllocator.init(allocator);
    defer parse_arena.deinit();

    const raw = try doc.parse(parse_arena.allocator(), RawConfig);

    var cfg = Config{
        .allocator = allocator,
        .listen_address = try allocator.dupe(u8, raw.listen_address orelse "0.0.0.0"),
        .state_dir = try allocator.dupe(u8, raw.state_dir orelse "/var/lib/stardust"),
        .log_level = parseLogLevel(raw.log_level orelse "info"),
        .pool_allocation_random = false,
        .sync = null,
        .mac_classes = try allocator.alloc(MacClass, 0),
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

            if (root_map.get("sync")) |sync_val| {
                if (sync_val.asMap()) |sync_map| {
                    cfg.sync = try parseSyncConfig(allocator, sync_map);
                }
            }

            if (root_map.get("mac_classes")) |mc_val| {
                if (mc_val.asList()) |mc_list| {
                    cfg.mac_classes = try parseMacClasses(allocator, mc_list);
                }
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
        .tftp_server_name = try allocator.dupe(u8, ""),
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

    if (pool_map.get("tftp_server_name")) |v| {
        if (v.asScalar()) |s| {
            allocator.free(pool.tftp_server_name);
            pool.tftp_server_name = try allocator.dupe(u8, s);
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
            for (pool.dns_servers) |*s| s.* = "";
            for (list, 0..) |item, i| {
                pool.dns_servers[i] = try allocator.dupe(u8, item.asScalar() orelse "");
            }
        }
    }

    if (pool_map.get("domain_search")) |v| {
        if (v.asList()) |list| {
            allocator.free(pool.domain_search);
            pool.domain_search = try allocator.alloc([]const u8, list.len);
            for (pool.domain_search) |*s| s.* = "";
            for (list, 0..) |item, i| {
                pool.domain_search[i] = try allocator.dupe(u8, item.asScalar() orelse "");
            }
        }
    }

    if (pool_map.get("time_servers")) |v| {
        if (v.asList()) |list| {
            allocator.free(pool.time_servers);
            pool.time_servers = try allocator.alloc([]const u8, list.len);
            for (pool.time_servers) |*s| s.* = "";
            for (list, 0..) |item, i| {
                pool.time_servers[i] = try allocator.dupe(u8, item.asScalar() orelse "");
            }
        }
    }

    if (pool_map.get("log_servers")) |v| {
        if (v.asList()) |list| {
            allocator.free(pool.log_servers);
            pool.log_servers = try allocator.alloc([]const u8, list.len);
            for (pool.log_servers) |*s| s.* = "";
            for (list, 0..) |item, i| {
                pool.log_servers[i] = try allocator.dupe(u8, item.asScalar() orelse "");
            }
        }
    }

    if (pool_map.get("ntp_servers")) |v| {
        if (v.asList()) |list| {
            allocator.free(pool.ntp_servers);
            pool.ntp_servers = try allocator.alloc([]const u8, list.len);
            for (pool.ntp_servers) |*s| s.* = "";
            for (list, 0..) |item, i| {
                pool.ntp_servers[i] = try allocator.dupe(u8, item.asScalar() orelse "");
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

    validatePoolRange(&pool);

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

        pool.reservations[idx] = .{
            .mac = mac_owned,
            .ip = ip_owned,
            .hostname = hostname_owned,
            .client_id = client_id_owned,
            .dhcp_options = res_opts,
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
        std.log.err("config: static_route '{s}' is a default route (0.0.0.0/0); use the 'router' option instead, skipping", .{dest_str});
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

    return SyncConfig{
        .enable = true,
        .group_name = group_name,
        .key_file = key_file,
        .port = port,
        .full_sync_interval = full_sync_interval,
        .multicast = multicast,
        .peers = peers,
    };
}

fn parseMacClasses(allocator: std.mem.Allocator, list: anytype) ![]MacClass {
    var classes = try allocator.alloc(MacClass, list.len);
    var idx: usize = 0;
    for (list) |item| {
        const m = item.asMap() orelse continue;
        const name_str = if (m.get("name")) |v| (v.asScalar() orelse "") else "";
        const match_str = if (m.get("match")) |v| (v.asScalar() orelse "") else "";
        if (match_str.len == 0) {
            std.log.warn("config: mac_class missing 'match', skipping", .{});
            continue;
        }

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

        const name_duped = try allocator.dupe(u8, name_str);
        errdefer allocator.free(name_duped);
        const match_duped = try allocator.dupe(u8, match_str);

        classes[idx] = .{
            .name = name_duped,
            .match = match_duped,
            .dhcp_options = opts,
        };
        idx += 1;
    }
    return allocator.realloc(classes, idx) catch classes[0..idx];
}

/// Compute a SHA-256 pool hash over all pools' subnets, addresses, reservations,
/// and static routes. Used by SyncManager to verify peer config compatibility.
pub fn computePoolHash(cfg: *const Config) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});

    // Hash pool count to distinguish configs with different numbers of pools.
    var pc_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &pc_bytes, @intCast(cfg.pools.len), .big);
    h.update(&pc_bytes);

    for (cfg.pools) |*pool| {
        hashPoolIntoSha256(&h, pool);
    }

    var digest: [32]u8 = undefined;
    h.final(&digest);
    return digest;
}

fn hashPoolIntoSha256(h: *std.crypto.hash.sha2.Sha256, pool: *const PoolConfig) void {
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
            const hi = std.fmt.charToDigit(r.mac[pos], 16) catch 0;
            const lo = std.fmt.charToDigit(r.mac[pos + 1], 16) catch 0;
            mac_bytes[bi] = (hi << 4) | lo;
            pos += 3;
        }
        h.update(&mac_bytes);
        const ip_bytes = parseIpv4(r.ip) catch [4]u8{ 0, 0, 0, 0 };
        h.update(&ip_bytes);
    }

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
fn validatePoolRange(pool: *const PoolConfig) void {
    const subnet_bytes = parseIpv4(pool.subnet) catch return;
    const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
    const broadcast_int = subnet_int | ~pool.subnet_mask;
    // Degenerate subnets (/32 of max address or /32 of 0.0.0.0) have no usable
    // host range. Skip further validation rather than panicking on overflow.
    if (subnet_int == std.math.maxInt(u32) or broadcast_int == 0) return;
    const valid_start = subnet_int + 1;
    const valid_end = broadcast_int - 1;

    var start_int: u32 = valid_start;
    var end_int: u32 = valid_end;
    var has_start = false;
    var has_end = false;

    if (pool.pool_start.len > 0) {
        const b = parseIpv4(pool.pool_start) catch {
            std.log.warn("config: pool_start '{s}' is not a valid IP address", .{pool.pool_start});
            return;
        };
        start_int = std.mem.readInt(u32, &b, .big);
        has_start = true;
        if (start_int < valid_start or start_int > valid_end) {
            std.log.warn("config: pool_start {s} is outside subnet {s}/{d}", .{
                pool.pool_start, pool.subnet, pool.prefix_len,
            });
        }
    }

    if (pool.pool_end.len > 0) {
        const b = parseIpv4(pool.pool_end) catch {
            std.log.warn("config: pool_end '{s}' is not a valid IP address", .{pool.pool_end});
            return;
        };
        end_int = std.mem.readInt(u32, &b, .big);
        has_end = true;
        if (end_int < valid_start or end_int > valid_end) {
            std.log.warn("config: pool_end {s} is outside subnet {s}/{d}", .{
                pool.pool_end, pool.subnet, pool.prefix_len,
            });
        }
    }

    if (has_start and has_end and start_int > end_int) {
        std.log.warn("config: pool_start {s} > pool_end {s}: pool is empty", .{
            pool.pool_start, pool.pool_end,
        });
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
        .tftp_server_name = alloc.dupe(u8, "") catch unreachable,
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
        .mac = "aa:bb:cc:dd:ee:ff",
        .ip = "192.168.1.50",
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
    res1[0] = .{ .mac = "aa:bb:cc:dd:ee:01", .ip = "192.168.1.50", .hostname = null, .client_id = null };
    res1[1] = .{ .mac = "aa:bb:cc:dd:ee:02", .ip = "192.168.1.51", .hostname = null, .client_id = null };
    c1.pools[0].reservations = res1;

    alloc.free(c2.pools[0].reservations);
    const res2 = try alloc.alloc(Reservation, 2);
    res2[0] = .{ .mac = "aa:bb:cc:dd:ee:02", .ip = "192.168.1.51", .hostname = null, .client_id = null };
    res2[1] = .{ .mac = "aa:bb:cc:dd:ee:01", .ip = "192.168.1.50", .hostname = null, .client_id = null };
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
        .tftp_server_name = alloc.dupe(u8, "") catch unreachable,
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
