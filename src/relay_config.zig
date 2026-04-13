/// Configuration for the DHCP relay agent.
///
/// Loaded from a YAML file (default: relay.yaml). Only `upstream_servers` is
/// required — downstream interfaces are auto-detected unless overridden.
const std = @import("std");
const yaml = @import("yaml");

pub const Option82Policy = enum {
    replace, // Strip existing option 82, add ours
    append, // Keep existing option 82, add ours after
    drop, // Strip existing option 82, don't add ours
    keep, // Leave existing untouched; add ours only if absent
};

pub const Option82Config = struct {
    enable: bool = true,
    circuit_id: []const u8 = "auto", // "auto" = use interface name
    remote_id: []const u8 = "", // empty = omit sub-option 2
    policy: Option82Policy = .replace,
};

pub const RelayConfig = struct {
    log_level: std.log.Level = .info,
    upstream_servers: []const []const u8 = &.{},
    /// Optional manual downstream interface names. Empty = auto-detect.
    downstream_interfaces: []const []const u8 = &.{},
    /// Optional single downstream IP (simple mode). Empty = auto-detect.
    downstream_ip: []const u8 = "",
    max_hops: u8 = 16,
    option82: Option82Config = .{},

    // Heap-allocated arena owning all YAML-parsed string values.
    _arena: ?*std.heap.ArenaAllocator = null,

    pub fn deinit(self: *const RelayConfig, allocator: std.mem.Allocator) void {
        if (self._arena) |arena| {
            arena.deinit();
            allocator.destroy(arena);
        }
    }
};

pub fn load(allocator: std.mem.Allocator, path: []const u8) !RelayConfig {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    const source = try allocator.alloc(u8, stat.size);
    defer allocator.free(source);
    _ = try file.readAll(source);

    const arena = try allocator.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(allocator);
    errdefer {
        arena.deinit();
        allocator.destroy(arena);
    }
    const aa = arena.allocator();

    var doc = yaml.Yaml{ .source = source };
    doc.load(allocator) catch |err| {
        std.log.err("relay config: YAML parse error: {s}", .{@errorName(err)});
        return error.InvalidConfig;
    };
    defer doc.deinit(allocator);

    const root_map = if (doc.docs.items.len > 0)
        doc.docs.items[0].asMap() orelse {
            std.log.err("relay config: root is not a mapping", .{});
            return error.InvalidConfig;
        }
    else {
        std.log.err("relay config: empty document", .{});
        return error.InvalidConfig;
    };

    var cfg = RelayConfig{};
    cfg._arena = arena;

    // log_level
    if (root_map.get("log_level")) |v| {
        if (v.asScalar()) |s| {
            if (std.mem.eql(u8, s, "err") or std.mem.eql(u8, s, "error")) {
                cfg.log_level = .err;
            } else if (std.mem.eql(u8, s, "warn")) {
                cfg.log_level = .warn;
            } else if (std.mem.eql(u8, s, "info")) {
                cfg.log_level = .info;
            } else if (std.mem.eql(u8, s, "debug")) {
                cfg.log_level = .debug;
            }
        }
    }

    // upstream_servers (required)
    if (root_map.get("upstream_servers")) |v| {
        if (v.asList()) |list| {
            var servers = std.ArrayList([]const u8){};
            for (list) |item| {
                if (item.asScalar()) |s| {
                    try servers.append(aa, try aa.dupe(u8, s));
                }
            }
            cfg.upstream_servers = try servers.toOwnedSlice(aa);
        }
    }
    if (cfg.upstream_servers.len == 0) {
        std.log.err("relay config: upstream_servers is required and must not be empty", .{});
        return error.InvalidConfig;
    }

    // downstream_interfaces (optional)
    if (root_map.get("downstream_interfaces")) |v| {
        if (v.asList()) |list| {
            var ifaces = std.ArrayList([]const u8){};
            for (list) |item| {
                if (item.asScalar()) |s| {
                    try ifaces.append(aa, try aa.dupe(u8, s));
                }
            }
            cfg.downstream_interfaces = try ifaces.toOwnedSlice(aa);
        }
    }

    // downstream_ip (optional, simple single-interface mode)
    if (root_map.get("downstream_ip")) |v| {
        if (v.asScalar()) |s| {
            cfg.downstream_ip = try aa.dupe(u8, s);
        }
    }

    // max_hops
    if (root_map.get("max_hops")) |v| {
        if (v.asScalar()) |s| {
            cfg.max_hops = std.fmt.parseInt(u8, s, 10) catch 16;
        }
    }

    // option82
    if (root_map.get("option82")) |v| {
        if (v.asMap()) |m| {
            if (m.get("enable")) |ev| {
                if (ev.asScalar()) |s| {
                    cfg.option82.enable = std.mem.eql(u8, s, "true");
                }
            }
            if (m.get("circuit_id")) |cv| {
                if (cv.asScalar()) |s| {
                    cfg.option82.circuit_id = try aa.dupe(u8, s);
                }
            }
            if (m.get("remote_id")) |rv| {
                if (rv.asScalar()) |s| {
                    cfg.option82.remote_id = try aa.dupe(u8, s);
                }
            }
            if (m.get("policy")) |pv| {
                if (pv.asScalar()) |s| {
                    if (std.mem.eql(u8, s, "replace")) {
                        cfg.option82.policy = .replace;
                    } else if (std.mem.eql(u8, s, "append")) {
                        cfg.option82.policy = .append;
                    } else if (std.mem.eql(u8, s, "drop")) {
                        cfg.option82.policy = .drop;
                    } else if (std.mem.eql(u8, s, "keep")) {
                        cfg.option82.policy = .keep;
                    }
                }
            }
        }
    }

    return cfg;
}
