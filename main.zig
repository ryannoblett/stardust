const std = @import("std");
const dhcp = @import("./src/dhcp.zig");
const config_mod = @import("./src/config.zig");
const state_mod = @import("./src/state.zig");
const dns = @import("./src/dns.zig");
const sync_mod = @import("./src/sync.zig");
const metrics_mod = @import("./src/metrics.zig");
const admin_mod = @import("./src/admin_ssh.zig");

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

pub const std_options: std.Options = .{
    .logFn = logFn,
    // Override the compile-time filter so std.log.debug calls are compiled in
    // across all build modes; runtime filtering is handled by g_log_level.
    .log_level = .debug,
};

var g_log_level: config_mod.LogLevel = .info;
// Set to true when stderr is connected to the systemd journal (JOURNAL_STREAM is set).
// sd-daemon priority prefixes (<N>) are only emitted in that case.
var g_journal_stream: bool = false;
var g_log_mutex: std.Thread.Mutex = .{};

fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    // Verbose messages are emitted as std.log.debug with scope .verbose.
    // Map (level, scope) to our 5-level LogLevel for runtime filtering.
    const is_verbose = comptime (scope == .verbose and level == .debug);
    const effective_level: u8 = if (is_verbose) 3 else switch (level) {
        .err => 0,
        .warn => 1,
        .info => 2,
        .debug => 4,
    };
    const threshold: u8 = switch (g_log_level) {
        .err => 0,
        .warn => 1,
        .info => 2,
        .verbose => 3,
        .debug => 4,
    };
    if (effective_level > threshold) return;

    const sd_prefix = comptime if (is_verbose) "<7>" else switch (level) {
        .debug => "<7>",
        .info => "<6>",
        .warn => "<5>",
        .err => "<3>",
    };
    const level_str = comptime if (is_verbose) "VERBOSE" else switch (level) {
        .debug => "DEBUG",
        .info => "INFO",
        .warn => "WARN",
        .err => "ERROR",
    };
    g_log_mutex.lock();
    defer g_log_mutex.unlock();

    if (g_journal_stream) {
        std.debug.print(sd_prefix ++ "[" ++ level_str ++ "] " ++ format ++ "\n", args);
    } else {
        var ts_buf: [20]u8 = undefined;
        const ts = fmtTimestamp(&ts_buf, std.time.timestamp());
        std.debug.print("{s} [" ++ level_str ++ "] " ++ format ++ "\n", .{ts} ++ args);
    }
}

fn fmtTimestamp(buf: *[20]u8, ts: i64) []const u8 {
    const ts_positive: i64 = @max(ts, 0);
    const secs: u64 = @intCast(ts_positive);
    const epoch_secs = std.time.epoch.EpochSeconds{ .secs = secs };
    const day_secs = epoch_secs.getDaySeconds();
    const epoch_day = epoch_secs.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const year = year_day.year;
    buf[0] = '0' + @as(u8, @intCast((year / 1000) % 10));
    buf[1] = '0' + @as(u8, @intCast((year / 100) % 10));
    buf[2] = '0' + @as(u8, @intCast((year / 10) % 10));
    buf[3] = '0' + @as(u8, @intCast(year % 10));
    buf[4] = '-';
    writeDigits2(buf[5..7], month_day.month.numeric());
    buf[7] = '-';
    writeDigits2(buf[8..10], month_day.day_index + 1);
    buf[10] = 'T';
    writeDigits2(buf[11..13], day_secs.getHoursIntoDay());
    buf[13] = ':';
    writeDigits2(buf[14..16], day_secs.getMinutesIntoHour());
    buf[16] = ':';
    writeDigits2(buf[17..19], day_secs.getSecondsIntoMinute());
    buf[19] = 'Z';
    return buf[0..20];
}

fn writeDigits2(buf: *[2]u8, val: anytype) void {
    buf[0] = '0' + @as(u8, @intCast(val / 10));
    buf[1] = '0' + @as(u8, @intCast(val % 10));
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(1);
}

pub fn main() !void {
    // Allocator setup: GPA for leak detection in debug, page allocator otherwise
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    g_journal_stream = std.posix.getenv("JOURNAL_STREAM") != null;

    // Parse command-line arguments.
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var cfg_path: []const u8 = "config.yaml";
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            i += 1;
            if (i >= args.len) fatal("Missing argument for {s}", .{arg});
            cfg_path = args[i];
        } else {
            fatal("Unknown argument: {s}\nUsage: stardust [-c|--config <path>]", .{arg});
        }
    }

    std.log.info("Starting Stardust DHCP Server...", .{});

    // Load configuration into a heap allocation so the DHCP server can reload
    // it in-place on SIGHUP without disturbing the pointer it holds.
    const cfg = try allocator.create(config_mod.Config);
    cfg.* = config_mod.load(allocator, cfg_path) catch |err| {
        fatal("Failed to load config: {s}", .{@errorName(err)});
    };
    defer {
        cfg.deinit();
        allocator.destroy(cfg);
    }

    // Apply log level from config (updated in-place via &g_log_level on SIGHUP reload).
    g_log_level = cfg.log_level;

    std.log.info("Configuration loaded", .{});
    std.log.info("  listen:    {s}", .{cfg.listen_address});
    std.log.info("  state_dir: {s}", .{cfg.state_dir});
    std.log.info("  pools:     {d}", .{cfg.pools.len});
    for (cfg.pools, 0..) |pool, idx| {
        std.log.info("  pool[{d}]: {s}/{d}, router={s}, lease={d}s", .{
            idx, pool.subnet, pool.prefix_len, pool.router, pool.lease_time,
        });
    }

    // Initialize state store
    const store = state_mod.StateStore.init(allocator, cfg.state_dir) catch |err| {
        fatal("Failed to initialize state store: {s}", .{@errorName(err)});
    };
    defer store.deinit();

    std.log.info("State store initialized", .{});

    // Initialize sync manager if enabled.
    std.log.debug("Computing pool hash...", .{});
    const pool_hash = config_mod.computePoolHash(cfg);
    std.log.debug("Pool hash computed", .{});
    var sync_mgr: ?*sync_mod.SyncManager = null;
    if (cfg.sync) |*sync_cfg| {
        if (sync_cfg.enable) {
            std.log.info("Initializing sync manager (key_file={s})...", .{sync_cfg.key_file});
            sync_mgr = sync_mod.SyncManager.init(allocator, sync_cfg, cfg, cfg_path, store, pool_hash) catch |err| blk: {
                std.log.err("Failed to initialize sync manager ({s}); running without sync", .{@errorName(err)});
                break :blk null;
            };
        }
    }
    defer if (sync_mgr) |s| s.deinit();

    if (sync_mgr != null) {
        std.log.info("Sync manager enabled", .{});
    }

    // Create and run DHCP server. The server creates and owns per-pool DNS updaters.
    const dhcp_server = dhcp.create_server(allocator, cfg, cfg_path, store, &g_log_level, sync_mgr) catch |err| {
        fatal("Failed to create DHCP server: {s}", .{@errorName(err)});
    };
    defer dhcp_server.deinit();

    // Sync reservations from config into the state store.
    // On SIGHUP the server calls syncReservations() again after reloading config.
    dhcp_server.syncReservations();

    // Start HTTP metrics server in a background thread if enabled.
    var metrics_server: ?*metrics_mod.MetricsServer = null;
    var metrics_thread: ?std.Thread = null;
    if (cfg.metrics.http_enable) {
        metrics_server = metrics_mod.MetricsServer.init(allocator, cfg, store, &dhcp_server.counters) catch |err| blk: {
            std.log.err("Failed to initialize metrics server ({s}); running without metrics HTTP", .{@errorName(err)});
            break :blk null;
        };
        if (metrics_server) |ms| {
            metrics_thread = std.Thread.spawn(.{}, metrics_mod.MetricsServer.run, .{ms}) catch |err| blk: {
                std.log.err("Failed to start metrics thread ({s}); running without metrics HTTP", .{@errorName(err)});
                break :blk null;
            };
        }
    }
    defer {
        if (metrics_server) |ms| {
            ms.stop();
            if (metrics_thread) |t| t.join();
            ms.deinit();
        }
    }

    if (cfg.metrics.http_enable and metrics_server != null) {
        std.log.info("Metrics HTTP server enabled on {s}:{d}", .{
            cfg.metrics.http_bind,
            cfg.metrics.http_port,
        });
    }

    // Start SSH admin TUI server in a background thread if enabled.
    var admin_server: ?*admin_mod.AdminServer = null;
    var admin_thread: ?std.Thread = null;
    if (cfg.admin_ssh.enable) {
        admin_server = admin_mod.AdminServer.init(allocator, cfg, store, &dhcp_server.counters) catch |err| blk: {
            std.log.err("Failed to initialize admin SSH server ({s}); running without admin TUI", .{@errorName(err)});
            break :blk null;
        };
        if (admin_server) |as| {
            admin_thread = std.Thread.spawn(.{}, admin_mod.AdminServer.run, .{as}) catch |err| blk: {
                std.log.err("Failed to start admin SSH thread ({s}); running without admin TUI", .{@errorName(err)});
                break :blk null;
            };
        }
    }
    defer {
        if (admin_server) |as| {
            as.stop();
            if (admin_thread) |t| t.join();
            as.deinit();
        }
    }

    if (cfg.admin_ssh.enable and admin_server != null) {
        std.log.info("Admin SSH server enabled on {s}:{d}", .{
            cfg.admin_ssh.bind,
            cfg.admin_ssh.port,
        });
    }

    std.log.info("Starting DHCP server...", .{});
    dhcp_server.run() catch |err| {
        fatal("DHCP server error: {s}", .{@errorName(err)});
    };
}
