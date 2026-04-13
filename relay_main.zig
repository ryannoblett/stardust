const std = @import("std");
const builtin = @import("builtin");
const relay = @import("./src/relay.zig");
const relay_config = @import("./src/relay_config.zig");

pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = logFn,
};

/// Global log level, adjustable at runtime via config reload.
var g_log_level: std.log.Level = .info;

/// Set to true when stderr is connected to the systemd journal (JOURNAL_STREAM is set).
/// When true, timestamps are omitted (journald adds its own) and sd-daemon priority
/// prefixes are used for log level filtering.
var g_journal_stream: bool = false;

/// Custom log function matching the server's sd-daemon priority format.
fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    _ = scope;
    const runtime_level = @intFromEnum(g_log_level);
    const msg_level = @intFromEnum(level);
    if (msg_level > runtime_level) return;

    const sd_prefix = comptime switch (level) {
        .err => "<3>",
        .warn => "<5>",
        .info => "<6>",
        .debug => "<7>",
    };
    const level_str = comptime switch (level) {
        .err => "ERROR",
        .warn => "WARN",
        .info => "INFO",
        .debug => "DEBUG",
    };

    // Format the message first so we can include it in the final line.
    var msg_buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&msg_buf, format, args) catch "(message too long)";

    // Single-syscall write to stderr for atomicity.
    var line_buf: [4352]u8 = undefined;
    if (g_journal_stream) {
        const line = std.fmt.bufPrint(&line_buf, sd_prefix ++ "[" ++ level_str ++ "] {s}\n", .{msg}) catch return;
        _ = std.posix.write(std.posix.STDERR_FILENO, line) catch {};
    } else {
        var ts_buf: [20]u8 = undefined;
        const ts = fmtTimestamp(&ts_buf, std.time.timestamp());
        const line = std.fmt.bufPrint(&line_buf, "{s} [" ++ level_str ++ "] {s}\n", .{ ts, msg }) catch return;
        _ = std.posix.write(std.posix.STDERR_FILENO, line) catch {};
    }
}

fn fmtTimestamp(buf: *[20]u8, ts: i64) []const u8 {
    const secs: u64 = @intCast(@max(ts, 0));
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

/// Signal state: atomic flags set by signal handlers, read by the main loop.
var g_running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true);
var g_reload: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn sigHandler(sig: c_int) callconv(.c) void {
    switch (sig) {
        std.posix.SIG.INT, std.posix.SIG.TERM => g_running.store(false, .monotonic),
        std.posix.SIG.HUP => g_reload.store(true, .monotonic),
        else => {},
    }
}

pub fn main() !void {
    const gpa_config = if (builtin.mode == .Debug)
        std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 8 }){}
    else
        std.heap.GeneralPurposeAllocator(.{}){};
    var gpa = gpa_config;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse args: -c <config_path>
    var config_path: []const u8 = "relay.yaml";
    var config_path_owned: ?[]const u8 = null;
    defer if (config_path_owned) |p| allocator.free(p);
    {
        var args = try std.process.argsWithAllocator(allocator);
        defer args.deinit();
        _ = args.next(); // skip argv[0]
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
                const path = args.next() orelse {
                    std.log.err("missing config path after {s}", .{arg});
                    std.process.exit(1);
                };
                config_path_owned = try allocator.dupe(u8, path);
                config_path = config_path_owned.?;
            } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
                _ = std.posix.write(
                    std.posix.STDOUT_FILENO,
                    "Usage: stardust-relay [options]\n\n" ++
                        "Options:\n" ++
                        "  -c, --config <path>  Config file (default: relay.yaml)\n" ++
                        "  -h, --help           Show this help\n",
                ) catch 0;
                return;
            } else {
                std.log.err("unknown argument: {s}", .{arg});
                std.process.exit(1);
            }
        }
    }

    // Detect journald — omit timestamps when running under systemd.
    g_journal_stream = std.posix.getenv("JOURNAL_STREAM") != null;

    // Load config.
    const cfg = relay_config.load(allocator, config_path) catch |err| {
        std.log.err("failed to load config '{s}': {s}", .{ config_path, @errorName(err) });
        std.process.exit(1);
    };

    // Apply configured log level.
    g_log_level = cfg.log_level;

    // Install signal handlers.
    const sa = std.posix.Sigaction{
        .handler = .{ .handler = sigHandler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sa, null);
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null);
    std.posix.sigaction(std.posix.SIG.HUP, &sa, null);

    // Create and run the relay agent (agent owns the config).
    var agent = relay.RelayAgent.init(allocator, cfg, config_path, &g_log_level) catch |err| {
        std.log.err("failed to initialise relay: {s}", .{@errorName(err)});
        std.process.exit(1);
    };
    defer agent.deinit();

    agent.run(&g_running, &g_reload);
}
