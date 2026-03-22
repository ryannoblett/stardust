const std = @import("std");
const dhcp = @import("./src/dhcp.zig");
const config_mod = @import("./src/config.zig");
const state_mod = @import("./src/state.zig");
const dns = @import("./src/dns.zig");

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

pub const std_options: std.Options = .{
    .logFn = logFn,
};

var g_log_level: std.log.Level = .info;

fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    _ = scope;
    if (@intFromEnum(level) > @intFromEnum(g_log_level)) return;
    const sd_prefix = comptime switch (level) {
        .debug => "<7>",
        .info => "<6>",
        .warn => "<5>",
        .err => "<3>",
    };
    const level_str = comptime switch (level) {
        .debug => "DEBUG",
        .info => "INFO",
        .warn => "WARN",
        .err => "ERROR",
    };
    var ts_buf: [20]u8 = undefined;
    const ts = fmtTimestamp(&ts_buf, std.time.timestamp());
    const stderr = std.io.getStdErr().writer();
    stderr.print(sd_prefix ++ "{s} [" ++ level_str ++ "] " ++ format ++ "\n", .{ts} ++ args) catch {};
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

    std.log.info("Starting Stardust DHCP Server...", .{});

    // Load configuration
    var cfg = config_mod.load(allocator, "config.yaml") catch |err| {
        fatal("Failed to load config: {s}", .{@errorName(err)});
    };
    defer cfg.deinit();

    // Apply log level from config
    g_log_level = cfg.log_level;

    // Format subnet mask as dotted-decimal for display
    const mask = cfg.subnet_mask;
    const mask_a: u8 = @intCast((mask >> 24) & 0xFF);
    const mask_b: u8 = @intCast((mask >> 16) & 0xFF);
    const mask_c: u8 = @intCast((mask >> 8) & 0xFF);
    const mask_d: u8 = @intCast(mask & 0xFF);

    std.log.info("Configuration loaded", .{});
    std.log.info("  listen:     {s}", .{cfg.listen_address});
    std.log.info("  subnet:     {s}/{d}.{d}.{d}.{d}", .{
        cfg.subnet, mask_a, mask_b, mask_c, mask_d,
    });
    std.log.info("  router:     {s}", .{cfg.router});
    std.log.info("  lease_time: {d}s", .{cfg.lease_time});
    std.log.info("  state_dir:  {s}", .{cfg.state_dir});

    // Initialize state store
    const store = state_mod.StateStore.init(allocator, cfg.state_dir) catch |err| {
        fatal("Failed to initialize state store: {s}", .{@errorName(err)});
    };
    defer store.deinit();

    std.log.info("State store initialized", .{});

    // Seed static reservations into the state store.
    for (cfg.reservations) |r| {
        if (store.getReservationByMac(r.mac) != null) continue; // already seeded from leases.json
        store.addReservation(r.mac, r.ip, r.hostname, r.client_id) catch |err| {
            std.log.warn("Failed to seed reservation for {s}: {s}", .{ r.mac, @errorName(err) });
        };
        std.log.info("Seeded reservation: {s} -> {s}", .{ r.mac, r.ip });
    }

    // Initialize DNS updater
    const dns_updater = dns.create_updater(allocator, &cfg.dns_update) catch |err| {
        fatal("Failed to initialize DNS updater: {s}", .{@errorName(err)});
    };
    defer dns_updater.cleanup();

    if (cfg.dns_update.enable) {
        std.log.info("DNS updater enabled (server: {s}, zone: {s})", .{
            cfg.dns_update.server, cfg.dns_update.zone,
        });
    } else {
        std.log.info("DNS updater disabled", .{});
    }

    // Create and run DHCP server
    const dhcp_server = dhcp.create_server(allocator, &cfg, store, dns_updater) catch |err| {
        fatal("Failed to create DHCP server: {s}", .{@errorName(err)});
    };
    defer dhcp_server.deinit();

    std.log.info("Starting DHCP server...", .{});
    dhcp_server.run() catch |err| {
        fatal("DHCP server error: {s}", .{@errorName(err)});
    };
}
