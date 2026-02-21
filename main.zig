const std = @import("std");
const dhcp = @import("./src/dhcp.zig");
const config_mod = @import("./src/config.zig");
const state_mod = @import("./src/state.zig");
const dns = @import("./src/dns.zig");

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("fatal: " ++ fmt ++ "\n", args) catch {};
    std.process.exit(1);
}

pub fn main() !void {
    // Allocator setup: GPA for leak detection in debug, page allocator otherwise
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try std.fs.File.stdout().writeAll("Starting Stardust DHCP Server...\n");

    // Load configuration
    var cfg = config_mod.load(allocator, "config.yaml") catch |err| {
        fatal("Failed to load config: {s}", .{@errorName(err)});
    };
    defer cfg.deinit();

    // Format subnet mask as dotted-decimal for display
    const mask = cfg.subnet_mask;
    const mask_a: u8 = @intCast((mask >> 24) & 0xFF);
    const mask_b: u8 = @intCast((mask >> 16) & 0xFF);
    const mask_c: u8 = @intCast((mask >> 8) & 0xFF);
    const mask_d: u8 = @intCast(mask & 0xFF);

    try std.fs.File.stdout().writeAll("Configuration loaded successfully\n");
    try std.fs.File.stdout().writeAll("  listen:     {s}\n", .{cfg.listen_address});
    try std.fs.File.stdout().writeAll("  subnet:     {s}/{d}.{d}.{d}.{d}\n", .{
        cfg.subnet, mask_a, mask_b, mask_c, mask_d,
    });
    try std.fs.File.stdout().writeAll("  router:     {s}\n", .{cfg.router});
    try std.fs.File.stdout().writeAll("  lease_time: {d}s\n", .{cfg.lease_time});
    try std.fs.File.stdout().writeAll("  state_dir:  {s}\n", .{cfg.state_dir});

    // Initialize state store
    const store = state_mod.StateStore.init(allocator, cfg.state_dir) catch |err| {
        fatal("Failed to initialize state store: {s}", .{@errorName(err)});
    };
    defer store.deinit();

    try std.fs.File.stdout().writeAll("State store initialized\n", .{});

    // Start DNS updater
    const dns_updater = dns.create_updater(allocator, &cfg.dns_update, store) catch |err| {
        fatal("Failed to initialize DNS updater: {s}", .{@errorName(err)});
    };
    defer dns_updater.cleanup();

    dns_updater.run() catch |err| {
        try std.fs.File.stdout().writeAll("DNS updater warning: {s}\n", .{@errorName(err)});
    };

    // Create and run DHCP server
    const dhcp_server = dhcp.create_server(allocator, &cfg, store) catch |err| {
        fatal("Failed to create DHCP server: {s}", .{@errorName(err)});
    };
    defer dhcp_server.deinit();

    try std.fs.File.stdout().writeAll("Starting DHCP server...\n", .{});
    dhcp_server.run() catch |err| {
        fatal("DHCP server error: {s}", .{@errorName(err)});
    };
}
