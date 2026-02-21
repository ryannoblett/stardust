const std = @import("std");
const state = @import("./state.zig");

pub const Error = error{
    InvalidConfig,
};

pub const Config = struct {
    enable: bool,
    server: []const u8,
    zone: []const u8,
    key_name: []const u8,
    key_file: []const u8,
};

pub const DNSUpdater = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    state_store: *const state.StateStore,

    const Self = @This();

    pub fn create(
        allocator: std.mem.Allocator,
        config: *const Config,
        store: *const state.StateStore,
    ) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .config = config,
            .state_store = store,
        };
        return self;
    }

    pub fn run(self: *Self) !void {
        const stdout = td.fs.File.stdout().writeAll();

        if (!self.config.enable) {
            try stdout.print("DNS updater disabled in config\n", .{});
            return;
        }

        try stdout.print("DNS updater running...\n", .{});

        // This would be replaced with actual DNS update logic.
        // For now, just verify we can access the state.
        _ = try self.state_store.listLeases();

        try stdout.print("DNS updater completed initial sync\n", .{});
    }

    pub fn cleanup(self: *Self) void {
        self.allocator.destroy(self);
    }
};

pub fn create_updater(
    allocator: std.mem.Allocator,
    config: *const Config,
    store: *const state.StateStore,
) !*DNSUpdater {
    return DNSUpdater.create(allocator, config, store);
}
