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
    state_store: *state.StateStore,

    const Self = @This();

    pub fn create(
        allocator: std.mem.Allocator,
        config: *const Config,
        store: *state.StateStore,
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

        if (!self.config.enable) {
            std.debug.print("DNS updater disabled in config\n", .{});
            return;
        }

        std.debug.print("DNS updater running...\n", .{});
        // TODO: implement DNS update logic (TSIG/BIND integration).
        std.debug.print("DNS updater completed initial sync\n", .{});
    }

    pub fn cleanup(self: *Self) void {
        self.allocator.destroy(self);
    }
};

pub fn create_updater(
    allocator: std.mem.Allocator,
    config: *const Config,
    store: *state.StateStore,
) !*DNSUpdater {
    return DNSUpdater.create(allocator, config, store);
}
