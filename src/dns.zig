const std = @import("std");
const state_mod = @import("./state.zig");
const config_mod = @import("./config.zig");

pub const Error = error{
    InvalidConfig,
    OutOfMemory,
};

pub const Config = config_mod.DnsUpdateConfig;

pub const DNSUpdater = struct {
    allocator: std.mem.Allocator,
    cfg: *const Config,
    store: *const state_mod.StateStore,

    const Self = @This();

    pub fn create(
        allocator: std.mem.Allocator,
        cfg: *const Config,
        store: *const state_mod.StateStore,
    ) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .cfg = cfg,
            .store = store,
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self);
    }

    /// Perform an initial DNS sync and enter the update loop.
    pub fn run(self: *Self) !void {
        const stdout = std.io.getStdOut().writer();

        if (!self.cfg.enable) {
            try stdout.print("DNS updater disabled in config\n", .{});
            return;
        }

        try stdout.print("DNS updater running against server {s} zone {s}\n", .{
            self.cfg.server,
            self.cfg.zone,
        });

        // Initial sync: iterate all leases and push A records
        const leases = self.store.listLeases();
        for (leases) |lease| {
            try stdout.print("  sync: {s} -> {s}\n", .{ lease.mac, lease.ip });
            // TODO: send DNS UPDATE (RFC 2136) for each lease
        }

        try stdout.print("DNS updater completed initial sync ({d} leases)\n", .{leases.len});
    }

    pub fn cleanup(self: *Self) void {
        self.deinit();
    }
};

pub fn create_updater(
    allocator: std.mem.Allocator,
    cfg: *const Config,
    store: *const state_mod.StateStore,
) !*DNSUpdater {
    return DNSUpdater.create(allocator, cfg, store);
}
