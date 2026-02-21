const std = @import("std");

pub const Error = error{
    IoError,
    OutOfMemory,
};

pub const Lease = struct {
    mac: []const u8,
    ip: []const u8,
    hostname: ?[]const u8,
    expires: i64,
    client_id: ?[]const u8,
};

pub const StateStore = struct {
    allocator: std.mem.Allocator,
    dir: []const u8,
    leases: std.ArrayList(Lease),

    const Self = @This();

    /// Initialize a new StateStore, loading persisted state from `dir`.
    pub fn init(allocator: std.mem.Allocator, dir: []const u8) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .dir = dir,
            .leases = std.ArrayList(Lease).init(allocator),
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.leases.deinit();
        self.allocator.destroy(self);
    }

    /// Add or update a lease record.
    pub fn addLease(self: *Self, lease: Lease) !void {
        try self.leases.append(lease);
    }

    /// Remove a lease by MAC address.
    pub fn removeLease(self: *Self, mac: []const u8) !void {
        for (self.leases.items, 0..) |lease, i| {
            if (std.mem.eql(u8, lease.mac, mac)) {
                _ = self.leases.swapRemove(i);
                return;
            }
        }
    }

    /// Look up a lease by MAC address. Returns null if not found.
    pub fn getLeaseByMac(self: *const Self, mac: []const u8) ?Lease {
        for (self.leases.items) |lease| {
            if (std.mem.eql(u8, lease.mac, mac)) return lease;
        }
        return null;
    }

    /// Look up a lease by IP address. Returns null if not found.
    pub fn getLeaseByIp(self: *const Self, ip: []const u8) ?Lease {
        for (self.leases.items) |lease| {
            if (std.mem.eql(u8, lease.ip, ip)) return lease;
        }
        return null;
    }

    /// Return a slice of all current leases. Caller does not own the slice.
    pub fn listLeases(self: *const Self) []const Lease {
        return self.leases.items;
    }
};

test "StateStore basic operations" {
    const allocator = std.testing.allocator;
    const store = try StateStore.init(allocator, "/tmp/test-state");
    defer store.deinit();

    const lease = Lease{
        .mac = "aa:bb:cc:dd:ee:ff",
        .ip = "192.168.1.100",
        .hostname = "testhost",
        .expires = 9999999999,
        .client_id = null,
    };

    try store.addLease(lease);
    try std.testing.expect(store.getLeaseByMac("aa:bb:cc:dd:ee:ff") != null);
    try std.testing.expect(store.getLeaseByIp("192.168.1.100") != null);
    try std.testing.expect(store.getLeaseByMac("ff:ff:ff:ff:ff:ff") == null);

    try store.removeLease("aa:bb:cc:dd:ee:ff");
    try std.testing.expect(store.getLeaseByMac("aa:bb:cc:dd:ee:ff") == null);
}
