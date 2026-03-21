const std = @import("std");

pub const Error = error{
    IoError,
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
    leases: std.StringHashMap(Lease),

    pub fn init(allocator: std.mem.Allocator, dir: []const u8) !*StateStore {
        const self = try allocator.create(StateStore);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .dir = dir,
            .leases = std.StringHashMap(Lease).init(allocator),
        };

        // Create the state directory (no-op if it already exists).
        try std.fs.cwd().makePath(dir);

        self.load() catch |err| switch (err) {
            error.FileNotFound => {},
            else => std.log.warn("Could not load lease state ({s}), starting fresh", .{@errorName(err)}),
        };

        return self;
    }

    pub fn deinit(store: *StateStore) void {
        var it = store.leases.valueIterator();
        while (it.next()) |lease| {
            store.allocator.free(lease.mac);
            store.allocator.free(lease.ip);
            if (lease.hostname) |h| store.allocator.free(h);
            if (lease.client_id) |c| store.allocator.free(c);
        }
        store.leases.deinit();
        store.allocator.destroy(store);
    }

    /// Add or update a lease. The store dupes all strings; caller need not keep them alive.
    pub fn addLease(store: *StateStore, lease: Lease) !void {
        // Remove old entry for this MAC if present.
        if (store.leases.fetchRemove(lease.mac)) |kv| {
            store.allocator.free(kv.value.mac);
            store.allocator.free(kv.value.ip);
            if (kv.value.hostname) |h| store.allocator.free(h);
            if (kv.value.client_id) |c| store.allocator.free(c);
        }

        const mac = try store.allocator.dupe(u8, lease.mac);
        errdefer store.allocator.free(mac);
        const ip = try store.allocator.dupe(u8, lease.ip);
        errdefer store.allocator.free(ip);
        const hostname: ?[]const u8 = if (lease.hostname) |h| try store.allocator.dupe(u8, h) else null;
        errdefer if (hostname) |h| store.allocator.free(h);
        const client_id: ?[]const u8 = if (lease.client_id) |c| try store.allocator.dupe(u8, c) else null;
        errdefer if (client_id) |c| store.allocator.free(c);

        try store.leases.put(mac, .{
            .mac = mac,
            .ip = ip,
            .hostname = hostname,
            .expires = lease.expires,
            .client_id = client_id,
        });

        store.save() catch |err| {
            std.log.warn("Failed to persist lease state ({s})", .{@errorName(err)});
        };
    }

    /// Remove the lease for the given MAC. No-op if not found.
    pub fn removeLease(store: *StateStore, mac: []const u8) void {
        if (store.leases.fetchRemove(mac)) |kv| {
            store.allocator.free(kv.value.mac);
            store.allocator.free(kv.value.ip);
            if (kv.value.hostname) |h| store.allocator.free(h);
            if (kv.value.client_id) |c| store.allocator.free(c);
            store.save() catch |err| {
                std.log.warn("Failed to persist lease state ({s})", .{@errorName(err)});
            };
        }
    }

    /// Look up a lease by MAC address. Returns null if not found or expired.
    pub fn getLeaseByMac(store: *StateStore, mac: []const u8) ?Lease {
        const lease = store.leases.get(mac) orelse return null;
        if (lease.expires <= std.time.timestamp()) return null;
        return lease;
    }

    /// Look up a lease by IP address. Returns null if not found or expired.
    pub fn getLeaseByIp(store: *StateStore, ip: []const u8) ?Lease {
        const now = std.time.timestamp();
        var it = store.leases.valueIterator();
        while (it.next()) |lease| {
            if (lease.expires <= now) continue;
            if (std.mem.eql(u8, lease.ip, ip)) return lease.*;
        }
        return null;
    }

    /// Remove all expired leases from memory and persist.
    pub fn pruneExpired(store: *StateStore) void {
        const now = std.time.timestamp();
        var to_remove: [64][]const u8 = undefined;
        var count: usize = 0;
        var it = store.leases.keyIterator();
        while (it.next()) |key| {
            const lease = store.leases.get(key.*).?;
            if (lease.expires <= now) {
                if (count < to_remove.len) {
                    to_remove[count] = key.*;
                    count += 1;
                }
            }
        }
        for (to_remove[0..count]) |mac| {
            store.removeLease(mac);
        }
    }

    /// Returns a slice of all leases. Caller owns the slice (free it) but not the string fields.
    pub fn listLeases(store: *StateStore) ![]Lease {
        const list = try store.allocator.alloc(Lease, store.leases.count());
        var it = store.leases.valueIterator();
        var i: usize = 0;
        while (it.next()) |lease| {
            list[i] = lease.*;
            i += 1;
        }
        return list;
    }

    fn leasesPath(store: *StateStore) ![]u8 {
        return std.fs.path.join(store.allocator, &.{ store.dir, "leases.json" });
    }

    fn save(store: *StateStore) !void {
        const path = try store.leasesPath();
        defer store.allocator.free(path);

        const list = try store.listLeases();
        defer store.allocator.free(list);

        const json_str = try std.json.Stringify.valueAlloc(store.allocator, list, .{});
        defer store.allocator.free(json_str);

        const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer file.close();
        try file.writeAll(json_str);
    }

    fn load(store: *StateStore) !void {
        const path = try store.leasesPath();
        defer store.allocator.free(path);

        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(store.allocator, 10 * 1024 * 1024);
        defer store.allocator.free(content);

        const parsed = try std.json.parseFromSlice([]Lease, store.allocator, content, .{});
        defer parsed.deinit();

        const now = std.time.timestamp();
        for (parsed.value) |lease| {
            if (lease.expires <= now) continue; // Skip expired leases.
            const mac = try store.allocator.dupe(u8, lease.mac);
            errdefer store.allocator.free(mac);
            const ip = try store.allocator.dupe(u8, lease.ip);
            errdefer store.allocator.free(ip);
            const hostname: ?[]const u8 = if (lease.hostname) |h| try store.allocator.dupe(u8, h) else null;
            errdefer if (hostname) |h| store.allocator.free(h);
            const client_id: ?[]const u8 = if (lease.client_id) |c| try store.allocator.dupe(u8, c) else null;
            errdefer if (client_id) |c| store.allocator.free(c);
            try store.leases.put(mac, .{
                .mac = mac,
                .ip = ip,
                .hostname = hostname,
                .expires = lease.expires,
                .client_id = client_id,
            });
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Create a store that bypasses init (no disk I/O). Uses /tmp so save()
/// calls that reach disk don't pollute the project tree.
fn makeTestStore(allocator: std.mem.Allocator) !*StateStore {
    const store = try allocator.create(StateStore);
    store.* = .{
        .allocator = allocator,
        .dir = "/tmp",
        .leases = std.StringHashMap(Lease).init(allocator),
    };
    return store;
}

/// Insert a lease directly into the map (bypasses save).
fn putLease(store: *StateStore, mac: []const u8, ip: []const u8, expires: i64) !void {
    const mac_owned = try store.allocator.dupe(u8, mac);
    errdefer store.allocator.free(mac_owned);
    const ip_owned = try store.allocator.dupe(u8, ip);
    errdefer store.allocator.free(ip_owned);
    try store.leases.put(mac_owned, .{
        .mac = mac_owned,
        .ip = ip_owned,
        .hostname = null,
        .expires = expires,
        .client_id = null,
    });
}

test "getLeaseByMac returns valid lease" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    try putLease(store, "aa:bb:cc:dd:ee:ff", "192.168.1.10", std.time.timestamp() + 3600);

    const lease = store.getLeaseByMac("aa:bb:cc:dd:ee:ff");
    try std.testing.expect(lease != null);
    try std.testing.expectEqualStrings("192.168.1.10", lease.?.ip);
}

test "getLeaseByMac returns null for expired lease" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    try putLease(store, "aa:bb:cc:dd:ee:ff", "192.168.1.10", std.time.timestamp() - 1);

    try std.testing.expect(store.getLeaseByMac("aa:bb:cc:dd:ee:ff") == null);
}

test "getLeaseByIp returns valid lease" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    try putLease(store, "aa:bb:cc:dd:ee:ff", "192.168.1.10", std.time.timestamp() + 3600);

    const lease = store.getLeaseByIp("192.168.1.10");
    try std.testing.expect(lease != null);
    try std.testing.expectEqualStrings("aa:bb:cc:dd:ee:ff", lease.?.mac);
}

test "getLeaseByIp returns null for expired lease" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    try putLease(store, "aa:bb:cc:dd:ee:ff", "192.168.1.10", std.time.timestamp() - 1);

    try std.testing.expect(store.getLeaseByIp("192.168.1.10") == null);
}

test "pruneExpired removes expired and keeps valid" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    try putLease(store, "aa:bb:cc:dd:ee:01", "192.168.1.10", std.time.timestamp() - 1); // expired
    try putLease(store, "aa:bb:cc:dd:ee:02", "192.168.1.11", std.time.timestamp() + 3600); // valid

    store.pruneExpired();

    try std.testing.expectEqual(@as(usize, 1), store.leases.count());
    try std.testing.expect(store.leases.get("aa:bb:cc:dd:ee:01") == null);
    try std.testing.expect(store.leases.get("aa:bb:cc:dd:ee:02") != null);
}
