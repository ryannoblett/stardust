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
    reserved: bool = false,
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
            .reserved = lease.reserved,
        });

        store.save() catch |err| {
            std.log.warn("Failed to persist lease state ({s})", .{@errorName(err)});
        };
    }

    /// Remove the lease for the given MAC. No-op if not found.
    /// For reserved leases, sets expires=0 (inactive) instead of deleting.
    pub fn removeLease(store: *StateStore, mac: []const u8) void {
        if (store.leases.getPtr(mac)) |lease_ptr| {
            if (lease_ptr.reserved) {
                lease_ptr.expires = 0;
                store.save() catch |err| {
                    std.log.warn("Failed to persist lease state ({s})", .{@errorName(err)});
                };
                return;
            }
        }
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

    /// Look up a lease by client identifier (option 61, hex-encoded). Returns null if not found or expired.
    pub fn getLeaseByClientId(store: *StateStore, client_id: []const u8) ?Lease {
        const now = std.time.timestamp();
        var it = store.leases.valueIterator();
        while (it.next()) |lease| {
            if (lease.expires <= now) continue;
            if (lease.client_id) |cid| {
                if (std.mem.eql(u8, cid, client_id)) return lease.*;
            }
        }
        return null;
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
            if (lease.reserved) continue;
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

    /// Returns a reservation (reserved=true) for this MAC regardless of expiry.
    pub fn getReservationByMac(store: *StateStore, mac: []const u8) ?Lease {
        const lease = store.leases.get(mac) orelse return null;
        if (!lease.reserved) return null;
        return lease;
    }

    /// Returns a reservation matching this hex-encoded client_id regardless of expiry.
    pub fn getReservationByClientId(store: *StateStore, client_id: []const u8) ?Lease {
        var it = store.leases.valueIterator();
        while (it.next()) |lease| {
            if (!lease.reserved) continue;
            if (lease.client_id) |cid| {
                if (std.mem.eql(u8, cid, client_id)) return lease.*;
            }
        }
        return null;
    }

    /// Returns a reservation holding this IP regardless of expiry.
    pub fn getReservationByIp(store: *StateStore, ip: []const u8) ?Lease {
        var it = store.leases.valueIterator();
        while (it.next()) |lease| {
            if (!lease.reserved) continue;
            if (std.mem.eql(u8, lease.ip, ip)) return lease.*;
        }
        return null;
    }

    /// Seed a reservation. Preserves expiry if a lease for this MAC already exists.
    pub fn addReservation(store: *StateStore, mac: []const u8, ip: []const u8,
        hostname: ?[]const u8, client_id: ?[]const u8) !void {
        const existing_expires: i64 = if (store.leases.get(mac)) |existing| existing.expires else 0;
        try store.addLease(.{
            .mac = mac,
            .ip = ip,
            .hostname = hostname,
            .expires = existing_expires,
            .client_id = client_id,
            .reserved = true,
        });
    }

    fn leasesPath(store: *StateStore) ![]u8 {
        return std.fs.path.join(store.allocator, &.{ store.dir, "leases.json" });
    }

    fn save(store: *StateStore) !void {
        const path = try store.leasesPath();
        defer store.allocator.free(path);

        const tmp_path = try std.fmt.allocPrint(store.allocator, "{s}.tmp", .{path});
        defer store.allocator.free(tmp_path);

        const list = try store.listLeases();
        defer store.allocator.free(list);

        const json_str = try std.json.Stringify.valueAlloc(store.allocator, list, .{});
        defer store.allocator.free(json_str);

        // Write to a temp file then atomically rename into place.
        // Prevents corruption if the process is killed mid-write.
        const file = try std.fs.cwd().createFile(tmp_path, .{ .truncate = true });
        errdefer std.fs.cwd().deleteFile(tmp_path) catch {};
        try file.writeAll(json_str);
        file.close();

        try std.fs.rename(std.fs.cwd(), tmp_path, std.fs.cwd(), path);
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
            if (!lease.reserved and lease.expires <= now) continue; // Skip expired non-reserved leases.
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
                .reserved = lease.reserved,
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

/// Insert a reserved lease directly (bypasses save).
fn putReservation(store: *StateStore, mac: []const u8, ip: []const u8, expires: i64, client_id: ?[]const u8) !void {
    const mac_owned = try store.allocator.dupe(u8, mac);
    errdefer store.allocator.free(mac_owned);
    const ip_owned = try store.allocator.dupe(u8, ip);
    errdefer store.allocator.free(ip_owned);
    const cid_owned: ?[]const u8 = if (client_id) |c| try store.allocator.dupe(u8, c) else null;
    errdefer if (cid_owned) |c| store.allocator.free(c);
    try store.leases.put(mac_owned, .{
        .mac = mac_owned,
        .ip = ip_owned,
        .hostname = null,
        .expires = expires,
        .client_id = cid_owned,
        .reserved = true,
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

test "getReservationByMac returns inactive reservation (expires=0)" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    try putReservation(store, "aa:bb:cc:dd:ee:ff", "192.168.1.50", 0, null);

    const res = store.getReservationByMac("aa:bb:cc:dd:ee:ff");
    try std.testing.expect(res != null);
    try std.testing.expectEqualStrings("192.168.1.50", res.?.ip);
}

test "getReservationByMac returns null for non-reserved lease" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    try putLease(store, "aa:bb:cc:dd:ee:ff", "192.168.1.10", std.time.timestamp() + 3600);

    try std.testing.expect(store.getReservationByMac("aa:bb:cc:dd:ee:ff") == null);
}

test "getReservationByClientId returns reservation by client_id" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    try putReservation(store, "aa:bb:cc:dd:ee:ff", "192.168.1.50", 0, "01aabbccddeeff");

    const res = store.getReservationByClientId("01aabbccddeeff");
    try std.testing.expect(res != null);
    try std.testing.expectEqualStrings("192.168.1.50", res.?.ip);
    try std.testing.expect(store.getReservationByClientId("deadbeef") == null);
}

test "pruneExpired does not remove reserved leases" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    try putReservation(store, "aa:bb:cc:dd:ee:01", "192.168.1.50", 0, null); // inactive reservation
    try putReservation(store, "aa:bb:cc:dd:ee:02", "192.168.1.51", std.time.timestamp() - 1, null); // expired reservation
    try putLease(store, "aa:bb:cc:dd:ee:03", "192.168.1.10", std.time.timestamp() - 1); // expired regular

    store.pruneExpired();

    try std.testing.expectEqual(@as(usize, 2), store.leases.count());
    try std.testing.expect(store.leases.get("aa:bb:cc:dd:ee:01") != null);
    try std.testing.expect(store.leases.get("aa:bb:cc:dd:ee:02") != null);
    try std.testing.expect(store.leases.get("aa:bb:cc:dd:ee:03") == null);
}

test "removeLease on reserved lease zeros expiry, keeps entry" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    try putReservation(store, "aa:bb:cc:dd:ee:ff", "192.168.1.50", std.time.timestamp() + 3600, null);

    store.removeLease("aa:bb:cc:dd:ee:ff");

    // Entry still present
    const entry = store.leases.get("aa:bb:cc:dd:ee:ff");
    try std.testing.expect(entry != null);
    try std.testing.expectEqual(@as(i64, 0), entry.?.expires);
    try std.testing.expect(entry.?.reserved);
}

test "addReservation preserves expiry of existing lease" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    const future = std.time.timestamp() + 3600;
    try putLease(store, "aa:bb:cc:dd:ee:ff", "192.168.1.10", future);

    try store.addReservation("aa:bb:cc:dd:ee:ff", "192.168.1.50", null, null);

    const entry = store.leases.get("aa:bb:cc:dd:ee:ff");
    try std.testing.expect(entry != null);
    try std.testing.expectEqual(future, entry.?.expires);
    try std.testing.expect(entry.?.reserved);
    try std.testing.expectEqualStrings("192.168.1.50", entry.?.ip);
}
