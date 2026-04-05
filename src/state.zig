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
    reserved: bool = false,
    last_modified: i64 = 0, // unix timestamp; 0 = unknown (old JSON records)
    local: bool = false, // true = this server issued the DHCPACK; not persisted (defaults false on load/sync)
    forcerenew_nonce: ?[]const u8 = null, // 32-char hex string (16 random bytes); RFC 6704
};

pub const StateStore = struct {
    allocator: std.mem.Allocator,
    dir: []const u8,
    leases: std.StringHashMap(Lease),
    lock: std.Thread.RwLock = .{},

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

        // load() is called before any concurrent access so no lock needed.
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
            if (lease.forcerenew_nonce) |n| store.allocator.free(n);
        }
        store.leases.deinit();
        store.allocator.destroy(store);
    }

    /// Add or update a lease. The store dupes all strings; caller need not keep them alive.
    pub fn addLease(store: *StateStore, lease: Lease) !void {
        store.lock.lock();
        defer store.lock.unlock();
        try store.addLeaseUnlocked(lease);
        store.saveUnlocked() catch |err| {
            std.log.warn("Failed to persist lease state ({s})", .{@errorName(err)});
        };
    }

    /// Unconditionally delete a lease entry regardless of its reserved flag.
    /// Used when syncing config reservations: a MAC removed from config must be
    /// fully purged even if it currently has reserved=true.
    pub fn forceRemoveLease(store: *StateStore, mac: []const u8) void {
        store.lock.lock();
        defer store.lock.unlock();
        if (store.forceRemoveLeaseUnlocked(mac)) {
            store.saveUnlocked() catch |err| {
                std.log.warn("Failed to persist lease state ({s})", .{@errorName(err)});
            };
        }
    }

    /// Remove the lease for the given MAC. No-op if not found.
    /// For reserved leases, sets expires=0 (inactive) instead of deleting.
    pub fn removeLease(store: *StateStore, mac: []const u8) void {
        store.lock.lock();
        defer store.lock.unlock();
        if (store.removeLeaseUnlocked(mac)) {
            store.saveUnlocked() catch |err| {
                std.log.warn("Failed to persist lease state ({s})", .{@errorName(err)});
            };
        }
    }

    /// Look up a lease by MAC address. Returns null if not found or expired.
    pub fn getLeaseByMac(store: *StateStore, mac: []const u8) ?Lease {
        store.lock.lockShared();
        defer store.lock.unlockShared();
        const lease = store.leases.get(mac) orelse return null;
        if (lease.expires <= std.time.timestamp()) return null;
        return lease;
    }

    /// Look up a lease by client identifier (option 61, hex-encoded). Returns null if not found or expired.
    pub fn getLeaseByClientId(store: *StateStore, client_id: []const u8) ?Lease {
        store.lock.lockShared();
        defer store.lock.unlockShared();
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
        store.lock.lockShared();
        defer store.lock.unlockShared();
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
        store.lock.lock();
        defer store.lock.unlock();
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
        var removed: usize = 0;
        for (to_remove[0..count]) |mac| {
            if (store.removeLeaseUnlocked(mac)) removed += 1;
        }
        if (removed > 0) {
            store.saveUnlocked() catch |err| {
                std.log.warn("Failed to persist lease state ({s})", .{@errorName(err)});
            };
        }
    }

    /// Returns a slice of all leases. Caller owns the slice (free it) but not the string fields.
    pub fn listLeases(store: *StateStore) ![]Lease {
        store.lock.lockShared();
        defer store.lock.unlockShared();
        return store.listLeasesUnlocked();
    }

    /// Returns a reservation (reserved=true) for this MAC regardless of expiry.
    pub fn getReservationByMac(store: *StateStore, mac: []const u8) ?Lease {
        store.lock.lockShared();
        defer store.lock.unlockShared();
        const lease = store.leases.get(mac) orelse return null;
        if (!lease.reserved) return null;
        return lease;
    }

    /// Returns a reservation matching this hex-encoded client_id regardless of expiry.
    pub fn getReservationByClientId(store: *StateStore, client_id: []const u8) ?Lease {
        store.lock.lockShared();
        defer store.lock.unlockShared();
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
        store.lock.lockShared();
        defer store.lock.unlockShared();
        var it = store.leases.valueIterator();
        while (it.next()) |lease| {
            if (!lease.reserved) continue;
            if (std.mem.eql(u8, lease.ip, ip)) return lease.*;
        }
        return null;
    }

    /// Seed a reservation. Preserves expiry if a lease for this MAC already exists.
    pub fn addReservation(store: *StateStore, mac: []const u8, ip: []const u8, hostname: ?[]const u8, client_id: ?[]const u8) !void {
        store.lock.lock();
        defer store.lock.unlock();
        const existing_expires: i64 = if (store.leases.get(mac)) |existing| existing.expires else 0;
        try store.addLeaseUnlocked(.{
            .mac = mac,
            .ip = ip,
            .hostname = hostname,
            .expires = existing_expires,
            .client_id = client_id,
            .reserved = true,
        });
        store.saveUnlocked() catch |err| {
            std.log.warn("Failed to persist lease state ({s})", .{@errorName(err)});
        };
    }

    // -----------------------------------------------------------------------
    // Internal: unlocked implementations (caller must hold appropriate lock)
    // -----------------------------------------------------------------------

    /// Add or update a lease without acquiring a lock or saving. Caller must hold write lock.
    fn addLeaseUnlocked(store: *StateStore, lease: Lease) !void {
        // Allocate all new strings BEFORE removing the old entry so that OOM
        // does not cause data loss (the old lease stays intact on failure).
        const mac = try store.allocator.dupe(u8, lease.mac);
        errdefer store.allocator.free(mac);
        const ip = try store.allocator.dupe(u8, lease.ip);
        errdefer store.allocator.free(ip);
        const hostname: ?[]const u8 = if (lease.hostname) |h| try store.allocator.dupe(u8, h) else null;
        errdefer if (hostname) |h| store.allocator.free(h);
        const client_id: ?[]const u8 = if (lease.client_id) |c| try store.allocator.dupe(u8, c) else null;
        errdefer if (client_id) |c| store.allocator.free(c);
        const nonce: ?[]const u8 = if (lease.forcerenew_nonce) |n| try store.allocator.dupe(u8, n) else null;
        errdefer if (nonce) |n| store.allocator.free(n);

        // Now that all allocations succeeded, remove the old entry (if any).
        if (store.leases.fetchRemove(lease.mac)) |kv| {
            store.allocator.free(kv.value.mac);
            store.allocator.free(kv.value.ip);
            if (kv.value.hostname) |h| store.allocator.free(h);
            if (kv.value.client_id) |c| store.allocator.free(c);
            if (kv.value.forcerenew_nonce) |n| store.allocator.free(n);
        }

        try store.leases.put(mac, .{
            .mac = mac,
            .ip = ip,
            .hostname = hostname,
            .expires = lease.expires,
            .client_id = client_id,
            .reserved = lease.reserved,
            // Preserve the caller's last_modified if set; otherwise stamp now.
            // Sync peers supply the original timestamp so lease hashes stay in sync.
            .last_modified = if (lease.last_modified != 0) lease.last_modified else std.time.timestamp(),
            .forcerenew_nonce = nonce,
        });
    }

    /// Remove a lease (reserved: deactivate; non-reserved: delete). Returns true if any change.
    /// Caller must hold write lock. Does NOT save.
    fn removeLeaseUnlocked(store: *StateStore, mac: []const u8) bool {
        if (store.leases.getPtr(mac)) |lease_ptr| {
            if (lease_ptr.reserved) {
                lease_ptr.expires = 0;
                lease_ptr.last_modified = std.time.timestamp();
                return true;
            }
        }
        if (store.leases.fetchRemove(mac)) |kv| {
            store.allocator.free(kv.value.mac);
            store.allocator.free(kv.value.ip);
            if (kv.value.hostname) |h| store.allocator.free(h);
            if (kv.value.client_id) |c| store.allocator.free(c);
            if (kv.value.forcerenew_nonce) |n| store.allocator.free(n);
            return true;
        }
        return false;
    }

    /// Unconditionally remove a lease. Returns true if something was removed.
    /// Caller must hold write lock. Does NOT save.
    fn forceRemoveLeaseUnlocked(store: *StateStore, mac: []const u8) bool {
        if (store.leases.fetchRemove(mac)) |kv| {
            store.allocator.free(kv.value.mac);
            store.allocator.free(kv.value.ip);
            if (kv.value.hostname) |h| store.allocator.free(h);
            if (kv.value.client_id) |c| store.allocator.free(c);
            if (kv.value.forcerenew_nonce) |n| store.allocator.free(n);
            return true;
        }
        return false;
    }

    /// Collect all leases into an allocated slice. Caller must hold at least a read lock.
    fn listLeasesUnlocked(store: *StateStore) ![]Lease {
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

    /// Persist leases to disk. Caller must hold write lock (or be in single-threaded init).
    fn saveUnlocked(store: *StateStore) !void {
        const path = try store.leasesPath();
        defer store.allocator.free(path);

        const tmp_path = try std.fmt.allocPrint(store.allocator, "{s}.tmp", .{path});
        defer store.allocator.free(tmp_path);

        const list = try store.listLeasesUnlocked();
        defer store.allocator.free(list);

        const json_str = try std.json.Stringify.valueAlloc(store.allocator, list, .{});
        defer store.allocator.free(json_str);

        // Write to a temp file then atomically rename into place.
        // Prevents corruption if the process is killed mid-write.
        const file = try std.fs.cwd().createFile(tmp_path, .{ .truncate = true });
        errdefer std.fs.cwd().deleteFile(tmp_path) catch {};
        try file.writeAll(json_str);
        file.close();

        std.fs.rename(std.fs.cwd(), tmp_path, std.fs.cwd(), path) catch |err| {
            std.fs.cwd().deleteFile(tmp_path) catch {};
            return err;
        };
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
            const nonce: ?[]const u8 = if (lease.forcerenew_nonce) |n| try store.allocator.dupe(u8, n) else null;
            errdefer if (nonce) |n| store.allocator.free(n);
            if (store.leases.contains(mac)) {
                std.log.warn("leases.json: duplicate MAC {s}, keeping last entry", .{mac});
            }
            try store.leases.put(mac, .{
                .mac = mac,
                .ip = ip,
                .hostname = hostname,
                .expires = lease.expires,
                .client_id = client_id,
                .reserved = lease.reserved,
                .last_modified = lease.last_modified,
                .forcerenew_nonce = nonce,
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

test "addLease sets last_modified to current time" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    const before = std.time.timestamp();
    try store.addLease(.{
        .mac = "aa:bb:cc:dd:ee:ff",
        .ip = "192.168.1.10",
        .hostname = null,
        .expires = before + 3600,
        .client_id = null,
    });
    const after = std.time.timestamp();

    const entry = store.leases.get("aa:bb:cc:dd:ee:ff");
    try std.testing.expect(entry != null);
    try std.testing.expect(entry.?.last_modified >= before);
    try std.testing.expect(entry.?.last_modified <= after);
}

test "removeLease on reserved sets last_modified" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    try putReservation(store, "aa:bb:cc:dd:ee:ff", "192.168.1.50", std.time.timestamp() + 3600, null);

    const before = std.time.timestamp();
    store.removeLease("aa:bb:cc:dd:ee:ff");
    const after = std.time.timestamp();

    const entry = store.leases.get("aa:bb:cc:dd:ee:ff");
    try std.testing.expect(entry != null);
    try std.testing.expectEqual(@as(i64, 0), entry.?.expires);
    try std.testing.expect(entry.?.last_modified >= before);
    try std.testing.expect(entry.?.last_modified <= after);
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

test "getLeaseByMac returns null when expires equals current time" {
    // expires <= now is the expiry condition, so expires == now must be treated as expired.
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    const now = std.time.timestamp();
    try putLease(store, "aa:bb:cc:dd:ee:ff", "192.168.1.10", now);

    try std.testing.expect(store.getLeaseByMac("aa:bb:cc:dd:ee:ff") == null);
}

test "getLeaseByIp returns null when expires equals current time" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    const now = std.time.timestamp();
    try putLease(store, "aa:bb:cc:dd:ee:ff", "192.168.1.10", now);

    try std.testing.expect(store.getLeaseByIp("192.168.1.10") == null);
}

test "getLeaseByClientId returns lease with matching client_id" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    const mac = try store.allocator.dupe(u8, "aa:bb:cc:dd:ee:ff");
    try store.leases.put(
        mac,
        .{
            .mac = mac,
            .ip = try store.allocator.dupe(u8, "192.168.1.10"),
            .hostname = null,
            .expires = std.time.timestamp() + 3600,
            .client_id = try store.allocator.dupe(u8, "01aabbccddeeff"),
        },
    );

    const lease = store.getLeaseByClientId("01aabbccddeeff");
    try std.testing.expect(lease != null);
    try std.testing.expectEqualStrings("192.168.1.10", lease.?.ip);
}

test "getLeaseByClientId returns null for expired lease" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    const mac = try store.allocator.dupe(u8, "aa:bb:cc:dd:ee:ff");
    try store.leases.put(
        mac,
        .{
            .mac = mac,
            .ip = try store.allocator.dupe(u8, "192.168.1.10"),
            .hostname = null,
            .expires = std.time.timestamp() - 1,
            .client_id = try store.allocator.dupe(u8, "01aabbccddeeff"),
        },
    );

    try std.testing.expect(store.getLeaseByClientId("01aabbccddeeff") == null);
}

test "getLeaseByClientId returns null when no lease has matching client_id" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    try putLease(store, "aa:bb:cc:dd:ee:ff", "192.168.1.10", std.time.timestamp() + 3600);

    try std.testing.expect(store.getLeaseByClientId("01aabbccddeeff") == null);
}

test "getReservationByIp returns reservation for matching IP" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    try putReservation(store, "aa:bb:cc:dd:ee:ff", "192.168.1.50", 0, null);

    const lease = store.getReservationByIp("192.168.1.50");
    try std.testing.expect(lease != null);
    try std.testing.expectEqualStrings("aa:bb:cc:dd:ee:ff", lease.?.mac);
}

test "getReservationByIp returns null for non-reserved lease" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    try putLease(store, "aa:bb:cc:dd:ee:ff", "192.168.1.50", std.time.timestamp() + 3600);

    try std.testing.expect(store.getReservationByIp("192.168.1.50") == null);
}

test "getReservationByIp returns null for unknown IP" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    try std.testing.expect(store.getReservationByIp("192.168.1.99") == null);
}

test "listLeases returns all leases including expired and reserved" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    // active lease
    try putLease(store, "aa:bb:cc:dd:ee:01", "192.168.1.10", std.time.timestamp() + 3600);
    // expired lease
    try putLease(store, "aa:bb:cc:dd:ee:02", "192.168.1.11", std.time.timestamp() - 1);
    // reserved (expires=0)
    try putReservation(store, "aa:bb:cc:dd:ee:03", "192.168.1.50", 0, null);

    const list = try store.listLeases();
    defer store.allocator.free(list);
    try std.testing.expectEqual(@as(usize, 3), list.len);
}

test "forceRemoveLease removes reserved lease unconditionally" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    try putReservation(store, "aa:bb:cc:dd:ee:ff", "192.168.1.50", 0, null);
    try std.testing.expect(store.leases.contains("aa:bb:cc:dd:ee:ff"));

    store.forceRemoveLease("aa:bb:cc:dd:ee:ff");
    try std.testing.expect(!store.leases.contains("aa:bb:cc:dd:ee:ff"));
}

test "forceRemoveLease is no-op for unknown MAC" {
    const store = try makeTestStore(std.testing.allocator);
    defer store.deinit();

    // Should not crash on a missing key.
    store.forceRemoveLease("de:ad:be:ef:00:01");
    try std.testing.expectEqual(@as(usize, 0), store.leases.count());
}

test "save/load round-trip preserves active lease fields" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    // Save phase
    {
        const store = try makeTestStoreAt(std.testing.allocator, tmp_path);
        defer store.deinit();

        try store.addLease(.{
            .mac = "aa:bb:cc:dd:ee:ff",
            .ip = "192.168.1.10",
            .hostname = "myhost",
            .expires = std.time.timestamp() + 3600,
            .client_id = "01aabbccddeeff",
        });
        try store.saveUnlocked();
    }

    // Load phase
    {
        const store = try makeTestStoreAt(std.testing.allocator, tmp_path);
        defer store.deinit();
        try store.load();

        const lease = store.leases.get("aa:bb:cc:dd:ee:ff");
        try std.testing.expect(lease != null);
        try std.testing.expectEqualStrings("192.168.1.10", lease.?.ip);
        try std.testing.expectEqualStrings("myhost", lease.?.hostname.?);
        try std.testing.expectEqualStrings("01aabbccddeeff", lease.?.client_id.?);
    }
}

test "save/load: expired lease is skipped on load" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    {
        const store = try makeTestStoreAt(std.testing.allocator, tmp_path);
        defer store.deinit();

        try putLease(store, "aa:bb:cc:dd:ee:01", "192.168.1.10", std.time.timestamp() - 1); // expired
        try putLease(store, "aa:bb:cc:dd:ee:02", "192.168.1.11", std.time.timestamp() + 3600); // active
        try store.saveUnlocked();
    }

    {
        const store = try makeTestStoreAt(std.testing.allocator, tmp_path);
        defer store.deinit();
        try store.load();

        try std.testing.expectEqual(@as(usize, 1), store.leases.count());
        try std.testing.expect(store.leases.get("aa:bb:cc:dd:ee:01") == null);
        try std.testing.expect(store.leases.get("aa:bb:cc:dd:ee:02") != null);
    }
}

test "save/load: reserved lease loads regardless of expiry" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    {
        const store = try makeTestStoreAt(std.testing.allocator, tmp_path);
        defer store.deinit();

        try putReservation(store, "aa:bb:cc:dd:ee:ff", "192.168.1.50", 0, null); // expires=0
        try store.saveUnlocked();
    }

    {
        const store = try makeTestStoreAt(std.testing.allocator, tmp_path);
        defer store.deinit();
        try store.load();

        const lease = store.leases.get("aa:bb:cc:dd:ee:ff");
        try std.testing.expect(lease != null);
        try std.testing.expect(lease.?.reserved);
        try std.testing.expectEqualStrings("192.168.1.50", lease.?.ip);
    }
}

fn makeTestStoreAt(allocator: std.mem.Allocator, dir: []const u8) !*StateStore {
    const store = try allocator.create(StateStore);
    store.* = .{
        .allocator = allocator,
        .dir = dir,
        .leases = std.StringHashMap(Lease).init(allocator),
    };
    return store;
}

test "addLeaseUnlocked: updating same MAC replaces IP" {
    const alloc = std.testing.allocator;
    const store = try makeTestStore(alloc);
    defer store.deinit();

    // Add a lease for a MAC.
    try store.addLeaseUnlocked(.{
        .mac = "aa:bb:cc:dd:ee:01",
        .ip = "192.168.1.10",
        .hostname = "host-a",
        .expires = std.time.timestamp() + 3600,
        .client_id = null,
    });
    try std.testing.expectEqual(@as(usize, 1), store.leases.count());
    try std.testing.expectEqualStrings("192.168.1.10", store.leases.get("aa:bb:cc:dd:ee:01").?.ip);
    try std.testing.expectEqualStrings("host-a", store.leases.get("aa:bb:cc:dd:ee:01").?.hostname.?);

    // Update the same MAC with a new IP and hostname.
    try store.addLeaseUnlocked(.{
        .mac = "aa:bb:cc:dd:ee:01",
        .ip = "192.168.1.20",
        .hostname = "host-b",
        .expires = std.time.timestamp() + 7200,
        .client_id = null,
    });

    // Still only one entry; old IP replaced.
    try std.testing.expectEqual(@as(usize, 1), store.leases.count());
    const updated = store.leases.get("aa:bb:cc:dd:ee:01").?;
    try std.testing.expectEqualStrings("192.168.1.20", updated.ip);
    try std.testing.expectEqualStrings("host-b", updated.hostname.?);
}

test "addLeaseUnlocked: old IP mapping gone after MAC update" {
    const alloc = std.testing.allocator;
    const store = try makeTestStore(alloc);
    defer store.deinit();

    // Add lease with IP .10.
    try store.addLeaseUnlocked(.{
        .mac = "aa:bb:cc:dd:ee:02",
        .ip = "192.168.1.10",
        .hostname = null,
        .expires = std.time.timestamp() + 3600,
        .client_id = null,
    });

    // Update same MAC with IP .20.
    try store.addLeaseUnlocked(.{
        .mac = "aa:bb:cc:dd:ee:02",
        .ip = "192.168.1.20",
        .hostname = null,
        .expires = std.time.timestamp() + 3600,
        .client_id = null,
    });

    // getLeaseByIp for the old IP should return null (no lease has it).
    store.lock.lockShared();
    defer store.lock.unlockShared();
    var found_old_ip = false;
    var it = store.leases.valueIterator();
    while (it.next()) |lease| {
        if (std.mem.eql(u8, lease.ip, "192.168.1.10")) found_old_ip = true;
    }
    try std.testing.expect(!found_old_ip);
}

test "forcerenew_nonce lifecycle: store, replace, remove without leak" {
    const alloc = std.testing.allocator;
    const store = try makeTestStore(alloc);
    defer store.deinit();

    // 1. Add a lease with a nonce string.
    try store.addLeaseUnlocked(.{
        .mac = "aa:bb:cc:dd:ee:99",
        .ip = "192.168.1.99",
        .hostname = null,
        .expires = std.time.timestamp() + 3600,
        .client_id = null,
        .forcerenew_nonce = "aabbccdd00112233aabbccdd00112233",
    });

    // Verify the nonce is stored correctly.
    const l1 = store.leases.get("aa:bb:cc:dd:ee:99").?;
    try std.testing.expect(l1.forcerenew_nonce != null);
    try std.testing.expectEqualStrings("aabbccdd00112233aabbccdd00112233", l1.forcerenew_nonce.?);

    // 2. Replace the lease with a new nonce — old nonce must be freed (test allocator detects leaks).
    try store.addLeaseUnlocked(.{
        .mac = "aa:bb:cc:dd:ee:99",
        .ip = "192.168.1.99",
        .hostname = null,
        .expires = std.time.timestamp() + 7200,
        .client_id = null,
        .forcerenew_nonce = "11223344556677881122334455667788",
    });

    const l2 = store.leases.get("aa:bb:cc:dd:ee:99").?;
    try std.testing.expect(l2.forcerenew_nonce != null);
    try std.testing.expectEqualStrings("11223344556677881122334455667788", l2.forcerenew_nonce.?);

    // 3. Remove the lease — nonce must be freed (test allocator catches leaks on deinit).
    _ = store.removeLeaseUnlocked("aa:bb:cc:dd:ee:99");
    try std.testing.expect(store.leases.get("aa:bb:cc:dd:ee:99") == null);
}

test "pruneExpired removes nonce-bearing expired lease without leak" {
    const alloc = std.testing.allocator;
    const store = try makeTestStore(alloc);
    defer store.deinit();

    // Add an expired lease with a forcerenew_nonce.
    try store.addLeaseUnlocked(.{
        .mac = "aa:bb:cc:dd:ee:77",
        .ip = "192.168.1.77",
        .hostname = "nonce-host",
        .expires = std.time.timestamp() - 10, // already expired
        .client_id = "01aabbccddeeff",
        .forcerenew_nonce = "deadbeefdeadbeefdeadbeefdeadbeef",
    });

    // Verify the lease was stored.
    try std.testing.expect(store.leases.get("aa:bb:cc:dd:ee:77") != null);

    // pruneExpired should remove it (not reserved, expired).
    StateStore.pruneExpired(store);

    // Verify the lease was removed.
    try std.testing.expect(store.leases.get("aa:bb:cc:dd:ee:77") == null);

    // The test allocator will detect any leaked strings (mac, ip, hostname,
    // client_id, forcerenew_nonce) when the store is deinited.
}

test "save/load round-trip preserves last_modified" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const specific_ts: i64 = 1700000000; // a fixed timestamp

    // Save phase: add a lease with an explicit last_modified value.
    {
        const store = try makeTestStoreAt(std.testing.allocator, tmp_path);
        defer store.deinit();

        try store.addLeaseUnlocked(.{
            .mac = "aa:bb:cc:dd:ee:ff",
            .ip = "192.168.1.42",
            .hostname = "persist-host",
            .expires = std.time.timestamp() + 7200,
            .client_id = null,
            .last_modified = specific_ts,
        });
        try store.saveUnlocked();
    }

    // Load phase: verify last_modified survived the round-trip.
    {
        const store = try makeTestStoreAt(std.testing.allocator, tmp_path);
        defer store.deinit();
        try store.load();

        const lease = store.leases.get("aa:bb:cc:dd:ee:ff");
        try std.testing.expect(lease != null);
        try std.testing.expectEqual(specific_ts, lease.?.last_modified);
    }
}
