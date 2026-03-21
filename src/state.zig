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
            else => std.debug.print("warning: could not load lease state ({s}), starting fresh\n", .{@errorName(err)}),
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
            std.debug.print("warning: failed to persist lease state ({s})\n", .{@errorName(err)});
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
                std.debug.print("warning: failed to persist lease state ({s})\n", .{@errorName(err)});
            };
        }
    }

    /// Look up a lease by MAC address. Returns null if not found.
    pub fn getLeaseByMac(store: *StateStore, mac: []const u8) ?Lease {
        return store.leases.get(mac);
    }

    /// Look up a lease by IP address. Returns null if not found.
    pub fn getLeaseByIp(store: *StateStore, ip: []const u8) ?Lease {
        var it = store.leases.valueIterator();
        while (it.next()) |lease| {
            if (std.mem.eql(u8, lease.ip, ip)) return lease.*;
        }
        return null;
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
