/// Prometheus metrics HTTP exporter.
///
/// Runs a minimal HTTP/1.1 server on a configured port. Responds to GET /metrics
/// with a Prometheus text format response. All other paths return 404.
///
/// This server is intentionally minimal:
/// - Single-threaded accept loop (one connection at a time is fine for scrape traffic)
/// - No keep-alive (Connection: close)
/// - Reads only the first line of the request to determine the path
///
/// Metrics exposed:
///   stardust_dhcp_packets_total{type="discover|offer|request|ack|nak|release|decline|inform"}
///   stardust_leases_active{pool="<subnet>/<prefix>"}
///   stardust_leases_reserved{pool="<subnet>/<prefix>"}
///   stardust_leases_expired{pool="<subnet>/<prefix>"}
///   stardust_pool_capacity{pool="<subnet>/<prefix>"}
///   stardust_pool_available{pool="<subnet>/<prefix>"}
const std = @import("std");
const config_mod = @import("./config.zig");
const state_mod = @import("./state.zig");
const dhcp_mod = @import("./dhcp.zig");

pub const MetricsServer = struct {
    allocator: std.mem.Allocator,
    cfg: *const config_mod.Config,
    store: *state_mod.StateStore,
    counters: *const dhcp_mod.Counters,
    running: std.atomic.Value(bool),
    start_time: i64,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        cfg: *const config_mod.Config,
        store: *state_mod.StateStore,
        counters: *const dhcp_mod.Counters,
    ) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .cfg = cfg,
            .store = store,
            .counters = counters,
            .running = std.atomic.Value(bool).init(true),
            .start_time = std.time.timestamp(),
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self);
    }

    pub fn stop(self: *Self) void {
        self.running.store(false, .release);
    }

    /// Entry point for the metrics server thread.
    pub fn run(self: *Self) void {
        self.runInner() catch |err| {
            std.log.err("metrics: server error: {s}", .{@errorName(err)});
        };
    }

    fn runInner(self: *Self) !void {
        const bind_ip = config_mod.parseIpv4(self.cfg.metrics.http_bind) catch {
            std.log.err("metrics: invalid bind address '{s}'", .{self.cfg.metrics.http_bind});
            return;
        };

        const addr = std.net.Address.initIp4(bind_ip, self.cfg.metrics.http_port);
        var server = try addr.listen(.{ .reuse_address = true });
        defer server.deinit();

        std.log.info("metrics: HTTP server listening on {s}:{d}", .{
            self.cfg.metrics.http_bind,
            self.cfg.metrics.http_port,
        });

        // Set the listening socket to non-blocking so we can check running flag periodically.
        const flags = try std.posix.fcntl(server.stream.handle, std.posix.F.GETFL, 0);
        _ = try std.posix.fcntl(server.stream.handle, std.posix.F.SETFL, flags | @as(u32, std.posix.SOCK.NONBLOCK));

        while (self.running.load(.acquire)) {
            // Poll with 500ms timeout so we check the running flag frequently.
            var pfd = [_]std.posix.pollfd{.{
                .fd = server.stream.handle,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const ready = std.posix.poll(&pfd, 500) catch 0;
            if (ready == 0) continue; // timeout — loop back to check running flag

            const conn = server.accept() catch |err| switch (err) {
                error.WouldBlock => continue,
                else => {
                    if (!self.running.load(.acquire)) break;
                    std.log.warn("metrics: accept error: {s}", .{@errorName(err)});
                    continue;
                },
            };
            self.handleConnection(conn) catch |err| {
                std.log.debug("metrics: connection error: {s}", .{@errorName(err)});
            };
        }
    }

    fn handleConnection(self: *Self, conn: std.net.Server.Connection) !void {
        defer conn.stream.close();

        // Read request line (up to 512 bytes)
        var req_buf: [512]u8 = undefined;
        var total: usize = 0;
        while (total < req_buf.len) {
            const n = conn.stream.read(req_buf[total..]) catch break;
            if (n == 0) break;
            total += n;
            // Stop once we have a full line
            if (std.mem.indexOfPos(u8, req_buf[0..total], 0, "\r\n")) |_| break;
            if (std.mem.indexOfPos(u8, req_buf[0..total], 0, "\n")) |_| break;
        }

        const req = req_buf[0..total];
        // Parse: "GET /path HTTP/1.1\r\n"
        const is_get = std.mem.startsWith(u8, req, "GET ");
        const path_start: usize = if (is_get) 4 else 0;
        const path_end = std.mem.indexOfAnyPos(u8, req, path_start, " \r\n") orelse req.len;
        const path = req[path_start..path_end];

        if (is_get and std.mem.eql(u8, path, "/metrics")) {
            try self.writeMetrics(conn.stream);
        } else if (is_get and std.mem.eql(u8, path, "/healthz")) {
            try conn.stream.writeAll(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
            );
        } else {
            try conn.stream.writeAll(
                "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found",
            );
        }
    }

    fn writeMetrics(self: *Self, stream: std.net.Stream) !void {
        // Build the body in a buffer first so we can set Content-Length accurately.
        var body_buf = std.ArrayList(u8){};
        defer body_buf.deinit(self.allocator);
        try self.renderMetrics(body_buf.writer(self.allocator));

        // Build complete response (headers + body) in a second buffer and write atomically.
        var resp_buf = std.ArrayList(u8){};
        defer resp_buf.deinit(self.allocator);
        const rw = resp_buf.writer(self.allocator);
        try rw.print(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
            .{body_buf.items.len},
        );
        try rw.writeAll(body_buf.items);
        try stream.writeAll(resp_buf.items);
    }

    fn renderMetrics(self: *Self, w: anytype) !void {
        const now = std.time.timestamp();

        // DHCP packet counters
        try w.writeAll("# HELP stardust_dhcp_packets_total DHCP packets processed since start\n");
        try w.writeAll("# TYPE stardust_dhcp_packets_total counter\n");
        try w.print("stardust_dhcp_packets_total{{type=\"discover\"}} {d}\n", .{self.counters.discover.load(.monotonic)});
        try w.print("stardust_dhcp_packets_total{{type=\"offer\"}} {d}\n", .{self.counters.offer.load(.monotonic)});
        try w.print("stardust_dhcp_packets_total{{type=\"request\"}} {d}\n", .{self.counters.request.load(.monotonic)});
        try w.print("stardust_dhcp_packets_total{{type=\"ack\"}} {d}\n", .{self.counters.ack.load(.monotonic)});
        try w.print("stardust_dhcp_packets_total{{type=\"nak\"}} {d}\n", .{self.counters.nak.load(.monotonic)});
        try w.print("stardust_dhcp_packets_total{{type=\"release\"}} {d}\n", .{self.counters.release.load(.monotonic)});
        try w.print("stardust_dhcp_packets_total{{type=\"decline\"}} {d}\n", .{self.counters.decline.load(.monotonic)});
        try w.print("stardust_dhcp_packets_total{{type=\"inform\"}} {d}\n", .{self.counters.inform.load(.monotonic)});
        try w.print("stardust_dhcp_packets_total{{type=\"leasequery\"}} {d}\n", .{self.counters.leasequery.load(.monotonic)});

        // Server uptime
        try w.writeAll("\n# HELP stardust_uptime_seconds Seconds since the DHCP server started\n");
        try w.writeAll("# TYPE stardust_uptime_seconds gauge\n");
        try w.print("stardust_uptime_seconds {d}\n", .{now - self.start_time});

        // Per-pool lease stats
        try w.writeAll("\n# HELP stardust_leases_active Active (non-expired) leases by pool\n");
        try w.writeAll("# TYPE stardust_leases_active gauge\n");
        try w.writeAll("# HELP stardust_leases_reserved Reserved (static) leases by pool\n");
        try w.writeAll("# TYPE stardust_leases_reserved gauge\n");
        try w.writeAll("# HELP stardust_leases_expired Expired leases still in state by pool\n");
        try w.writeAll("# TYPE stardust_leases_expired gauge\n");
        try w.writeAll("# HELP stardust_pool_capacity Total allocatable addresses in pool\n");
        try w.writeAll("# TYPE stardust_pool_capacity gauge\n");
        try w.writeAll("# HELP stardust_pool_available Addresses not currently leased or reserved\n");
        try w.writeAll("# TYPE stardust_pool_available gauge\n");

        const leases = self.store.listLeases() catch return;
        defer self.store.allocator.free(leases);

        for (self.cfg.pools) |pool| {
            const pool_label = try std.fmt.allocPrint(self.allocator, "{s}/{d}", .{ pool.subnet, pool.prefix_len });
            defer self.allocator.free(pool_label);

            // Compute capacity from pool_start/pool_end
            const capacity = poolCapacity(&pool);

            // Count leases in this pool
            var active: u64 = 0;
            var reserved: u64 = 0;
            var expired: u64 = 0;
            for (leases) |lease| {
                if (!isIpInPool(lease.ip, &pool)) continue;
                if (lease.reserved) {
                    reserved += 1;
                    if (lease.expires > now) active += 1;
                } else if (lease.expires > now) {
                    active += 1;
                } else {
                    expired += 1;
                }
            }
            const available: u64 = if (capacity > active + reserved) capacity - active - reserved else 0;

            try w.print("stardust_leases_active{{pool=\"{s}\"}} {d}\n", .{ pool_label, active });
            try w.print("stardust_leases_reserved{{pool=\"{s}\"}} {d}\n", .{ pool_label, reserved });
            try w.print("stardust_leases_expired{{pool=\"{s}\"}} {d}\n", .{ pool_label, expired });
            try w.print("stardust_pool_capacity{{pool=\"{s}\"}} {d}\n", .{ pool_label, capacity });
            try w.print("stardust_pool_available{{pool=\"{s}\"}} {d}\n", .{ pool_label, available });
        }
    }
};

/// Calculate the number of allocatable addresses in a pool.
fn poolCapacity(pool: *const config_mod.PoolConfig) u64 {
    // Determine start and end from pool_start/pool_end or subnet defaults
    const start = if (pool.pool_start.len > 0)
        config_mod.parseIpv4(pool.pool_start) catch null
    else
        null;
    const end = if (pool.pool_end.len > 0)
        config_mod.parseIpv4(pool.pool_end) catch null
    else
        null;

    const subnet_bytes = config_mod.parseIpv4(pool.subnet) catch return 0;
    const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);

    // /32: single host (RFC 7600)
    if (pool.subnet_mask == 0xFFFFFFFF) return 1;

    // /31: point-to-point link, both addresses usable (RFC 3021)
    if (pool.subnet_mask == 0xFFFFFFFE) return 2;

    const broadcast_int = subnet_int | ~pool.subnet_mask;

    const start_int: u32 = if (start) |s| std.mem.readInt(u32, &s, .big) else subnet_int + 1;
    const end_int: u32 = if (end) |e| std.mem.readInt(u32, &e, .big) else broadcast_int - 1;

    if (end_int < start_int) return 0;
    return end_int - start_int + 1;
}

/// Check whether an IP string falls within the given pool's subnet.
fn isIpInPool(ip_str: []const u8, pool: *const config_mod.PoolConfig) bool {
    const ip_bytes = config_mod.parseIpv4(ip_str) catch return false;
    const ip_int = std.mem.readInt(u32, &ip_bytes, .big);
    const subnet_bytes = config_mod.parseIpv4(pool.subnet) catch return false;
    const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
    return (ip_int & pool.subnet_mask) == (subnet_int & pool.subnet_mask);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "poolCapacity computes correct range" {
    var dhcp_options = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer dhcp_options.deinit();

    const pool = config_mod.PoolConfig{
        .subnet = "192.168.1.0",
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = "192.168.1.1",
        .pool_start = "192.168.1.100",
        .pool_end = "192.168.1.200",
        .dns_servers = &.{},
        .domain_name = "",
        .domain_search = &.{},
        .lease_time = 3600,
        .time_offset = null,
        .time_servers = &.{},
        .log_servers = &.{},
        .ntp_servers = &.{},
        .mtu = null,
        .wins_servers = &.{},
        .tftp_servers = &.{},
        .boot_filename = "",
        .http_boot_url = "",
        .dns_update = .{ .enable = false, .server = "", .zone = "", .rev_zone = "", .key_name = "", .key_file = "", .lease_time = 3600 },
        .dhcp_options = dhcp_options,
        .reservations = &.{},
        .static_routes = &.{},
    };
    try std.testing.expectEqual(@as(u64, 101), poolCapacity(&pool)); // 100 to 200 inclusive = 101
}

test "isIpInPool matches correct subnet" {
    var dhcp_options = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer dhcp_options.deinit();

    const pool = config_mod.PoolConfig{
        .subnet = "192.168.1.0",
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = "192.168.1.1",
        .pool_start = "",
        .pool_end = "",
        .dns_servers = &.{},
        .domain_name = "",
        .domain_search = &.{},
        .lease_time = 3600,
        .time_offset = null,
        .time_servers = &.{},
        .log_servers = &.{},
        .ntp_servers = &.{},
        .mtu = null,
        .wins_servers = &.{},
        .tftp_servers = &.{},
        .boot_filename = "",
        .http_boot_url = "",
        .dns_update = .{ .enable = false, .server = "", .zone = "", .rev_zone = "", .key_name = "", .key_file = "", .lease_time = 3600 },
        .dhcp_options = dhcp_options,
        .reservations = &.{},
        .static_routes = &.{},
    };

    try std.testing.expect(isIpInPool("192.168.1.50", &pool));
    try std.testing.expect(!isIpInPool("192.168.2.50", &pool));
    try std.testing.expect(!isIpInPool("10.0.0.1", &pool));
}
