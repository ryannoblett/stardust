/// SSH admin TUI server.
///
/// Runs an SSH/2 server (via libssh) on the configured admin_ssh.port.
/// Clients authenticate with an Ed25519 public key listed in the
/// admin_ssh.authorized_keys file.  Once authenticated a full-screen TUI is
/// presented over the session channel.
///
/// Tabs:
///   1  Leases  — table of all leases; j/k or ↑/↓ to navigate
///   2  Stats   — per-pool capacity bars + DHCP counters + uptime
///
/// Keys:
///   1/2       switch tabs
///   j / ↓     move selection down
///   k / ↑     move selection up
///   q         quit session
///   Ctrl+C    quit session
///
/// Requires libssh ≥ 0.9 installed on the build host (libssh-dev / libssh).
/// For production cross-compiled builds, install libssh-static on the build
/// host; the CI release workflow will need updating accordingly.
const std = @import("std");
const vaxis = @import("vaxis");
const config_mod = @import("./config.zig");
const state_mod = @import("./state.zig");
const dhcp_mod = @import("./dhcp.zig");
const sync_mod = @import("./sync.zig");
const config_write = @import("./config_write.zig");

const c = @cImport({
    @cInclude("libssh/libssh.h");
    @cInclude("libssh/server.h");
    @cInclude("libssh/callbacks.h");
});

const log = std.log.scoped(.admin_ssh);

// ---------------------------------------------------------------------------
// Peer address helper
// ---------------------------------------------------------------------------

/// Format the remote address of a connected session as "a.b.c.d:port".
/// buf must be at least 32 bytes.  Returns a slice into buf.
fn fmtPeerAddr(session: c.ssh_session, buf: []u8) []const u8 {
    const fd: std.posix.socket_t = @intCast(c.ssh_get_fd(session));
    var storage: std.posix.sockaddr.storage = undefined;
    var alen: std.posix.socklen_t = @sizeOf(@TypeOf(storage));
    std.posix.getpeername(fd, @ptrCast(&storage), &alen) catch return "?";
    const sa: *const std.posix.sockaddr = @ptrCast(&storage);
    switch (sa.family) {
        std.posix.AF.INET => {
            const sin: *const std.posix.sockaddr.in = @ptrCast(&storage);
            const b: *const [4]u8 = @ptrCast(&sin.addr); // network byte order
            return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{
                b[0],                               b[1], b[2], b[3],
                std.mem.bigToNative(u16, sin.port),
            }) catch "?";
        },
        std.posix.AF.INET6 => {
            const sin6: *const std.posix.sockaddr.in6 = @ptrCast(&storage);
            return std.fmt.bufPrint(buf, "[ipv6]:{d}", .{
                std.mem.bigToNative(u16, sin6.port),
            }) catch "?";
        },
        else => return "?",
    }
}

// ---------------------------------------------------------------------------
// SSH channel → std.io.Writer bridge
// ---------------------------------------------------------------------------

fn sshChanWrite(chan: c.ssh_channel, bytes: []const u8) error{WriteFailed}!usize {
    if (bytes.len == 0) return 0;
    const n = c.ssh_channel_write(chan, bytes.ptr, @intCast(bytes.len));
    if (n < 0) return error.WriteFailed;
    return @intCast(n);
}

/// Old-style (pre-0.15) generic writer wrapping an SSH channel.
/// Use `adaptToNewApi(&buf)` to get a new-API std.io.Writer for libvaxis.
const SshChanGenericWriter = std.io.GenericWriter(
    c.ssh_channel,
    error{WriteFailed},
    sshChanWrite,
);

// ---------------------------------------------------------------------------
// AdminServer
// ---------------------------------------------------------------------------

pub const AdminServer = struct {
    allocator: std.mem.Allocator,
    cfg: *config_mod.Config,
    cfg_path: []const u8,
    store: *state_mod.StateStore,
    counters: *dhcp_mod.Counters,
    /// Non-null when the server is part of a sync group.
    sync_mgr: ?*sync_mod.SyncManager,
    /// DHCP server reference for sending FORCERENEW messages. Null until set
    /// from main after both servers are created.
    dhcp_server: ?*dhcp_mod.DHCPServer = null,
    running: std.atomic.Value(bool),
    /// Number of session threads currently alive. Incremented in runInner
    /// before spawning (so stop() never races a freshly-spawned thread),
    /// decremented in sessionThread's defer.
    active_sessions: std.atomic.Value(i32),
    start_time: i64,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        cfg: *config_mod.Config,
        cfg_path: []const u8,
        store: *state_mod.StateStore,
        counters: *dhcp_mod.Counters,
        sync_mgr: ?*sync_mod.SyncManager,
    ) !*Self {
        // Silence libssh's default stderr logging *before* any libssh object is
        // created.  Also install a no-op callback so that even if a code path
        // bypasses the level check, nothing reaches stderr.
        _ = c.ssh_set_log_level(c.SSH_LOG_NOLOG);
        _ = c.ssh_set_log_callback(sshLogNoop);

        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .cfg = cfg,
            .cfg_path = cfg_path,
            .store = store,
            .counters = counters,
            .sync_mgr = sync_mgr,
            .running = std.atomic.Value(bool).init(true),
            .active_sessions = std.atomic.Value(i32).init(0),
            .start_time = std.time.timestamp(),
        };
        return self;
    }

    fn sshLogNoop(_: c_int, _: [*c]const u8, _: [*c]const u8, _: ?*anyopaque) callconv(.c) void {}

    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self);
    }

    pub fn stop(self: *Self) void {
        self.running.store(false, .release);
        // Wait up to 2 s for active session threads to send their terminal
        // cleanup sequences (mouse-off, exit alt-screen) before we free self.
        // Each session thread polls server.running with a 100 ms read timeout,
        // so it will notice within ~100 ms and finish cleanly.
        var waited_ms: u32 = 0;
        while (self.active_sessions.load(.acquire) > 0 and waited_ms < 2000) {
            std.Thread.sleep(50 * std.time.ns_per_ms);
            waited_ms += 50;
        }
    }

    /// Thread entry point.
    pub fn run(self: *Self) void {
        self.runInner() catch |err| {
            log.err("server error: {s}", .{@errorName(err)});
        };
    }

    fn runInner(self: *Self) !void {
        const bind = c.ssh_bind_new() orelse return error.SshBindFailed;
        defer c.ssh_bind_free(bind);

        // Bind address
        {
            const addr = try self.allocator.dupeZ(u8, self.cfg.admin_ssh.bind);
            defer self.allocator.free(addr);
            _ = c.ssh_bind_options_set(bind, c.SSH_BIND_OPTIONS_BINDADDR, addr.ptr);
        }
        var port: c_uint = self.cfg.admin_ssh.port;
        _ = c.ssh_bind_options_set(bind, c.SSH_BIND_OPTIONS_BINDPORT, &port);

        // Host key
        {
            const hk = try self.allocator.dupeZ(u8, self.cfg.admin_ssh.host_key);
            defer self.allocator.free(hk);
            _ = c.ssh_bind_options_set(bind, c.SSH_BIND_OPTIONS_HOSTKEY, hk.ptr);
        }

        if (c.ssh_bind_listen(bind) < 0) return error.SshBindListenFailed;
        log.info("listening on {s}:{d}", .{ self.cfg.admin_ssh.bind, self.cfg.admin_ssh.port });

        const bind_fd = c.ssh_bind_get_fd(bind);
        while (self.running.load(.acquire)) {
            var pfd = [_]std.posix.pollfd{.{
                .fd = bind_fd,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const ready = std.posix.poll(&pfd, 500) catch 0;
            if (ready == 0) continue;

            const session = c.ssh_new() orelse continue;
            if (c.ssh_bind_accept(bind, session) < 0) {
                c.ssh_free(session);
                continue;
            }
            // Increment before spawning so stop() cannot race a thread that
            // has been spawned but hasn't yet run its first instruction.
            _ = self.active_sessions.fetchAdd(1, .acq_rel);
            const thread = std.Thread.spawn(.{}, sessionThread, .{ self, session }) catch |err| {
                _ = self.active_sessions.fetchSub(1, .acq_rel);
                log.warn("failed to spawn session thread: {s}", .{@errorName(err)});
                c.ssh_free(session);
                continue;
            };
            thread.detach();
        }
    }
};

// ---------------------------------------------------------------------------
// Per-connection session thread
// ---------------------------------------------------------------------------

fn sessionThread(server: *AdminServer, session: c.ssh_session) void {
    var peer_buf: [64]u8 = undefined;
    const peer = fmtPeerAddr(session, &peer_buf);
    log.info("connection from {s}", .{peer});
    defer {
        log.info("connection closed: {s}", .{peer});
        c.ssh_free(session);
        _ = server.active_sessions.fetchSub(1, .acq_rel);
    }
    runSession(server, session, peer) catch |err| {
        log.warn("session error from {s}: {s}", .{ peer, @errorName(err) });
    };
}

fn runSession(server: *AdminServer, session: c.ssh_session, peer: []const u8) !void {
    // Prefer post-quantum hybrid key exchange algorithms; libssh negotiates
    // down to a mutually supported algorithm if the client doesn't support PQC.
    const kex_pref = "sntrup761x25519-sha512@openssh.com," ++
        "mlkem768x25519-sha256," ++
        "curve25519-sha256,curve25519-sha256@libssh.org," ++
        "ecdh-sha2-nistp521,ecdh-sha2-nistp256," ++
        "diffie-hellman-group14-sha256";
    if (c.ssh_options_set(session, c.SSH_OPTIONS_KEY_EXCHANGE, kex_pref) < 0) {
        log.debug("{s}: could not set KEX preference: {s}", .{
            peer, std.mem.span(c.ssh_get_error(session)),
        });
    }

    _ = server.counters.ssh_attempts.fetchAdd(1, .monotonic);
    if (c.ssh_handle_key_exchange(session) < 0) {
        _ = server.counters.ssh_failures.fetchAdd(1, .monotonic);
        log.info("{s}: key exchange failed: {s}", .{
            peer, std.mem.span(c.ssh_get_error(session)),
        });
        return;
    }
    log.debug("{s}: key exchange OK", .{peer});

    c.ssh_set_auth_methods(session, c.SSH_AUTH_METHOD_PUBLICKEY);

    var channel: c.ssh_channel = null;
    var cols: u32 = 80;
    var rows: u32 = 24;
    var authed = false;

    // Process SSH messages until we have an authenticated shell channel.
    msg_loop: while (true) {
        const msg = c.ssh_message_get(session) orelse {
            if (authed) {
                log.debug("{s}: session closed after auth", .{peer});
            } else {
                log.info("{s}: session closed before auth completed", .{peer});
            }
            return;
        };
        defer c.ssh_message_free(msg);

        const msg_type = c.ssh_message_type(msg);
        const msg_sub = c.ssh_message_subtype(msg);

        switch (msg_type) {
            c.SSH_REQUEST_SERVICE => {
                _ = c.ssh_message_service_reply_success(msg);
            },
            c.SSH_REQUEST_AUTH => {
                if (msg_sub == c.SSH_AUTH_METHOD_PUBLICKEY) {
                    const client_key = c.ssh_message_auth_pubkey(msg);
                    const user_cstr = c.ssh_message_auth_user(msg);
                    const user: []const u8 = if (user_cstr != null) std.mem.span(user_cstr) else "(unknown)";
                    const key_type_cstr = c.ssh_key_type_to_char(c.ssh_key_type(client_key));
                    const key_type: []const u8 = if (key_type_cstr != null) std.mem.span(key_type_cstr) else "unknown";

                    const pk_state = c.ssh_message_auth_publickey_state(msg);
                    const in_auth_keys = checkAuthorizedKeys(server, client_key, user, peer);

                    if (in_auth_keys and pk_state == c.SSH_PUBLICKEY_STATE_NONE) {
                        // Query: client is checking whether the key is acceptable.
                        log.debug("{s}: pubkey query accepted for user '{s}' ({s})", .{ peer, user, key_type });
                        _ = c.ssh_message_auth_reply_pk_ok_simple(msg);
                    } else if (in_auth_keys and pk_state == c.SSH_PUBLICKEY_STATE_VALID) {
                        // Attempt: libssh already verified the signature.
                        log.info("{s}: authenticated user '{s}' ({s})", .{ peer, user, key_type });
                        _ = c.ssh_message_auth_reply_success(msg, 0);
                        _ = server.counters.ssh_logins.fetchAdd(1, .monotonic);
                        authed = true;
                    } else {
                        log.info("{s}: rejected pubkey for user '{s}' ({s}): key not in authorized_keys", .{ peer, user, key_type });
                        _ = server.counters.ssh_failures.fetchAdd(1, .monotonic);
                        _ = c.ssh_message_reply_default(msg);
                    }
                } else {
                    const user_cstr = c.ssh_message_auth_user(msg);
                    const user: []const u8 = if (user_cstr != null) std.mem.span(user_cstr) else "(unknown)";
                    log.debug("{s}: rejected non-pubkey auth method {d} for user '{s}'", .{ peer, msg_sub, user });
                    _ = c.ssh_message_reply_default(msg);
                }
            },
            c.SSH_REQUEST_CHANNEL_OPEN => {
                log.debug("{s}: channel open", .{peer});
                channel = c.ssh_message_channel_request_open_reply_accept(msg);
            },
            c.SSH_REQUEST_CHANNEL => {
                switch (msg_sub) {
                    c.SSH_CHANNEL_REQUEST_PTY => {
                        // These accessors are deprecated in 0.12 but still functional.
                        const w = c.ssh_message_channel_request_pty_width(msg);
                        const h = c.ssh_message_channel_request_pty_height(msg);
                        if (w > 0) cols = @intCast(w);
                        if (h > 0) rows = @intCast(h);
                        log.debug("{s}: PTY requested ({d}x{d})", .{ peer, cols, rows });
                        _ = c.ssh_message_channel_request_reply_success(msg);
                    },
                    c.SSH_CHANNEL_REQUEST_SHELL => {
                        _ = c.ssh_message_channel_request_reply_success(msg);
                        if (authed and channel != null) break :msg_loop;
                        // Unauthenticated — should not happen, but close cleanly.
                        log.warn("{s}: shell request before auth", .{peer});
                        return;
                    },
                    c.SSH_CHANNEL_REQUEST_WINDOW_CHANGE => {
                        const w = c.ssh_message_channel_request_pty_width(msg);
                        const h = c.ssh_message_channel_request_pty_height(msg);
                        if (w > 0) cols = @intCast(w);
                        if (h > 0) rows = @intCast(h);
                        // No reply needed for window-change.
                    },
                    else => _ = c.ssh_message_reply_default(msg),
                }
            },
            else => _ = c.ssh_message_reply_default(msg),
        }
    }

    if (!authed or channel == null) return;

    log.info("{s}: TUI session started", .{peer});
    defer log.info("{s}: TUI session ended", .{peer});

    try runTui(server, session, channel, cols, rows, peer);

    _ = c.ssh_channel_request_send_exit_status(channel, 0);
    c.ssh_channel_free(channel);
}

// ---------------------------------------------------------------------------
// authorized_keys check
// ---------------------------------------------------------------------------

fn checkAuthorizedKeys(server: *AdminServer, client_key: c.ssh_key, user: []const u8, peer: []const u8) bool {
    if (client_key == null) return false;

    const path = server.cfg.admin_ssh.authorized_keys;
    const file = std.fs.cwd().openFile(path, .{}) catch {
        log.warn("{s}: cannot open authorized_keys '{s}'", .{ peer, path });
        return false;
    };
    defer file.close();
    log.debug("{s}: checking authorized_keys '{s}' for user '{s}'", .{ peer, path, user });

    const content = file.readToEndAlloc(server.allocator, 1024 * 1024) catch {
        log.warn("{s}: failed to read authorized_keys '{s}'", .{ peer, path });
        return false;
    };
    defer server.allocator.free(content);

    var n_checked: usize = 0;
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        // Format: "keytype base64key [comment]"
        var tokens = std.mem.splitScalar(u8, trimmed, ' ');
        const keytype_str = tokens.next() orelse continue;
        const b64_key = tokens.next() orelse continue;
        // Optional comment field (used for logging identity of the matched key)
        const comment = tokens.next() orelse "";

        // ssh_key_type_from_name requires a null-terminated C string.
        var kt_buf: [64]u8 = undefined;
        if (keytype_str.len >= kt_buf.len) continue;
        @memcpy(kt_buf[0..keytype_str.len], keytype_str);
        kt_buf[keytype_str.len] = 0;
        const keytype = c.ssh_key_type_from_name(&kt_buf);
        if (keytype == c.SSH_KEYTYPE_UNKNOWN) {
            log.debug("{s}: skipping unknown key type '{s}'", .{ peer, keytype_str });
            continue;
        }

        // ssh_pki_import_pubkey_base64 also requires a null-terminated string.
        var b64z_buf: [2048]u8 = undefined;
        if (b64_key.len >= b64z_buf.len) continue;
        @memcpy(b64z_buf[0..b64_key.len], b64_key);
        b64z_buf[b64_key.len] = 0;

        var auth_key: c.ssh_key = undefined;
        if (c.ssh_pki_import_pubkey_base64(&b64z_buf, keytype, &auth_key) < 0) {
            log.debug("{s}: failed to parse key '{s}' ({s})", .{ peer, comment, keytype_str });
            continue;
        }
        defer c.ssh_key_free(auth_key);

        n_checked += 1;
        if (c.ssh_key_cmp(client_key, auth_key, c.SSH_KEY_CMP_PUBLIC) == 0) {
            log.debug("{s}: key matched entry '{s}' ({s})", .{ peer, comment, keytype_str });
            return true;
        }
    }

    log.debug("{s}: offered key not found (checked {d} entries)", .{ peer, n_checked });
    return false;
}

// ---------------------------------------------------------------------------
// Window-resize callback context (updated from libssh callback thread)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TUI session
// ---------------------------------------------------------------------------

/// Display row for the lease table (all string fields for Table widget).
const LeaseRow = struct {
    ip: []const u8,
    mac: []const u8,
    hostname: []const u8,
    type: []const u8,
    expires: []const u8,
    pool: []const u8,
};

const Tab = enum(u8) { leases = 0, stats = 1, pools = 2, settings = 3 };

const TuiMode = enum { normal, reservation_form, delete_confirm, pool_detail, pool_form, pool_delete_confirm, pool_save_confirm, pool_server_edit, pool_route_edit, pool_option_edit, pool_mac_class_edit, help, res_option_edit, option_lookup, pool_option_lookup, settings_confirm };

const ReservationForm = struct {
    /// MAC of the lease being edited; empty string means "new reservation".
    orig_mac: [18]u8 = [_]u8{0} ** 18,
    orig_mac_len: usize = 0,
    // Editable field buffers.
    ip_buf: [16]u8 = [_]u8{0} ** 16,
    ip_len: usize = 0,
    mac_buf: [18]u8 = [_]u8{0} ** 18,
    mac_len: usize = 0,
    hostname_buf: [64]u8 = [_]u8{0} ** 64,
    hostname_len: usize = 0,
    /// Active field: 0=ip, 1=mac, 2=hostname, 3=[+]add, 4..4+N-1=existing options.
    active_field: u8 = 0,
    /// Cursor position within the active field (byte offset).
    cursor: usize = 0,
    /// Per-reservation DHCP option overrides (pending, applied on save).
    options: [32]OptionEntry = [_]OptionEntry{.{}} ** 32,
    option_count: usize = 0,
    /// Option add/edit sub-modal state.
    opt_edit_code: [4]u8 = [_]u8{0} ** 4,
    opt_edit_code_len: usize = 0,
    opt_edit_value: [128]u8 = [_]u8{0} ** 128,
    opt_edit_value_len: usize = 0,
    opt_edit_field: u8 = 0, // 0=code, 1=value
    opt_edit_cursor: usize = 0,
    opt_edit_index: ?usize = null, // null=adding, index=editing existing
    /// Option lookup filter.
    opt_lookup_filter: [32]u8 = [_]u8{0} ** 32,
    opt_lookup_filter_len: usize = 0,
    opt_lookup_row: u16 = 0,
    /// Inline error message (empty = no error).
    err_buf: [80]u8 = [_]u8{0} ** 80,
    err_len: usize = 0,
    /// True immediately after a successful save; cleared on the next keypress.
    saved: bool = false,

    fn isNew(self: *const ReservationForm) bool {
        return self.orig_mac_len == 0;
    }

    fn activeLen(self: *const ReservationForm) usize {
        return switch (self.active_field) {
            0 => self.ip_len,
            1 => self.mac_len,
            2 => self.hostname_len,
            else => 0,
        };
    }

    fn totalFields(self: *const ReservationForm) u8 {
        return @intCast(4 + self.option_count); // ip, mac, hostname, [+], N options
    }
};

const InlineEntry = struct {
    buf: [64]u8 = [_]u8{0} ** 64,
    len: usize = 0,
};

const ServerEditTarget = enum { domain_search, dns, log, ntp, wins, tftp };

const RouteEntry = struct {
    dest_buf: [18]u8 = [_]u8{0} ** 18, // "10.0.0.0/24"
    dest_len: usize = 0,
    router_buf: [16]u8 = [_]u8{0} ** 16,
    router_len: usize = 0,
};

const OptionEntry = struct {
    code_buf: [4]u8 = [_]u8{0} ** 4, // option code e.g. "150"
    code_len: usize = 0,
    value_buf: [128]u8 = [_]u8{0} ** 128,
    value_len: usize = 0,
};

/// A single MAC class entry in the pool form.  Text fields use fixed buffers.
/// Multi-value fields (servers, routes, options) use inline entry arrays with
/// dedicated [+] Add buttons and edit sub-modals, matching the pool form.
const MacClassEntry = struct {
    name_buf: [32]u8 = [_]u8{0} ** 32,
    name_len: usize = 0,
    match_buf: [18]u8 = [_]u8{0} ** 18,
    match_len: usize = 0,
    // Override fields (empty = use pool default)
    router_buf: [16]u8 = [_]u8{0} ** 16,
    router_len: usize = 0,
    domain_name_buf: [64]u8 = [_]u8{0} ** 64,
    domain_name_len: usize = 0,
    time_offset_buf: [8]u8 = [_]u8{0} ** 8,
    time_offset_len: usize = 0,
    boot_filename_buf: [128]u8 = [_]u8{0} ** 128,
    boot_filename_len: usize = 0,
    http_boot_url_buf: [256]u8 = [_]u8{0} ** 256,
    http_boot_url_len: usize = 0,

    // Inline entry arrays (with [+] Add buttons and edit modals).
    domain_search: [8]InlineEntry = [_]InlineEntry{.{}} ** 8,
    domain_search_count: usize = 0,
    dns_servers: [8]InlineEntry = [_]InlineEntry{.{}} ** 8,
    dns_servers_count: usize = 0,
    ntp_servers: [4]InlineEntry = [_]InlineEntry{.{}} ** 4,
    ntp_servers_count: usize = 0,
    log_servers: [4]InlineEntry = [_]InlineEntry{.{}} ** 4,
    log_servers_count: usize = 0,
    wins_servers: [2]InlineEntry = [_]InlineEntry{.{}} ** 2,
    wins_servers_count: usize = 0,
    tftp_servers: [4]InlineEntry = [_]InlineEntry{.{}} ** 4,
    tftp_servers_count: usize = 0,
    routes: [16]RouteEntry = [_]RouteEntry{.{}} ** 16,
    route_count: usize = 0,
    options: [32]OptionEntry = [_]OptionEntry{.{}} ** 32,
    option_count: usize = 0,
};

const PoolForm = struct {
    editing_index: ?usize = null, // null = new pool
    active_field: u8 = 0,
    scroll_row: u16 = 0,

    // --- Network ---
    subnet_buf: [20]u8 = [_]u8{0} ** 20,
    subnet_len: usize = 0,
    router_buf: [16]u8 = [_]u8{0} ** 16,
    router_len: usize = 0,
    pool_start_buf: [16]u8 = [_]u8{0} ** 16,
    pool_start_len: usize = 0,
    pool_end_buf: [16]u8 = [_]u8{0} ** 16,
    pool_end_len: usize = 0,

    // --- Naming ---
    domain_name_buf: [64]u8 = [_]u8{0} ** 64,
    domain_name_len: usize = 0,

    // --- Domain Search (inline entries with edit modal) ---
    domain_search: [16]InlineEntry = [_]InlineEntry{.{}} ** 16,
    domain_search_count: usize = 0,

    // --- Inline server entry arrays ---
    dns_servers: [8]InlineEntry = [_]InlineEntry{.{}} ** 8,
    dns_servers_count: usize = 0,
    log_servers: [4]InlineEntry = [_]InlineEntry{.{}} ** 4,
    log_servers_count: usize = 0,
    ntp_servers: [4]InlineEntry = [_]InlineEntry{.{}} ** 4,
    ntp_servers_count: usize = 0,
    wins_servers: [2]InlineEntry = [_]InlineEntry{.{}} ** 2,
    wins_servers_count: usize = 0,
    tftp_servers: [4]InlineEntry = [_]InlineEntry{.{}} ** 4,
    tftp_servers_count: usize = 0,

    // --- Shared server edit modal state ---
    server_edit_target: ServerEditTarget = .domain_search,
    server_edit_buf: [64]u8 = [_]u8{0} ** 64,
    server_edit_len: usize = 0,
    server_edit_cursor: usize = 0,
    server_edit_index: ?usize = null, // null=adding, index=editing existing
    /// Which parent modal opened the server/route/option edit sub-modal.
    server_edit_parent: enum { pool_form, mac_class_edit } = .pool_form,

    // --- Timing ---
    lease_time_buf: [10]u8 = [_]u8{0} ** 10,
    lease_time_len: usize = 0,
    time_offset_buf: [8]u8 = [_]u8{0} ** 8,
    time_offset_len: usize = 0,

    // --- Servers ---
    time_servers_buf: [128]u8 = [_]u8{0} ** 128,
    time_servers_len: usize = 0,

    // --- Network (cont.) ---
    mtu_buf: [6]u8 = [_]u8{0} ** 6,
    mtu_len: usize = 0,

    // --- Boot ---
    boot_filename_buf: [128]u8 = [_]u8{0} ** 128,
    boot_filename_len: usize = 0,
    http_boot_url_buf: [256]u8 = [_]u8{0} ** 256,
    http_boot_url_len: usize = 0,

    // --- DNS Update ---
    dns_update_enable: bool = false,
    dns_update_server_buf: [64]u8 = [_]u8{0} ** 64,
    dns_update_server_len: usize = 0,
    dns_update_zone_buf: [64]u8 = [_]u8{0} ** 64,
    dns_update_zone_len: usize = 0,
    dns_update_key_name_buf: [64]u8 = [_]u8{0} ** 64,
    dns_update_key_name_len: usize = 0,
    dns_update_key_file_buf: [128]u8 = [_]u8{0} ** 128,
    dns_update_key_file_len: usize = 0,

    // --- Static Routes & DHCP Options (inline, with edit modals) ---
    routes: [32]RouteEntry = [_]RouteEntry{.{}} ** 32,
    route_count: usize = 0,
    options: [32]OptionEntry = [_]OptionEntry{.{}} ** 32,
    option_count: usize = 0,

    // --- MAC Classes (inline entries, with edit modal) ---
    mac_classes: [16]MacClassEntry = [_]MacClassEntry{.{}} ** 16,
    mac_class_count: usize = 0,
    /// MAC class edit modal state.
    mac_class_edit: MacClassEntry = .{},
    mac_class_edit_index: ?usize = null, // null=adding, index=editing existing
    mac_class_edit_field: u8 = 0,
    mac_class_edit_scroll: u16 = 0,
    mac_class_edit_cursor: usize = 0,

    // Route edit modal state.
    route_edit_dest: [18]u8 = [_]u8{0} ** 18,
    route_edit_dest_len: usize = 0,
    route_edit_router: [16]u8 = [_]u8{0} ** 16,
    route_edit_router_len: usize = 0,
    route_edit_field: u8 = 0, // 0=dest, 1=router
    route_edit_cursor: usize = 0,
    route_edit_index: ?usize = null, // null=adding, index=editing existing

    // Option edit modal state.
    opt_edit_code: [4]u8 = [_]u8{0} ** 4,
    opt_edit_code_len: usize = 0,
    opt_edit_value: [128]u8 = [_]u8{0} ** 128,
    opt_edit_value_len: usize = 0,
    opt_edit_field: u8 = 0, // 0=code, 1=value
    opt_edit_cursor: usize = 0,
    opt_edit_index: ?usize = null, // null=adding, index=editing existing

    // Option lookup filter (shared with pool option edit).
    opt_lookup_filter: [32]u8 = [_]u8{0} ** 32,
    opt_lookup_filter_len: usize = 0,
    opt_lookup_row: u16 = 0,

    // --- Cursor & Status ---
    cursor: usize = 0, // cursor position within the active field
    err_buf: [120]u8 = [_]u8{0} ** 120,
    err_len: usize = 0,

    const REGULAR_FIELD_COUNT: u8 = pool_field_meta.len;

    /// Which kind of navigable item the active_field corresponds to.
    const ActiveFieldKind = enum { field, add_button, inline_entry };
    const ActiveFieldInfo = struct {
        kind: ActiveFieldKind,
        /// For .field: pool_field_meta index.  For .add_button/.inline_entry: undefined.
        field_idx: u8 = 0,
        /// For .add_button/.inline_entry: which inline target.
        inline_target: ?InlineTarget = null,
        /// For .inline_entry: which entry within that section.
        entry_index: usize = 0,
    };

    /// Walk pool_layout to determine what kind of item the given active_field is.
    fn activeFieldInfo(self: *const PoolForm, af: u8) ActiveFieldInfo {
        var pos: u8 = 0;
        for (pool_layout) |item| {
            switch (item.kind) {
                .section => {},
                .field => {
                    if (pos == af) return .{ .kind = .field, .field_idx = item.field_idx.? };
                    pos += 1;
                },
                .inline_section => {
                    const target = item.inline_target.?;
                    if (pos == af) return .{ .kind = .add_button, .inline_target = target };
                    pos += 1;
                    const count = self.inlineCount(target);
                    if (af < pos + @as(u8, @intCast(count))) {
                        return .{ .kind = .inline_entry, .inline_target = target, .entry_index = af - pos };
                    }
                    pos += @intCast(count);
                },
            }
        }
        return .{ .kind = .field, .field_idx = 0 };
    }

    /// Return the active_field index for the [+] Add button or first entry of a target.
    fn fieldPosition(self: *const PoolForm, target: InlineTarget, which: enum { add_button, first_entry }) u8 {
        var pos: u8 = 0;
        for (pool_layout) |item| {
            switch (item.kind) {
                .section => {},
                .field => {
                    pos += 1;
                },
                .inline_section => {
                    const t = item.inline_target.?;
                    if (t == target) {
                        return if (which == .add_button) pos else pos + 1;
                    }
                    pos += 1; // [+] button
                    pos += @intCast(self.inlineCount(t));
                },
            }
        }
        return pos;
    }

    fn inlineCount(self: *const PoolForm, target: InlineTarget) usize {
        return switch (target) {
            .domain_search => self.domain_search_count,
            .dns => self.dns_servers_count,
            .wins => self.wins_servers_count,
            .ntp => self.ntp_servers_count,
            .log => self.log_servers_count,
            .tftp => self.tftp_servers_count,
            .routes => self.route_count,
            .options => self.option_count,
            .mac_classes => self.mac_class_count,
        };
    }

    fn inlineMax(target: InlineTarget) usize {
        return switch (target) {
            .domain_search => 16,
            .dns => 8,
            .wins => 2,
            .ntp => 4,
            .log => 4,
            .tftp => 4,
            .routes => 32,
            .options => 32,
            .mac_classes => 16,
        };
    }

    fn totalFields(self: *const PoolForm) u8 {
        var pos: u8 = 0;
        for (pool_layout) |item| {
            switch (item.kind) {
                .section => {},
                .field => {
                    pos += 1;
                },
                .inline_section => {
                    pos += 1; // [+] button
                    pos += @intCast(self.inlineCount(item.inline_target.?));
                },
            }
        }
        return pos;
    }

    fn isNew(self: *const PoolForm) bool {
        return self.editing_index == null;
    }
};

const PoolChangeKind = enum { sync_break, drift };

const PoolChange = struct {
    label: []const u8,
    old_val: []const u8,
    new_val: []const u8,
    kind: PoolChangeKind,
};

const PoolSaveConfirm = struct {
    changes: [32]PoolChange = undefined,
    change_count: usize = 0,
    has_sync_break: bool = false,
    is_new_pool: bool = false,
    is_delete: bool = false,
    scroll: u16 = 0,
    // Scratch buffer for formatting old/new value strings.
    scratch: [4096]u8 = undefined,
    scratch_used: usize = 0,
};

// Lease table sort state.  Column index matches LeaseRow field order (0-based).
const SortCol = enum(u8) { none = 255, ip = 0, mac = 1, hostname = 2, type = 3, expires = 4, pool = 5 };
const SortDir = enum { asc, desc };

const TuiState = struct {
    tab: Tab = .leases,
    mode: TuiMode = .normal,
    lease_row: u16 = 0,
    lease_start: u16 = 0,
    lease_prev_ctx_row: u16 = 0, // tracks table_ctx.row from last frame for MAC-follow
    sort_col: SortCol = .expires,
    sort_dir: SortDir = .desc,
    stats_scroll: u16 = 0,
    // Filter ('/') — active while the user is typing; cleared when Esc/Enter pressed.
    filter_active: bool = false,
    filter_buf: [256]u8 = undefined,
    filter_len: usize = 0,
    // Yank mode ('y' prefix) — next keypress copies i=IP, m=MAC, h=hostname via OSC 52.
    yank_mode: bool = false,
    // Selected row field values (updated each frame by renderLeaseTab).
    sel_ip: [16]u8 = [_]u8{0} ** 16,
    sel_ip_len: usize = 0,
    sel_mac: [18]u8 = [_]u8{0} ** 18,
    sel_mac_len: usize = 0,
    sel_hostname: [256]u8 = [_]u8{0} ** 256,
    sel_hostname_len: usize = 0,
    sel_reserved: bool = false,
    // Ctrl+R reload flash: show "Reloading config..." until this timestamp.
    reload_flash_until: i64 = 0,
    // Double-click detection: timestamp (ms) and row of last left-click.
    last_click_ms: i64 = 0,
    last_click_row: u16 = 0,
    last_click_tab: Tab = .leases,
    // Reservation form (mode == .reservation_form).
    form: ReservationForm = .{},
    // Delete confirm (mode == .delete_confirm): MAC of the reservation to delete.
    del_mac: [18]u8 = [_]u8{0} ** 18,
    del_mac_len: usize = 0,
    del_ip: [16]u8 = [_]u8{0} ** 16,
    del_ip_len: usize = 0,
    del_is_reservation: bool = false,
    // Pool tab state.
    pool_row: u16 = 0,
    pool_start: u16 = 0,
    pool_sort_col: u8 = 255, // 255 = no sort; 0-5 = column index
    pool_sort_asc: bool = true,
    pool_form: PoolForm = .{},
    pool_confirm: PoolSaveConfirm = .{},
    pool_detail_scroll: u16 = 0,
    pool_del_index: ?usize = null,
    // Pool filter (same pattern as lease filter).
    pool_filter_active: bool = false,
    pool_filter_buf: [256]u8 = undefined,
    pool_filter_len: usize = 0,
    // Settings tab.
    settings_row: u8 = 0,
    settings_scroll: u16 = 0,
    settings_cursor: usize = 0, // cursor position in the currently selected text field
    // Pending (dirty) values — applied on Enter, not immediately.
    settings_dirty: [SETTINGS_EDITABLE_COUNT]bool = [_]bool{false} ** SETTINGS_EDITABLE_COUNT,
    settings_pending_log_level: config_mod.LogLevel = .info,
    settings_pending_collect: bool = true,
    settings_pending_http_enable: bool = false,
    settings_pending_port_buf: [6]u8 = [_]u8{0} ** 6,
    settings_pending_port_len: usize = 0,
    settings_pending_bind_buf: [64]u8 = [_]u8{0} ** 64,
    settings_pending_bind_len: usize = 0,
    settings_pending_random_alloc: bool = false,
    settings_pending_config_sync: bool = false,
    settings_needs_scroll: bool = false, // set by key handler, cleared after auto-scroll
    // Dynamic line-to-edit mapping populated by renderSettingsTab, used by handleSettingsClick.
    settings_line_to_edit: [40]?u8 = [_]?u8{null} ** 40,
    settings_line_count: u16 = 0,
    // Validation error display.
    settings_err_buf: [80]u8 = [_]u8{0} ** 80,
    settings_err_len: usize = 0,
    // Confirmation diff lines (populated before entering settings_confirm mode).
    settings_confirm_buf: [512]u8 = [_]u8{0} ** 512,
    settings_confirm_len: usize = 0,
    settings_confirm_count: u8 = 0, // number of change lines
    settings_confirm_port_warn: bool = false, // port < 1024 warning
    help_scroll: u16 = 0,
};

/// Replicate the vaxis Table dynamic_fill column-width calculation.
fn calcDynColWidth(win_width: u16, num_cols: u16) u16 {
    if (num_cols == 0) return win_width;
    var cw: u16 = win_width / num_cols;
    if (cw % 2 != 0) cw +|= 1;
    while (@as(u32, cw) * num_cols < @as(u32, win_width) -| 1) cw +|= 1;
    return cw;
}

/// Case-insensitive substring search.
fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i <= haystack.len - needle.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

/// Send an OSC 52 clipboard write sequence (base64-encodes text).
/// Works over SSH with terminals that support OSC 52 (kitty, iTerm2, most
/// modern xterm-compatible terminals). No-op for terminals that ignore it.
fn sendOsc52(writer: *std.io.Writer, text: []const u8) !void {
    const enc = std.base64.standard.Encoder;
    const b64_len = enc.calcSize(text.len);
    // 512 bytes covers IP (20), MAC (24), and typical hostnames (≤344 for 256-char name).
    var b64_buf: [512]u8 = undefined;
    if (b64_len > b64_buf.len) return; // safety: skip if text is unexpectedly long
    const b64 = enc.encode(b64_buf[0..b64_len], text);
    try writer.writeAll("\x1b]52;c;");
    try writer.writeAll(b64);
    try writer.writeAll("\x07");
}

fn runTui(
    server: *AdminServer,
    session: c.ssh_session,
    channel: c.ssh_channel,
    init_cols: u32,
    init_rows: u32,
    peer: []const u8,
) !void {
    const allocator = server.allocator;

    log.debug("{s}: channel open={d} eof={d}", .{
        peer,
        c.ssh_channel_is_open(channel),
        c.ssh_channel_is_eof(channel),
    });

    // Build the SSH channel writer bridge.
    var gen_writer = SshChanGenericWriter{ .context = channel };
    var write_buf: [8192]u8 = undefined;
    // adapter must NOT be moved after this point (vtable uses @fieldParentPtr).
    var adapter = gen_writer.adaptToNewApi(&write_buf);
    const io = &adapter.new_interface;

    // Initialise vaxis.
    var vx = try vaxis.init(allocator, .{});
    defer vx.deinit(allocator, io);

    // Enter alt-screen and set initial size; flush immediately so the client
    // receives the sequences before the first read (SSH channel write is
    // buffered through the adapter — explicit flush is required after each
    // logical output operation).
    try vx.enterAltScreen(io);
    try io.flush();
    try vx.resize(allocator, io, .{
        .rows = @intCast(init_rows),
        .cols = @intCast(init_cols),
        .x_pixel = 0,
        .y_pixel = 0,
    });
    try vx.setMouseMode(io, true);
    try io.flush();

    var parser: vaxis.Parser = .{};
    var state: TuiState = .{};
    var table_ctx: vaxis.widgets.Table.TableContext = .{
        .selected_bg = .{ .rgb = .{ 32, 64, 128 } },
        .active_bg = .{ .rgb = .{ 48, 96, 192 } },
    };

    // Per-frame arena: reset each iteration after win.clear(), freed on exit.
    var frame_arena = std.heap.ArenaAllocator.init(allocator);
    defer frame_arena.deinit();

    // Read buffer for SSH channel input.
    var read_buf: [1024]u8 = undefined;
    var read_start: usize = 0;

    // Track the current terminal dimensions so partial resize events (where only
    // one dimension changes) can be merged with the other unchanged dimension.
    var cur_cols: u32 = init_cols;
    var cur_rows: u32 = init_rows;

    var running = true;
    while (running and server.running.load(.acquire)) {
        // Read keyboard/mouse input with a 100 ms timeout.
        // Return values: >0 bytes read; 0 = timeout; -1 = SSH_ERROR (fatal);
        // -2 = SSH_AGAIN (session momentarily non-blocking, no data — not fatal).
        const n_raw = c.ssh_channel_read_timeout(
            channel,
            &read_buf[read_start],
            @intCast(read_buf.len - read_start),
            0,
            100,
        );
        if (n_raw == -1) {
            log.debug("{s}: channel read error, closing TUI", .{peer});
            break;
        }
        if (c.ssh_channel_is_eof(channel) != 0) {
            log.debug("{s}: channel EOF, closing TUI", .{peer});
            break;
        }
        // SSH_AGAIN (-2): throttle briefly to avoid spinning.
        if (n_raw == -2) std.Thread.sleep(50 * std.time.ns_per_ms);

        // Drain the SSH message queue for window-change requests.
        // In libssh server mode, SSH_CHANNEL_REQUEST_WINDOW_CHANGE arrives in
        // the session message queue rather than via channel callbacks.
        // Switch to non-blocking mode so ssh_message_get returns NULL immediately
        // when the queue is empty; restore blocking mode afterwards.
        c.ssh_set_blocking(session, 0);
        while (true) {
            const msg = c.ssh_message_get(session) orelse break;
            defer c.ssh_message_free(msg);
            const mt = c.ssh_message_type(msg);
            const ms = c.ssh_message_subtype(msg);
            if (mt == c.SSH_REQUEST_CHANNEL and ms == c.SSH_CHANNEL_REQUEST_WINDOW_CHANGE) {
                const w = c.ssh_message_channel_request_pty_width(msg);
                const h = c.ssh_message_channel_request_pty_height(msg);
                const new_cols: u32 = if (w > 0) @intCast(w) else cur_cols;
                const new_rows: u32 = if (h > 0) @intCast(h) else cur_rows;
                if (new_cols != cur_cols or new_rows != cur_rows) {
                    log.debug("{s}: resize {d}x{d} → {d}x{d}", .{
                        peer, cur_cols, cur_rows, new_cols, new_rows,
                    });
                    cur_cols = new_cols;
                    cur_rows = new_rows;
                    try vx.resize(allocator, io, .{
                        .rows = @intCast(new_rows),
                        .cols = @intCast(new_cols),
                        .x_pixel = 0,
                        .y_pixel = 0,
                    });
                    // Belt-and-suspenders: also erase the full viewport so
                    // content outside the new bounds is gone before redraw.
                    try io.writeAll("\x1b[2J");
                    try io.flush();
                }
                // RFC 4254 §6.7: window-change requests need no reply.
            } else {
                _ = c.ssh_message_reply_default(msg);
            }
        }
        c.ssh_set_blocking(session, 1);

        const n: usize = if (n_raw > 0) @intCast(n_raw) else 0;
        const avail = read_start + n;

        // Feed available bytes to the vaxis parser.
        var seq_start: usize = 0;
        parse_loop: while (seq_start < avail) {
            const result = parser.parse(read_buf[seq_start..avail], null) catch break;
            if (result.n == 0) {
                // Incomplete sequence — shift unprocessed bytes to start of buf.
                const remaining = avail - seq_start;
                @memmove(read_buf[0..remaining], read_buf[seq_start..avail]);
                read_start = remaining;
                break :parse_loop;
            }
            read_start = 0;
            seq_start += result.n;

            const event = result.event orelse continue;
            switch (event) {
                .key_press => |key| {
                    // Modal modes consume all keys before normal/filter/yank handling.
                    if (state.mode == .reservation_form) {
                        handleFormKey(server, &state, key);
                        continue :parse_loop;
                    }
                    if (state.mode == .delete_confirm) {
                        handleDeleteConfirmKey(server, &state, key);
                        continue :parse_loop;
                    }
                    if (state.mode == .pool_detail) {
                        handlePoolDetailKey(server, &state, key);
                        continue :parse_loop;
                    }
                    if (state.mode == .pool_form) {
                        handlePoolFormKey(server, &state, key);
                        continue :parse_loop;
                    }
                    if (state.mode == .pool_save_confirm) {
                        handlePoolSaveConfirmKey(server, &state, key);
                        continue :parse_loop;
                    }
                    if (state.mode == .pool_delete_confirm) {
                        handlePoolDeleteConfirmKey(server, &state, key);
                        continue :parse_loop;
                    }
                    if (state.mode == .pool_server_edit) {
                        handlePoolServerEditKey(&state, key);
                        continue :parse_loop;
                    }
                    if (state.mode == .pool_route_edit) {
                        handlePoolRouteEditKey(&state, key);
                        continue :parse_loop;
                    }
                    if (state.mode == .pool_option_edit) {
                        handlePoolOptionEditKey(&state, key);
                        continue :parse_loop;
                    }
                    if (state.mode == .pool_mac_class_edit) {
                        handleMacClassEditKey(&state, key);
                        continue :parse_loop;
                    }
                    if (state.mode == .pool_option_lookup) {
                        handlePoolOptionLookupKey(&state, key);
                        continue :parse_loop;
                    }
                    if (state.mode == .help) {
                        if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{})) {
                            state.help_scroll +|= 1;
                        } else if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{})) {
                            state.help_scroll -|= 1;
                        } else {
                            state.mode = .normal;
                        }
                        continue :parse_loop;
                    }
                    if (state.mode == .settings_confirm) {
                        handleSettingsConfirmKey(server, &state, key);
                        continue :parse_loop;
                    }
                    if (state.mode == .res_option_edit) {
                        handleResOptionEditKey(&state, key);
                        continue :parse_loop;
                    }
                    if (state.mode == .option_lookup) {
                        handleOptionLookupKey(&state, key);
                        continue :parse_loop;
                    }
                    if (state.pool_filter_active) {
                        if (key.matches(vaxis.Key.escape, .{}) or
                            key.matches(vaxis.Key.enter, .{}))
                        {
                            state.pool_filter_active = false;
                        } else if (key.matches(vaxis.Key.backspace, .{})) {
                            if (state.pool_filter_len > 0) state.pool_filter_len -= 1;
                        } else if (key.codepoint >= 0x20 and key.codepoint <= 0x7E) {
                            if (state.pool_filter_len < state.pool_filter_buf.len - 1) {
                                state.pool_filter_buf[state.pool_filter_len] = @intCast(key.codepoint);
                                state.pool_filter_len += 1;
                            }
                        }
                        continue :parse_loop;
                    }
                    if (state.filter_active) {
                        // Filter input mode: Esc/Enter closes; Backspace deletes;
                        // printable ASCII appends.
                        if (key.matches(vaxis.Key.escape, .{}) or
                            key.matches(vaxis.Key.enter, .{}))
                        {
                            state.filter_active = false;
                        } else if (key.matches(vaxis.Key.backspace, .{})) {
                            if (state.filter_len > 0) state.filter_len -= 1;
                        } else if (key.codepoint >= 0x20 and key.codepoint <= 0x7E) {
                            if (state.filter_len < state.filter_buf.len - 1) {
                                state.filter_buf[state.filter_len] = @intCast(key.codepoint);
                                state.filter_len += 1;
                            }
                        }
                    } else if (state.yank_mode) {
                        // Yank mode: one keypress selects the field to copy.
                        state.yank_mode = false;
                        const yank_text: []const u8 = if (key.matches('i', .{}))
                            state.sel_ip[0..state.sel_ip_len]
                        else if (key.matches('m', .{}))
                            state.sel_mac[0..state.sel_mac_len]
                        else if (key.matches('h', .{}))
                            state.sel_hostname[0..state.sel_hostname_len]
                        else
                            "";
                        if (yank_text.len > 0) {
                            try sendOsc52(io, yank_text);
                            try io.flush();
                        }
                    } else {
                        // Normal mode.
                        if (key.matches('c', .{ .ctrl = true }) or key.matches('q', .{})) {
                            running = false;
                            break :parse_loop;
                        }
                        if (key.matches('r', .{ .ctrl = true })) {
                            // Send SIGHUP to self — triggers config reload in the DHCP run loop.
                            const pid = std.os.linux.getpid();
                            std.posix.kill(@intCast(pid), std.posix.SIG.HUP) catch |err| {
                                log.warn("{s}: Ctrl+R kill failed: {s}", .{ peer, @errorName(err) });
                            };
                            state.reload_flash_until = std.time.timestamp() + 3;
                        }
                        if (key.matches('y', .{}) and state.tab == .leases) {
                            state.yank_mode = true;
                        }
                        if (key.matches('/', .{}) and state.tab == .leases) {
                            state.filter_active = true;
                            state.filter_len = 0;
                        }
                        if (key.matches(vaxis.Key.escape, .{}) and state.tab == .leases) {
                            // Clear filter without opening input.
                            state.filter_len = 0;
                        }
                        // Sort shortcuts (leases tab only).
                        // I=ip  M=mac  H=hostname  T=type  E=expires  P=pool
                        // Pressing the active column's key again toggles asc/desc.
                        if (state.tab == .leases) {
                            const sort_key: ?SortCol = if (key.matches('I', .{}))
                                .ip
                            else if (key.matches('M', .{}))
                                .mac
                            else if (key.matches('H', .{}))
                                .hostname
                            else if (key.matches('T', .{}))
                                .type
                            else if (key.matches('E', .{}))
                                .expires
                            else if (key.matches('P', .{}))
                                .pool
                            else
                                null;
                            if (sort_key) |col| {
                                if (state.sort_col == col) {
                                    state.sort_dir = if (state.sort_dir == .asc) .desc else .asc;
                                } else {
                                    state.sort_col = col;
                                    state.sort_dir = .asc;
                                }
                            }
                        }
                        switch (state.tab) {
                            .leases => handleLeaseKey(&state, &table_ctx, key),
                            .stats => handleStatsKey(&state, key),
                            .pools => handlePoolsKey(server, &state, key),
                            .settings => handleSettingsKey(server, &state, key),
                        }
                        if (key.matches('1', .{})) state.tab = .leases;
                        if (key.matches('2', .{})) state.tab = .stats;
                        if (key.matches('3', .{})) state.tab = .pools;
                        if (key.matches('4', .{})) state.tab = .settings;
                        if (key.matches('?', .{})) {
                            state.help_scroll = 0;
                            state.mode = .help;
                        }
                        if (key.matches(vaxis.Key.tab, .{})) {
                            state.tab = switch (state.tab) {
                                .leases => .stats,
                                .stats => .pools,
                                .pools => .settings,
                                .settings => .leases,
                            };
                        }
                        if (key.matches(vaxis.Key.tab, .{ .shift = true })) {
                            state.tab = switch (state.tab) {
                                .leases => .settings,
                                .stats => .leases,
                                .pools => .stats,
                                .settings => .pools,
                            };
                        }

                        // Reservation actions (leases tab only).
                        if (state.tab == .leases) {
                            if (key.matches('n', .{})) {
                                // New blank reservation.
                                state.form = .{};
                                state.mode = .reservation_form;
                            } else if (key.matches('e', .{})) {
                                // Edit selected lease as a reservation.
                                state.form = .{};
                                const ip = state.sel_ip[0..state.sel_ip_len];
                                const mac = state.sel_mac[0..state.sel_mac_len];
                                const hn = state.sel_hostname[0..state.sel_hostname_len];
                                @memcpy(state.form.ip_buf[0..ip.len], ip);
                                state.form.ip_len = ip.len;
                                @memcpy(state.form.mac_buf[0..mac.len], mac);
                                state.form.mac_len = mac.len;
                                @memcpy(state.form.hostname_buf[0..hn.len], hn);
                                state.form.hostname_len = hn.len;
                                // Store orig_mac so we can remove the old entry on rename.
                                @memcpy(state.form.orig_mac[0..mac.len], mac);
                                state.form.orig_mac_len = mac.len;
                                state.form.cursor = ip.len;
                                state.mode = .reservation_form;
                            } else if (key.matches('d', .{}) and state.sel_mac_len > 0) {
                                // Delete/release confirmation for any lease.
                                const mac = state.sel_mac[0..state.sel_mac_len];
                                const ip = state.sel_ip[0..state.sel_ip_len];
                                @memcpy(state.del_mac[0..mac.len], mac);
                                state.del_mac_len = mac.len;
                                @memcpy(state.del_ip[0..ip.len], ip);
                                state.del_ip_len = ip.len;
                                state.del_is_reservation = state.sel_reserved;
                                state.mode = .delete_confirm;
                            }
                        }
                    }
                },
                .mouse => |mouse| {
                    switch (mouse.button) {
                        .left => if (mouse.type == .press) {
                            // Modal overlays: [X] close + field click detection.
                            if (state.mode != .normal) {
                                const mr: u16 = if (mouse.row >= 0) @intCast(mouse.row) else 0;
                                const mc: u16 = if (mouse.col >= 0) @intCast(mouse.col) else 0;
                                const vwin = vx.window();
                                if (isModalCloseClick(state.mode, vwin.width, vwin.height, mr, mc, &state)) {
                                    // Sub-modals return to their parent; top-level modals return to normal.
                                    state.mode = switch (state.mode) {
                                        .res_option_edit => .reservation_form,
                                        .option_lookup => .res_option_edit,
                                        .pool_server_edit, .pool_route_edit, .pool_option_edit => subModalParent(&state.pool_form),
                                        .pool_mac_class_edit => .pool_form,
                                        .pool_option_lookup => .pool_option_edit,
                                        else => .normal,
                                    };
                                } else {
                                    // Double-click detection for modals.
                                    const modal_now = std.time.milliTimestamp();
                                    const modal_dbl = (modal_now - state.last_click_ms < 400 and mr == state.last_click_row);
                                    state.last_click_ms = modal_now;
                                    state.last_click_row = mr;
                                    handleModalFieldClick(&state, vwin.width, vwin.height, mr);
                                    // Double-click on [+] Add buttons triggers the add action.
                                    if (modal_dbl) {
                                        if (state.mode == .reservation_form and state.form.active_field == 3) {
                                            // Simulate Enter on [+] Add for reservation options.
                                            handleFormKey(server, &state, .{ .codepoint = vaxis.Key.enter });
                                        } else if (state.mode == .pool_form) {
                                            const pf = &state.pool_form;
                                            if (pf.activeFieldInfo(pf.active_field).kind == .add_button) {
                                                handlePoolFormKey(server, &state, .{ .codepoint = vaxis.Key.enter });
                                            }
                                        } else if (state.mode == .pool_mac_class_edit) {
                                            const mci = mcActiveFieldInfo(&state.pool_form.mac_class_edit, state.pool_form.mac_class_edit_field);
                                            if (mci.kind == .add_button) {
                                                handleMacClassEditKey(&state, .{ .codepoint = vaxis.Key.enter });
                                            }
                                        }
                                    }
                                }
                                break;
                            }
                            const term_row: u16 = if (mouse.row >= 0) @intCast(mouse.row) else 0;
                            const term_col: u16 = if (mouse.col >= 0) @intCast(mouse.col) else 0;
                            const now_ms = std.time.milliTimestamp();
                            const is_double = (now_ms - state.last_click_ms < 400 and
                                term_row == state.last_click_row and
                                state.tab == state.last_click_tab);
                            state.last_click_ms = now_ms;
                            state.last_click_row = term_row;
                            state.last_click_tab = state.tab;
                            if (term_row == 0) {
                                // Header bar: tab switching.
                                // Layout: " Stardust "(10) + " [1] Leases "(12) + " [2] Stats "(11) + " [3] Pools "(11)
                                // Layout: " Stardust "(10) + " [1] Leases "(12) + " [2] Stats "(11) + " [3] Pools "(11) + " [4] Settings "(14)
                                if (term_col >= 10 and term_col < 22) {
                                    state.tab = .leases;
                                } else if (term_col >= 22 and term_col < 33) {
                                    state.tab = .stats;
                                } else if (term_col >= 33 and term_col < 44) {
                                    state.tab = .pools;
                                } else if (term_col >= 44 and term_col < 58) {
                                    state.tab = .settings;
                                }
                            } else if (state.tab == .pools) {
                                if (term_row == 1) {
                                    // Column header: sort by clicked column.
                                    const pw = calcPoolColWidths(@intCast(vx.window().width));
                                    const clicked_col = hitTestCol(u16, &pw, LEASE_COL_SEP, term_col);
                                    if (clicked_col) |col| {
                                        const ci: u8 = @intCast(col);
                                        if (state.pool_sort_col == ci) {
                                            state.pool_sort_asc = !state.pool_sort_asc;
                                        } else {
                                            state.pool_sort_col = ci;
                                            state.pool_sort_asc = true;
                                        }
                                    }
                                } else if (term_row >= 2) {
                                    const clicked: u32 = (term_row - 2) + state.pool_start;
                                    if (clicked < server.cfg.pools.len) {
                                        state.pool_row = @intCast(clicked);
                                        if (is_double) {
                                            // Double-click: open detail view.
                                            state.pool_detail_scroll = 0;
                                            state.mode = .pool_detail;
                                        }
                                    }
                                }
                            } else if (state.tab == .leases) {
                                if (term_row == 1) {
                                    // Column header row: sort by clicked column.
                                    const lw = calcLeaseColWidths(@intCast(vx.window().width));
                                    const clicked_col: SortCol = if (hitTestCol(u16, &lw, LEASE_COL_SEP, term_col)) |ci|
                                        @enumFromInt(@min(ci, 5))
                                    else
                                        .ip;
                                    if (state.sort_col == clicked_col) {
                                        state.sort_dir = if (state.sort_dir == .asc) .desc else .asc;
                                    } else {
                                        state.sort_col = clicked_col;
                                        state.sort_dir = .asc;
                                    }
                                } else if (term_row >= 2) {
                                    // Data row: select it.
                                    const clicked: u32 = (term_row - 2) + table_ctx.start;
                                    if (clicked <= std.math.maxInt(u16)) {
                                        table_ctx.row = @intCast(clicked);
                                        if (is_double and state.mode == .normal) {
                                            // Double-click: open reservation edit form
                                            // (sel_* fields are updated on next render, so
                                            // we force an update from the current table_ctx).
                                            state.form = .{};
                                            const ip = state.sel_ip[0..state.sel_ip_len];
                                            const mac = state.sel_mac[0..state.sel_mac_len];
                                            const hn = state.sel_hostname[0..state.sel_hostname_len];
                                            @memcpy(state.form.ip_buf[0..ip.len], ip);
                                            state.form.ip_len = ip.len;
                                            @memcpy(state.form.mac_buf[0..mac.len], mac);
                                            state.form.mac_len = mac.len;
                                            @memcpy(state.form.hostname_buf[0..hn.len], hn);
                                            state.form.hostname_len = hn.len;
                                            @memcpy(state.form.orig_mac[0..mac.len], mac);
                                            state.form.orig_mac_len = mac.len;
                                            state.form.cursor = ip.len;
                                            state.mode = .reservation_form;
                                        }
                                    }
                                }
                            } else if (state.tab == .settings) {
                                // Click on settings fields — map row to editable field.
                                handleSettingsClick(&state, server.cfg, term_row, state.settings_scroll);
                            }
                        },
                        .wheel_right => if (state.mode == .normal) {
                            state.tab = switch (state.tab) {
                                .leases => .leases,
                                .stats => .leases,
                                .pools => .stats,
                                .settings => .pools,
                            };
                        },
                        .wheel_left => if (state.mode == .normal) {
                            state.tab = switch (state.tab) {
                                .leases => .stats,
                                .stats => .pools,
                                .pools => .settings,
                                .settings => .settings,
                            };
                        },
                        .wheel_up => switch (state.mode) {
                            .pool_detail => state.pool_detail_scroll -|= 3,
                            .pool_save_confirm => state.pool_confirm.scroll -|= 3,
                            .pool_form => if (state.pool_form.active_field > 0) {
                                state.pool_form.active_field -= 1;
                                state.pool_form.cursor = activeFieldCursorLen(&state.pool_form, state.pool_form.active_field);
                            },
                            .normal => switch (state.tab) {
                                .leases => table_ctx.row -|= 1,
                                .stats => state.stats_scroll -|= 3,
                                .pools => state.pool_row -|= 1,
                                .settings => state.settings_scroll -|= 1,
                            },
                            .reservation_form => {
                                if (state.form.active_field > 0) state.form.active_field -= 1;
                            },
                            .pool_mac_class_edit => if (state.pool_form.mac_class_edit_field > 0) {
                                state.pool_form.mac_class_edit_field -= 1;
                                state.pool_form.mac_class_edit_cursor = mcActiveFieldCursorLen(&state.pool_form.mac_class_edit, state.pool_form.mac_class_edit_field);
                            },
                            .pool_option_lookup => state.pool_form.opt_lookup_row -|= 1,
                            .option_lookup => if (state.form.opt_lookup_row > 0) {
                                state.form.opt_lookup_row -= 1;
                            },
                            // All other modals: swallow scroll.
                            .help => state.help_scroll -|= 1,
                            .delete_confirm, .pool_delete_confirm, .pool_server_edit, .pool_route_edit, .pool_option_edit, .res_option_edit, .settings_confirm => {},
                        },
                        .wheel_down => switch (state.mode) {
                            .pool_detail => state.pool_detail_scroll +|= 3,
                            .pool_save_confirm => state.pool_confirm.scroll +|= 3,
                            .pool_form => if (state.pool_form.active_field + 1 < state.pool_form.totalFields()) {
                                state.pool_form.active_field += 1;
                                state.pool_form.cursor = activeFieldCursorLen(&state.pool_form, state.pool_form.active_field);
                            },
                            .normal => switch (state.tab) {
                                .leases => table_ctx.row +|= 1,
                                .stats => state.stats_scroll +|= 3,
                                .pools => if (state.pool_row + 1 < server.cfg.pools.len) {
                                    state.pool_row += 1;
                                },
                                .settings => state.settings_scroll +|= 1,
                            },
                            .reservation_form => {
                                if (state.form.active_field + 1 < state.form.totalFields()) state.form.active_field += 1;
                            },
                            .pool_mac_class_edit => {
                                const mc_total = mcTotalFields(&state.pool_form.mac_class_edit);
                                if (state.pool_form.mac_class_edit_field + 1 < mc_total) {
                                    state.pool_form.mac_class_edit_field += 1;
                                    state.pool_form.mac_class_edit_cursor = mcActiveFieldCursorLen(&state.pool_form.mac_class_edit, state.pool_form.mac_class_edit_field);
                                }
                            },
                            .pool_option_lookup => {
                                state.pool_form.opt_lookup_row +|= 1;
                            },
                            .option_lookup => {
                                state.form.opt_lookup_row +|= 1;
                            },
                            .help => state.help_scroll +|= 1,
                            .delete_confirm, .pool_delete_confirm, .pool_server_edit, .pool_route_edit, .pool_option_edit, .res_option_edit, .settings_confirm => {},
                        },
                        else => {},
                    }
                },
                else => {},
            }
        }

        // Render a frame and flush to the SSH channel.
        // win.clear() drops refs to the previous frame's grapheme slices; then
        // reset the frame arena and rebuild for this frame.  The arena must
        // stay alive through vx.render(io) because Cell.char.grapheme is a
        // []const u8 slice into the input string — vaxis does NOT copy it.
        // InternalScreen.eql dereferences that pointer during render.
        const win = vx.window();
        win.clear();
        _ = frame_arena.reset(.retain_capacity);
        const fa = frame_arena.allocator();
        try renderFrame(server, &state, &table_ctx, win, fa);
        try vx.render(io); // frame_arena still alive — grapheme slices valid
        try io.flush();
    }

    try vx.exitAltScreen(io);
    try io.flush();
}

fn handleLeaseKey(state: *TuiState, ctx: *vaxis.widgets.Table.TableContext, key: vaxis.Key) void {
    if (key.matchesAny(&.{ vaxis.Key.down, 'j' }, .{})) {
        ctx.row +|= 1;
    } else if (key.matchesAny(&.{ vaxis.Key.up, 'k' }, .{})) {
        ctx.row -|= 1;
    } else if (key.matches(vaxis.Key.page_down, .{})) {
        ctx.row +|= 20;
    } else if (key.matches(vaxis.Key.page_up, .{})) {
        ctx.row -|= 20;
    }
    state.lease_row = ctx.row;
    state.lease_start = ctx.start;
}

fn handleStatsKey(state: *TuiState, key: vaxis.Key) void {
    if (key.matchesAny(&.{ vaxis.Key.down, 'j' }, .{})) {
        state.stats_scroll +|= 1;
    } else if (key.matchesAny(&.{ vaxis.Key.up, 'k' }, .{})) {
        state.stats_scroll -|= 1;
    } else if (key.matches(vaxis.Key.page_down, .{})) {
        state.stats_scroll +|= 20;
    } else if (key.matches(vaxis.Key.page_up, .{})) {
        state.stats_scroll -|= 20;
    }
}

// ---------------------------------------------------------------------------
// Frame rendering
// ---------------------------------------------------------------------------

fn renderFrame(
    server: *AdminServer,
    state: *TuiState,
    table_ctx: *vaxis.widgets.Table.TableContext,
    win: vaxis.Window,
    fa: std.mem.Allocator,
) !void {
    if (win.height < 4 or win.width < 20) return; // terminal too small

    const h = win.height;
    const w = win.width;

    // Header bar (row 0)
    renderHeader(server, state, win.child(.{ .y_off = 0, .height = 1, .width = w }));

    // Body (rows 1 .. h-2)
    const body = win.child(.{
        .y_off = 1,
        .height = h -| 2,
        .width = w,
    });

    switch (state.tab) {
        .leases => try renderLeaseTab(server, state, table_ctx, body, fa),
        .stats => try renderStatsTab(server, state, body, fa),
        .pools => try renderPoolsTab(server, state, body, fa),
        .settings => try renderSettingsTab(server, state, body, fa),
    }

    // Status bar (last row)
    try renderStatus(server, state, win.child(.{ .y_off = h -| 1, .height = 1, .width = w }), fa);

    // Modal overlays — drawn on top of everything else.
    switch (state.mode) {
        .normal => {},
        .reservation_form => try renderReservationForm(state, win, fa),
        .delete_confirm => renderDeleteConfirm(state, win),
        .pool_detail => try renderPoolDetail(server, state, win, fa),
        .pool_form => try renderPoolForm(state, win, fa),
        .pool_save_confirm => try renderPoolSaveConfirm(server, state, win, fa),
        .pool_delete_confirm => try renderPoolDeleteConfirm(server, state, win, fa),
        .pool_server_edit => try renderPoolServerEdit(state, win, fa),
        .pool_route_edit => try renderPoolRouteEdit(state, win, fa),
        .pool_option_edit => try renderPoolOptionEdit(state, win, fa),
        .pool_mac_class_edit => try renderMacClassEdit(state, win, fa),
        .pool_option_lookup => try renderPoolOptionLookup(state, win, fa),
        .help => renderHelp(state, win),
        .res_option_edit => try renderResOptionEdit(state, win, fa),
        .option_lookup => try renderOptionLookup(state, win, fa),
        .settings_confirm => try renderSettingsConfirm(state, win, fa),
    }
}

fn renderHeader(server: *AdminServer, state: *TuiState, win: vaxis.Window) void {
    const tab_style_active: vaxis.Style = .{
        .fg = .{ .rgb = .{ 0, 0, 0 } },
        .bg = .{ .rgb = .{ 64, 160, 255 } },
        .bold = true,
    };
    const tab_style_inactive: vaxis.Style = .{
        .fg = .{ .rgb = .{ 180, 180, 180 } },
        .bg = .{ .rgb = .{ 30, 30, 30 } },
    };
    const title_style: vaxis.Style = .{
        .fg = .{ .rgb = .{ 255, 200, 80 } },
        .bg = .{ .rgb = .{ 20, 20, 20 } },
        .bold = true,
    };
    const hint_style: vaxis.Style = .{
        .fg = .{ .rgb = .{ 120, 120, 120 } },
        .bg = .{ .rgb = .{ 20, 20, 20 } },
    };

    // Fill the header row background
    win.fill(.{ .style = .{ .bg = .{ .rgb = .{ 20, 20, 20 } } } });

    var col: u16 = 0;
    _ = win.print(&.{.{ .text = " Stardust ", .style = title_style }}, .{ .col_offset = col, .wrap = .none });
    col += 10;

    const tab_labels = [_]struct { text: []const u8, tab: Tab }{
        .{ .text = " [1] Leases ", .tab = .leases },
        .{ .text = " [2] Stats ", .tab = .stats },
        .{ .text = " [3] Pools ", .tab = .pools },
        .{ .text = " [4] Settings ", .tab = .settings },
    };
    for (tab_labels) |tl| {
        const style = if (state.tab == tl.tab) tab_style_active else tab_style_inactive;
        _ = win.print(&.{.{ .text = tl.text, .style = style }}, .{ .col_offset = col, .wrap = .none });
        col += @intCast(tl.text.len);
    }

    const hint: []const u8 = switch (state.tab) {
        .leases => "  /:filter  n:new  e:edit  d:delete",
        .stats => "",
        .pools => if (server.cfg.admin_ssh.read_only) "  /:filter  v:view" else "  /:filter  v:view  e:edit  n:new  d:del",
        .settings => "  j/k:move  Space:toggle  Enter:review & save",
    };
    _ = win.print(&.{.{ .text = hint, .style = hint_style }}, .{ .col_offset = col, .wrap = .none });
}

fn renderStatus(server: *AdminServer, state: *TuiState, win: vaxis.Window, fa: std.mem.Allocator) !void {
    win.fill(.{ .style = .{ .bg = .{ .rgb = .{ 15, 15, 15 } } } });

    if (state.tab == .leases and state.yank_mode) {
        const yank_style: vaxis.Style = .{
            .fg = .{ .rgb = .{ 0, 0, 0 } },
            .bg = .{ .rgb = .{ 80, 220, 80 } },
            .bold = true,
        };
        _ = win.print(&.{
            .{ .text = " YANK: i=IP  m=MAC  h=hostname  (any other key cancels)", .style = yank_style },
        }, .{ .col_offset = 0, .wrap = .none });
        return;
    }

    if (state.tab == .pools and state.pool_filter_active) {
        const filter_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 220, 80 } }, .bg = .{ .rgb = .{ 15, 15, 15 } } };
        const cursor_style2: vaxis.Style = .{ .fg = .{ .rgb = .{ 0, 0, 0 } }, .bg = .{ .rgb = .{ 255, 220, 80 } } };
        const prompt = try std.fmt.allocPrint(fa, " / {s}", .{state.pool_filter_buf[0..state.pool_filter_len]});
        _ = win.print(&.{
            .{ .text = prompt, .style = filter_style },
            .{ .text = " ", .style = cursor_style2 },
            .{ .text = "  Esc/Enter to close", .style = .{ .fg = .{ .rgb = .{ 100, 100, 100 } }, .bg = .{ .rgb = .{ 15, 15, 15 } } } },
        }, .{ .col_offset = 0, .wrap = .none });
        return;
    }
    if (state.tab == .leases and state.filter_active) {
        // Filter input bar.
        const filter_style: vaxis.Style = .{
            .fg = .{ .rgb = .{ 255, 220, 80 } },
            .bg = .{ .rgb = .{ 15, 15, 15 } },
        };
        const cursor_style: vaxis.Style = .{
            .fg = .{ .rgb = .{ 0, 0, 0 } },
            .bg = .{ .rgb = .{ 255, 220, 80 } },
        };
        const prompt = try std.fmt.allocPrint(fa, " / {s}", .{state.filter_buf[0..state.filter_len]});
        _ = win.print(&.{
            .{ .text = prompt, .style = filter_style },
            .{ .text = " ", .style = cursor_style },
            .{ .text = "  Esc/Enter to close", .style = .{ .fg = .{ .rgb = .{ 100, 100, 100 } }, .bg = .{ .rgb = .{ 15, 15, 15 } } } },
        }, .{ .col_offset = 0, .wrap = .none });
        return;
    }

    // Normal status bar.
    const style: vaxis.Style = .{
        .fg = .{ .rgb = .{ 150, 150, 150 } },
        .bg = .{ .rgb = .{ 15, 15, 15 } },
    };
    const now = std.time.timestamp();

    if (now <= state.reload_flash_until) {
        const flash_style: vaxis.Style = .{
            .fg = .{ .rgb = .{ 0, 0, 0 } },
            .bg = .{ .rgb = .{ 80, 180, 255 } },
            .bold = true,
        };
        _ = win.print(&.{.{ .text = " Reloading config... (settings not applied live require a process restart)", .style = flash_style }}, .{ .col_offset = 0, .wrap = .none });
        return;
    }
    const uptime_s = now - server.start_time;
    const uptime_h = @divTrunc(uptime_s, 3600);
    const uptime_m = @divTrunc(@rem(uptime_s, 3600), 60);

    const filter_note: []const u8 = if (state.tab == .leases and state.filter_len > 0)
        try std.fmt.allocPrint(fa, "  filter: {s}  (Esc clears)", .{state.filter_buf[0..state.filter_len]})
    else
        "";

    const rw_label = if (server.cfg.admin_ssh.read_only) "read-only" else "read-write";

    const text = try std.fmt.allocPrint(fa, " uptime {d}h{d:0>2}m  {s}{s}", .{
        uptime_h,
        uptime_m,
        rw_label,
        filter_note,
    });
    _ = win.print(&.{.{ .text = text, .style = style }}, .{ .col_offset = 0, .wrap = .none });

    // Sync peer indicator — only when sync is configured.
    if (server.sync_mgr) |sm| {
        const n = sm.authenticated_count.load(.monotonic);
        const col: u16 = @intCast(text.len);
        if (n == 0) {
            const warn_style: vaxis.Style = .{
                .fg = .{ .rgb = .{ 255, 160, 0 } },
                .bg = .{ .rgb = .{ 15, 15, 15 } },
                .bold = true,
            };
            _ = win.print(&.{.{ .text = "  sync: no peers", .style = warn_style }}, .{ .col_offset = col, .wrap = .none });
        } else {
            const peer_str = if (n == 1)
                try std.fmt.allocPrint(fa, "  {d} peer", .{n})
            else
                try std.fmt.allocPrint(fa, "  {d} peers", .{n});
            _ = win.print(&.{.{ .text = peer_str, .style = style }}, .{ .col_offset = col, .wrap = .none });
        }
    }

    // Right-aligned global shortcuts.
    const global_hint = "?:help  q:quit ";
    const rhs_col: u16 = if (win.width > global_hint.len) win.width - @as(u16, @intCast(global_hint.len)) else 0;
    _ = win.print(&.{.{ .text = global_hint, .style = style }}, .{ .col_offset = rhs_col, .wrap = .none });
}

// ---------------------------------------------------------------------------
// Lease tab
// ---------------------------------------------------------------------------

// Column base names (index matches SortCol enum value).
const LEASE_COL_NAMES = [_][]const u8{ "ip", "mac", "hostname", "type", "expires", "pool" };

// Per-column layout spec:
//   ideal     — preferred width (chars) when terminal has enough space
//   min       — minimum width before this column is squeezed no further
//   left_trunc — true = show the END of the string (best for addresses);
//               false = show the START (best for hostnames, labels)
const LeaseColSpec = struct { ideal: u16, min: u16, left_trunc: bool, right_align: bool = false };
const LEASE_COL_SPECS = [6]LeaseColSpec{
    .{ .ideal = 16, .min = 7, .left_trunc = true }, // ip      ("255.255.255.255" = 15 + 1 padding)
    .{ .ideal = 18, .min = 9, .left_trunc = true }, // mac     ("aa:bb:cc:dd:ee:ff" = 17 + 1 padding)
    .{ .ideal = 60, .min = 6, .left_trunc = false }, // hostname (room for FQDNs)
    .{ .ideal = 8, .min = 4, .left_trunc = false }, // type    ("reserved" = 8)
    .{ .ideal = 9, .min = 7, .left_trunc = false }, // expires ("1234h56m" ~ 9)
    .{ .ideal = 18, .min = 10, .left_trunc = false, .right_align = true }, // pool    ("192.168.100.0/24" = 16)
};
// Columns reduced in this priority order when terminal is too narrow.
// Flexible/variable content is reduced first; address columns last.
const LEASE_COL_REDUCE_ORDER = [6]usize{ 2, 5, 4, 3, 0, 1 }; // hostname→pool→exp→type→ip→mac
const LEASE_COL_SEP: u16 = 1; // single space between columns

/// Calculate column widths that fit within win_width.
/// Total occupied = sum(widths) + (N-1)*LEASE_COL_SEP.
fn calcLeaseColWidths(win_width: u16) [6]u16 {
    var widths: [6]u16 = undefined;
    for (LEASE_COL_SPECS, 0..) |spec, i| widths[i] = spec.ideal;
    const seps: u16 = (LEASE_COL_SPECS.len - 1) * LEASE_COL_SEP;
    var total: u16 = seps;
    for (widths) |w| total +|= w;
    for (LEASE_COL_REDUCE_ORDER) |col| {
        if (total <= win_width) break;
        const over = total - win_width;
        const slack = widths[col] - LEASE_COL_SPECS[col].min;
        const cut = @min(over, slack);
        widths[col] -= cut;
        total -= cut;
    }
    return widths;
}

/// Given column widths and a separator size, return which column index
/// the terminal column `x` falls within, or null if past all columns.
fn hitTestCol(comptime T: type, widths: []const T, sep: T, x: u16) ?usize {
    var edge: u16 = 0;
    for (widths, 0..) |w, i| {
        edge += @intCast(w);
        if (x < edge) return i;
        edge += @intCast(sep);
    }
    return null;
}

/// Right-align `text` within `width` columns by prepending spaces.
/// Returns text unchanged if it already fills or exceeds the width.
fn rightAlignText(fa: std.mem.Allocator, text: []const u8, width: u16) ![]const u8 {
    if (text.len >= width) return text;
    const pad = width - @as(u16, @intCast(text.len));
    const buf = try fa.alloc(u8, width);
    @memset(buf[0..pad], ' ');
    @memcpy(buf[pad..], text);
    return buf;
}

/// Truncate `text` to fit within `width` terminal columns using a single '…'.
/// left_trunc=true  → show the END of the string ("…1.100" for an IP);
/// left_trunc=false → show the BEGINNING ("hostname…").
/// Returns a slice of the input (no alloc) when it already fits.
fn truncateCell(fa: std.mem.Allocator, text: []const u8, width: u16, left_trunc: bool) ![]const u8 {
    if (width == 0) return "";
    if (text.len <= width) return text; // fits as-is (ASCII assumed for network data)
    if (width == 1) return "…";
    const content_len = width - 1; // one column reserved for the ellipsis
    if (left_trunc) {
        return try std.fmt.allocPrint(fa, "…{s}", .{text[text.len - content_len ..]});
    } else {
        return try std.fmt.allocPrint(fa, "{s}…", .{text[0..content_len]});
    }
}

/// Custom lease-table renderer with fixed-width address columns and sensible
/// proportional widths.  Replaces vaxis.widgets.Table.drawTable.
fn drawLeaseTable(
    win: vaxis.Window,
    rows: []const LeaseRow,
    ctx: *vaxis.widgets.Table.TableContext,
    header_names: []const []const u8,
    fa: std.mem.Allocator,
) !void {
    if (win.height < 2 or win.width < 10) return;

    const widths = calcLeaseColWidths(@intCast(win.width));
    const hdr_bg: vaxis.Color = .{ .rgb = .{ 30, 30, 50 } };
    const hdr_style: vaxis.Style = .{
        .bold = true,
        .fg = .{ .rgb = .{ 200, 200, 200 } },
        .bg = hdr_bg,
    };

    // --- Header row ---
    {
        const hdr_win = win.child(.{ .y_off = 0, .height = 1, .width = win.width });
        hdr_win.fill(.{ .style = .{ .bg = hdr_bg } });
        var x: i17 = 0;
        for (0..6) |ci| {
            if (widths[ci] > 0) {
                const cell = hdr_win.child(.{ .x_off = x, .y_off = 0, .width = widths[ci], .height = 1 });
                const raw = try truncateCell(fa, header_names[ci], widths[ci], false);
                const text = if (LEASE_COL_SPECS[ci].right_align) try rightAlignText(fa, raw, widths[ci]) else raw;
                _ = cell.print(&.{.{ .text = text, .style = hdr_style }}, .{ .wrap = .none });
            }
            x += @as(i17, widths[ci]) + LEASE_COL_SEP;
        }
    }

    // --- Scroll-offset management (mirrors vaxis Table logic) ---
    const visible: u16 = win.height -| 1;
    const n: u16 = if (rows.len > 0xFFFF) 0xFFFF else @intCast(rows.len);
    if (n > 0 and ctx.row >= n) ctx.row = n - 1;
    if (n == 0) ctx.row = 0;
    ctx.start = start: {
        if (ctx.row == 0) break :start 0;
        if (ctx.row < ctx.start) break :start ctx.row;
        const end = ctx.start +| visible;
        if (ctx.row >= end) break :start ctx.start + (ctx.row - end + 1);
        break :start ctx.start;
    };

    // --- Data rows ---
    const even_bg: vaxis.Color = .{ .rgb = .{ 20, 20, 30 } };
    const odd_bg: vaxis.Color = .{ .rgb = .{ 26, 26, 36 } };
    for (0..visible) |ri| {
        const row_idx = ctx.start + @as(u16, @intCast(ri));
        if (row_idx >= rows.len) break;
        const row = rows[row_idx];
        const selected = (row_idx == ctx.row);
        const row_bg: vaxis.Color = if (selected) ctx.active_bg else if (ri % 2 != 0) odd_bg else even_bg;
        const row_style: vaxis.Style = .{ .bg = row_bg };

        const row_win = win.child(.{ .x_off = 0, .y_off = @intCast(ri + 1), .width = win.width, .height = 1 });
        row_win.fill(.{ .style = row_style });

        const fields = [6][]const u8{ row.ip, row.mac, row.hostname, row.type, row.expires, row.pool };
        var x: i17 = 0;
        for (0..6) |ci| {
            if (widths[ci] > 0) {
                const cell = row_win.child(.{ .x_off = x, .y_off = 0, .width = widths[ci], .height = 1 });
                const spec = LEASE_COL_SPECS[ci];
                const raw = try truncateCell(fa, fields[ci], widths[ci], spec.left_trunc);
                const text = if (spec.right_align) try rightAlignText(fa, raw, widths[ci]) else raw;
                _ = cell.print(&.{.{ .text = text, .style = row_style }}, .{ .wrap = .none });
            }
            x += @as(i17, widths[ci]) + LEASE_COL_SEP;
        }
    }
}

/// Sort context for raw leases.  Operates on state_mod.Lease directly so that
/// the expires column sorts by numeric timestamp rather than a formatted string.
const LeaseSort = struct {
    col: SortCol,
    dir: SortDir,
    cfg: *const config_mod.Config,

    fn lessThan(ctx: LeaseSort, a: state_mod.Lease, b: state_mod.Lease) bool {
        const asc = switch (ctx.col) {
            .none => return false,
            .ip => ipLess(a.ip, b.ip),
            .mac => std.mem.lessThan(u8, a.mac, b.mac),
            .hostname => std.mem.lessThan(u8, a.hostname orelse "", b.hostname orelse ""),
            .type => std.mem.lessThan(u8, if (a.reserved) "reserved" else "dynamic", if (b.reserved) "reserved" else "dynamic"),
            .expires => expiresLess(a, b),
            .pool => poolLess(ctx.cfg, a.ip, b.ip),
        };
        return if (ctx.dir == .asc) asc else !asc;
    }

    fn ipLess(a: []const u8, b: []const u8) bool {
        const a_bytes = config_mod.parseIpv4(a) catch return false;
        const b_bytes = config_mod.parseIpv4(b) catch return true;
        const a_n = std.mem.readInt(u32, &a_bytes, .big);
        const b_n = std.mem.readInt(u32, &b_bytes, .big);
        return a_n < b_n;
    }

    fn expiresLess(a: state_mod.Lease, b: state_mod.Lease) bool {
        // Treat reserved leases as expires = maxInt so they sort after dynamic leases.
        const a_exp: i64 = if (a.reserved) std.math.maxInt(i64) else a.expires;
        const b_exp: i64 = if (b.reserved) std.math.maxInt(i64) else b.expires;
        return a_exp < b_exp;
    }

    fn poolLess(cfg: *const config_mod.Config, a_ip: []const u8, b_ip: []const u8) bool {
        const a_pool = findPoolLabel(cfg, a_ip) orelse "";
        const b_pool = findPoolLabel(cfg, b_ip) orelse "";
        return std.mem.lessThan(u8, a_pool, b_pool);
    }
};

fn renderLeaseTab(
    server: *AdminServer,
    state: *TuiState,
    table_ctx: *vaxis.widgets.Table.TableContext,
    win: vaxis.Window,
    fa: std.mem.Allocator,
) !void {
    // Use the caller-supplied frame arena (fa).  Do NOT create a local arena
    // here: Cell.char.grapheme stores a []const u8 into our strings, so they
    // must remain alive through the vx.render() call in the parent.
    const a = fa;

    const now = std.time.timestamp();
    const filter = state.filter_buf[0..state.filter_len];

    const leases = server.store.listLeases() catch return;
    defer server.store.allocator.free(leases);

    // Sort raw leases before formatting so numeric fields (expires timestamp)
    // compare correctly.
    if (state.sort_col != .none) {
        std.sort.pdq(state_mod.Lease, leases, LeaseSort{
            .col = state.sort_col,
            .dir = state.sort_dir,
            .cfg = server.cfg,
        }, LeaseSort.lessThan);
    }

    var rows = std.ArrayList(LeaseRow){};
    for (leases) |lease| {
        const is_conflict = std.mem.startsWith(u8, lease.mac, "conflict:");

        const pool = findPool(server.cfg, lease.ip);
        const pool_cidr = if (pool) |p|
            try std.fmt.allocPrint(a, "{s}/{d}", .{ p.subnet, p.prefix_len })
        else
            "?";
        const type_str: []const u8 = if (is_conflict) "conflict" else if (lease.reserved) "reserved" else "dynamic";
        const hostname_str: []const u8 = if (is_conflict) "" else lease.hostname orelse "";

        const expires_str = blk: {
            if (lease.reserved) break :blk try a.dupe(u8, "forever");
            const diff = lease.expires - now;
            if (diff <= 0) break :blk try a.dupe(u8, "expired");
            const h = @divTrunc(diff, 3600);
            const m = @divTrunc(@rem(diff, 3600), 60);
            break :blk try std.fmt.allocPrint(a, "{d}h{d:0>2}m", .{ h, m });
        };

        // Filter: skip rows that don't match any field (case-insensitive).
        if (filter.len > 0) {
            const match = containsIgnoreCase(lease.ip, filter) or
                containsIgnoreCase(lease.mac, filter) or
                containsIgnoreCase(hostname_str, filter) or
                containsIgnoreCase(type_str, filter) or
                containsIgnoreCase(pool_cidr, filter);
            if (!match) continue;
        }

        try rows.append(a, .{
            .ip = try a.dupe(u8, lease.ip),
            .mac = if (is_conflict) "" else try a.dupe(u8, lease.mac),
            .hostname = try a.dupe(u8, hostname_str),
            .type = type_str,
            .expires = expires_str,
            .pool = pool_cidr,
        });
    }

    // Follow the previously selected lease by MAC when data refreshes,
    // but only if the user didn't navigate since the last frame.
    const n_rows: u16 = if (rows.items.len > 0xFFFF) 0xFFFF else @intCast(rows.items.len);
    const user_navigated = (table_ctx.row != state.lease_prev_ctx_row);
    if (!user_navigated and state.sel_mac_len > 0 and n_rows > 0) {
        const prev_mac = state.sel_mac[0..state.sel_mac_len];
        for (rows.items, 0..) |row, ri| {
            if (std.mem.eql(u8, row.mac, prev_mac)) {
                table_ctx.row = @intCast(ri);
                break;
            }
        }
    }
    // Clamp.
    if (n_rows > 0 and table_ctx.row >= n_rows) table_ctx.row = n_rows - 1;
    if (n_rows == 0) table_ctx.row = 0;
    state.lease_prev_ctx_row = table_ctx.row;

    // Update selected-row state (used by yank mode and reservation form).
    if (rows.items.len > 0 and table_ctx.row < rows.items.len) {
        const sel = rows.items[table_ctx.row];
        const ip_len = @min(sel.ip.len, state.sel_ip.len);
        @memcpy(state.sel_ip[0..ip_len], sel.ip[0..ip_len]);
        state.sel_ip_len = ip_len;
        const mac_len = @min(sel.mac.len, state.sel_mac.len);
        @memcpy(state.sel_mac[0..mac_len], sel.mac[0..mac_len]);
        state.sel_mac_len = mac_len;
        const hn_len = @min(sel.hostname.len, state.sel_hostname.len);
        @memcpy(state.sel_hostname[0..hn_len], sel.hostname[0..hn_len]);
        state.sel_hostname_len = hn_len;
        state.sel_reserved = std.mem.eql(u8, sel.type, "reserved");
    }

    // Build column headers with sort indicator on the active column.
    var hdr_names: [LEASE_COL_NAMES.len][]const u8 = undefined;
    for (LEASE_COL_NAMES, 0..) |base, i| {
        if (state.sort_col != .none and @intFromEnum(state.sort_col) == i) {
            const arrow: []const u8 = if (state.sort_dir == .asc) " ^" else " v";
            hdr_names[i] = try std.fmt.allocPrint(a, "{s}{s}", .{ base, arrow });
        } else {
            hdr_names[i] = base;
        }
    }
    try drawLeaseTable(win, rows.items, table_ctx, &hdr_names, a);
}

fn findPool(cfg: *const config_mod.Config, ip_str: []const u8) ?*const config_mod.PoolConfig {
    const ip_bytes = config_mod.parseIpv4(ip_str) catch return null;
    const ip_int = std.mem.readInt(u32, &ip_bytes, .big);
    for (cfg.pools) |*pool| {
        const subnet_bytes = config_mod.parseIpv4(pool.subnet) catch continue;
        const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
        if ((ip_int & pool.subnet_mask) == (subnet_int & pool.subnet_mask)) return pool;
    }
    return null;
}

/// Returns the subnet string for sort/filter purposes.
fn findPoolLabel(cfg: *const config_mod.Config, ip_str: []const u8) ?[]const u8 {
    return if (findPool(cfg, ip_str)) |p| p.subnet else null;
}

// ---------------------------------------------------------------------------
// Stats tab
// ---------------------------------------------------------------------------

/// Map a virtual row to a display row given current scroll position.
/// Returns null if the row is scrolled out of view.
inline fn statsVr(vr: u16, scroll: u16, height: u16) ?u16 {
    if (vr < scroll) return null;
    const dr = vr - scroll;
    if (dr >= height) return null;
    return dr;
}

fn renderStatsTab(
    server: *AdminServer,
    state: *TuiState,
    win: vaxis.Window,
    fa: std.mem.Allocator,
) !void {
    const a = fa;

    // Dark background matching modals and settings tab.
    win.fill(.{ .char = .{ .grapheme = " ", .width = 1 }, .style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } } });

    const now = std.time.timestamp();
    const leases = server.store.listLeases() catch return;
    defer server.store.allocator.free(leases);

    const hdr_style: vaxis.Style = .{ .bold = true, .fg = .{ .rgb = .{ 255, 200, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const bg: vaxis.Color = .{ .rgb = .{ 20, 20, 30 } };
    const val_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 200, 200, 200 } }, .bg = bg };
    const bar_full: vaxis.Style = .{ .fg = .{ .rgb = .{ 64, 192, 64 } }, .bg = bg };
    const bar_warn: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 180, 0 } }, .bg = bg };
    const bar_crit: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 60, 60 } }, .bg = bg };

    // Compute total content height:
    //   1 (blank) + 1 (pool header) + 3 * n_pools (label + bar + blank) +
    //   1 (DHCP header) + 10 (DHCP counters) +
    //   1 (blank) + 1 (defense header) + 5 (defense counters) +
    //   1 (blank) + 1 (backend header) + 9 (backend counters) +
    //   1 (blank) + 1 (sync header) + sync_rows + 1 (trailing blank)
    const n_pools: u16 = @intCast(server.cfg.pools.len);
    const sync_rows: u16 = if (server.sync_mgr != null) 3 else 1; // peers + config sync + local config OR "not configured"
    const total_rows: u16 = 1 + 1 + 3 * n_pools + 1 + 10 + 1 + 1 + 5 + 1 + 1 + 9 + 1 + 1 + sync_rows + 1;

    // Clamp scroll so we never scroll past the last line of content.
    const max_scroll: u16 = if (total_rows > win.height) total_rows - win.height else 0;
    if (state.stats_scroll > max_scroll) state.stats_scroll = max_scroll;
    const scroll = state.stats_scroll;

    var vr: u16 = 0;

    vr += 1; // blank line above section header

    // ---- Pool stats ----
    if (statsVr(vr, scroll, win.height)) |dr|
        _ = win.print(&.{.{ .text = "  Pool Utilization", .style = hdr_style }}, .{ .col_offset = 0, .row_offset = dr, .wrap = .none });
    vr += 1;

    for (server.cfg.pools) |*pool| {
        const capacity = poolCapacity(pool);

        var active: u64 = 0;
        var reserved: u64 = 0;
        var expired: u64 = 0;
        for (leases) |lease| {
            if (!isIpInPool(lease.ip, pool)) continue;
            if (lease.reserved) {
                reserved += 1;
                if (lease.expires > now) active += 1;
            } else if (lease.expires > now) {
                active += 1;
            } else {
                expired += 1;
            }
        }
        const used = active + reserved;
        const available: u64 = if (capacity > used) capacity - used else 0;

        // Pool label line: "  subnet/prefix  .abbrev – .abbrev"
        const range_str = fmtAbbrevRange(a, pool) catch "?";
        const pool_label = try std.fmt.allocPrint(a, "  {s}/{d}  {s}", .{
            pool.subnet, pool.prefix_len, range_str,
        });
        if (statsVr(vr, scroll, win.height)) |dr|
            _ = win.print(&.{.{ .text = pool_label, .style = val_style }}, .{ .col_offset = 0, .row_offset = dr, .wrap = .none });
        vr += 1;

        // Bar chart: use up to 40 columns
        const BAR_W: usize = 40;
        const bar_fill: usize = if (capacity > 0) @intCast(@min((used * BAR_W + capacity - 1) / capacity, BAR_W)) else 0;
        const pct: u64 = if (capacity > 0) (used * 100) / capacity else 0;

        const bar_style = if (pct >= 90) bar_crit else if (pct >= 75) bar_warn else bar_full;

        var bar_buf: [48]u8 = undefined;
        @memset(bar_buf[0..bar_fill], '#');
        @memset(bar_buf[bar_fill..BAR_W], '-');

        const bar_str = try std.fmt.allocPrint(a, "  [{s}] {d:>3}%  {d}/{d} used  {d} avail  {d} exp", .{
            bar_buf[0..BAR_W],
            pct,
            used,
            capacity,
            available,
            expired,
        });
        if (statsVr(vr, scroll, win.height)) |dr|
            _ = win.print(&.{.{ .text = bar_str, .style = bar_style }}, .{ .col_offset = 0, .row_offset = dr, .wrap = .none });
        vr += 2; // bar row + blank row
    }

    // ---- DHCP counters ----
    if (statsVr(vr, scroll, win.height)) |dr|
        _ = win.print(&.{.{ .text = "  DHCP Counters", .style = hdr_style }}, .{ .col_offset = 0, .row_offset = dr, .wrap = .none });
    vr += 1;

    const ctr = server.counters;
    const counter_lines = [_]struct { label: []const u8, val: u64 }{
        .{ .label = "DISCOVER  ", .val = ctr.discover.load(.monotonic) },
        .{ .label = "OFFER     ", .val = ctr.offer.load(.monotonic) },
        .{ .label = "REQUEST   ", .val = ctr.request.load(.monotonic) },
        .{ .label = "ACK       ", .val = ctr.ack.load(.monotonic) },
        .{ .label = "NAK       ", .val = ctr.nak.load(.monotonic) },
        .{ .label = "RELEASE   ", .val = ctr.release.load(.monotonic) },
        .{ .label = "DECLINE   ", .val = ctr.decline.load(.monotonic) },
        .{ .label = "INFORM    ", .val = ctr.inform.load(.monotonic) },
        .{ .label = "FORCERENEW", .val = ctr.forcerenew.load(.monotonic) },
        .{ .label = "LEASEQUERY", .val = ctr.leasequery.load(.monotonic) },
    };

    for (counter_lines) |cl| {
        if (statsVr(vr, scroll, win.height)) |dr| {
            const line = try std.fmt.allocPrint(a, "    {s}  {d}", .{ cl.label, cl.val });
            _ = win.print(&.{.{ .text = line, .style = val_style }}, .{ .col_offset = 0, .row_offset = dr, .wrap = .none });
        }
        vr += 1;
    }

    // ---- Defense counters ----
    vr += 1; // blank separator
    if (statsVr(vr, scroll, win.height)) |dr|
        _ = win.print(&.{.{ .text = "  Defense Counters", .style = hdr_style }}, .{ .col_offset = 0, .row_offset = dr, .wrap = .none });
    vr += 1;

    const defense_lines = [_]struct { label: []const u8, val: u64 }{
        .{ .label = "PROBE CONFLICT  ", .val = ctr.probe_conflict.load(.monotonic) },
        .{ .label = "DECLINE QUARANT ", .val = ctr.decline_ip_quarantined.load(.monotonic) },
        .{ .label = "MAC BLOCKED     ", .val = ctr.decline_mac_blocked.load(.monotonic) },
        .{ .label = "GLOBAL LIMITED  ", .val = ctr.decline_global_limited.load(.monotonic) },
        .{ .label = "ALLOC REFUSED   ", .val = ctr.decline_refused.load(.monotonic) },
    };

    for (defense_lines) |cl| {
        if (statsVr(vr, scroll, win.height)) |dr| {
            const line = try std.fmt.allocPrint(a, "    {s}  {d}", .{ cl.label, cl.val });
            _ = win.print(&.{.{ .text = line, .style = val_style }}, .{ .col_offset = 0, .row_offset = dr, .wrap = .none });
        }
        vr += 1;
    }

    // ---- Backend counters ----
    vr += 1; // blank separator
    if (statsVr(vr, scroll, win.height)) |dr|
        _ = win.print(&.{.{ .text = "  Backend Counters", .style = hdr_style }}, .{ .col_offset = 0, .row_offset = dr, .wrap = .none });
    vr += 1;

    const backend_lines = [_]struct { label: []const u8, val: u64 }{
        .{ .label = "SSH ATTEMPTS    ", .val = ctr.ssh_attempts.load(.monotonic) },
        .{ .label = "SSH LOGINS      ", .val = ctr.ssh_logins.load(.monotonic) },
        .{ .label = "SSH FAILURES    ", .val = ctr.ssh_failures.load(.monotonic) },
        .{ .label = "SYNC FULL       ", .val = if (server.sync_mgr) |s| s.sync_full_events.load(.monotonic) else 0 },
        .{ .label = "SYNC LEASE      ", .val = if (server.sync_mgr) |s| s.sync_lease_events.load(.monotonic) else 0 },
        .{ .label = "CONFIG PUSH     ", .val = if (server.sync_mgr) |s| s.config_push_events.load(.monotonic) else 0 },
        .{ .label = "CONFIG RECV     ", .val = if (server.sync_mgr) |s| s.config_recv_events.load(.monotonic) else 0 },
        .{ .label = "RESV PUSH       ", .val = if (server.sync_mgr) |s| s.reservation_push_events.load(.monotonic) else 0 },
        .{ .label = "RESV RECV       ", .val = if (server.sync_mgr) |s| s.reservation_recv_events.load(.monotonic) else 0 },
    };

    for (backend_lines) |cl| {
        if (statsVr(vr, scroll, win.height)) |dr| {
            const line = try std.fmt.allocPrint(a, "    {s}  {d}", .{ cl.label, cl.val });
            _ = win.print(&.{.{ .text = line, .style = val_style }}, .{ .col_offset = 0, .row_offset = dr, .wrap = .none });
        }
        vr += 1;
    }

    // ---- Sync Status ----
    vr += 1; // blank separator
    if (statsVr(vr, scroll, win.height)) |dr|
        _ = win.print(&.{.{ .text = "  Sync Status", .style = hdr_style }}, .{ .col_offset = 0, .row_offset = dr, .wrap = .none });
    vr += 1;

    if (server.sync_mgr) |sm| {
        const pc = sm.peerCount();
        const peers_line = try std.fmt.allocPrint(a, "    Peers           {d} authenticated, {d} config-capable", .{ pc.authenticated, pc.config_capable });
        if (statsVr(vr, scroll, win.height)) |dr|
            _ = win.print(&.{.{ .text = peers_line, .style = val_style }}, .{ .col_offset = 0, .row_offset = dr, .wrap = .none });
        vr += 1;

        const cfg_sync_on = if (server.cfg.sync) |s| s.config_sync else false;
        const config_sync_line = try std.fmt.allocPrint(a, "    Config Sync     {s}", .{
            if (cfg_sync_on) "enabled" else "disabled",
        });
        if (statsVr(vr, scroll, win.height)) |dr|
            _ = win.print(&.{.{ .text = config_sync_line, .style = val_style }}, .{ .col_offset = 0, .row_offset = dr, .wrap = .none });
        vr += 1;

        const local_label = if (server.cfg.config_writable and cfg_sync_on)
            "    Local Config    writable + sync enabled"
        else if (server.cfg.config_writable)
            "    Local Config    writable (sync disabled)"
        else
            "    Local Config    read-only";
        if (statsVr(vr, scroll, win.height)) |dr|
            _ = win.print(&.{.{ .text = local_label, .style = val_style }}, .{ .col_offset = 0, .row_offset = dr, .wrap = .none });
        vr += 1;
    } else {
        if (statsVr(vr, scroll, win.height)) |dr|
            _ = win.print(&.{.{ .text = "    Not configured", .style = val_style }}, .{ .col_offset = 0, .row_offset = dr, .wrap = .none });
        vr += 1;
    }

    // trailing blank line (vr not used after this point)
    comptime {} // suppress unused-variable lint; vr is intentionally incremented for accounting
    _ = &vr;
}

// ---------------------------------------------------------------------------
// Reservation form overlay
// ---------------------------------------------------------------------------

/// Draw a simple single-line border box starting at (row, col) in `win`.
/// Box is `w` columns wide, `h` rows tall.
fn drawBox(win: vaxis.Window, row: u16, col: u16, w: u16, h: u16, style: vaxis.Style) void {
    if (w < 2 or h < 2) return;

    // Draw character-by-character to avoid UTF-8 string assembly issues.
    // Corners.
    _ = win.print(&.{.{ .text = "\xe2\x94\x8c", .style = style }}, .{ .col_offset = col, .row_offset = row, .wrap = .none }); // ┌
    _ = win.print(&.{.{ .text = "\xe2\x94\x90", .style = style }}, .{ .col_offset = col + w - 1, .row_offset = row, .wrap = .none }); // ┐
    _ = win.print(&.{.{ .text = "\xe2\x94\x94", .style = style }}, .{ .col_offset = col, .row_offset = row + h - 1, .wrap = .none }); // └
    _ = win.print(&.{.{ .text = "\xe2\x94\x98", .style = style }}, .{ .col_offset = col + w - 1, .row_offset = row + h - 1, .wrap = .none }); // ┘

    // Top and bottom horizontal edges.
    var cx: u16 = 1;
    while (cx < w - 1) : (cx += 1) {
        _ = win.print(&.{.{ .text = "\xe2\x94\x80", .style = style }}, .{ .col_offset = col + cx, .row_offset = row, .wrap = .none }); // ─
        _ = win.print(&.{.{ .text = "\xe2\x94\x80", .style = style }}, .{ .col_offset = col + cx, .row_offset = row + h - 1, .wrap = .none }); // ─
    }

    // Left and right vertical edges.
    var r: u16 = 1;
    while (r < h - 1) : (r += 1) {
        _ = win.print(&.{.{ .text = "\xe2\x94\x82", .style = style }}, .{ .col_offset = col, .row_offset = row + r, .wrap = .none }); // │
        _ = win.print(&.{.{ .text = "\xe2\x94\x82", .style = style }}, .{ .col_offset = col + w - 1, .row_offset = row + r, .wrap = .none }); // │
    }
}

/// Render the reservation add/edit form as a centered overlay.
fn renderReservationForm(state: *TuiState, win: vaxis.Window, fa: std.mem.Allocator) !void {
    const form = &state.form;
    // Dynamic height: 3 fixed fields + blank + [+]add + N options + saved/hints + borders
    const opt_rows: u16 = @intCast(form.option_count);
    const BOX_W: u16 = 58;
    const BOX_H: u16 = @min(win.height -| 2, 11 + opt_rows); // border+title+blank + 3 fields + blank + [+] + N opts + saved + hints + border
    if (win.width < BOX_W or win.height < 10) return;

    const col: u16 = (win.width - BOX_W) / 2;
    const row: u16 = (win.height -| BOX_H) / 2;

    const bg_color: vaxis.Color = .{ .rgb = .{ 20, 20, 30 } };
    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 160, 255 } }, .bg = bg_color };
    const title_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 200, 80 } }, .bg = bg_color, .bold = true };
    const label_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 180, 180 } }, .bg = bg_color };
    const field_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 220, 220, 220 } }, .bg = .{ .rgb = .{ 40, 40, 55 } } };
    const active_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 255, 255 } }, .bg = .{ .rgb = .{ 50, 80, 140 } } };
    const cursor_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 0, 0, 0 } }, .bg = .{ .rgb = .{ 100, 180, 255 } } };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 120, 120, 120 } }, .bg = bg_color };
    const err_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 80, 80 } }, .bg = bg_color, .bold = true };
    const close_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 80, 80 } }, .bg = bg_color, .bold = true };
    const opt_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 180, 200 } }, .bg = .{ .rgb = .{ 30, 30, 42 } } };

    // Fill + border.
    var r: u16 = 0;
    while (r < BOX_H) : (r += 1) {
        const fill = try fa.alloc(u8, BOX_W);
        @memset(fill, ' ');
        _ = win.print(&.{.{ .text = fill, .style = .{ .bg = bg_color } }}, .{ .col_offset = col, .row_offset = row + r, .wrap = .none });
    }
    drawBox(win, row, col, BOX_W, BOX_H, border_style);

    const title = if (form.isNew()) "  New Reservation" else "  Edit Reservation";
    _ = win.print(&.{.{ .text = title, .style = title_style }}, .{ .col_offset = col + 1, .row_offset = row + 1, .wrap = .none });
    _ = win.print(&.{.{ .text = "[X]", .style = close_style }}, .{ .col_offset = col + BOX_W -| 5, .row_offset = row, .wrap = .none });

    const LABEL_W: u16 = 17;
    const FIELD_W: u16 = BOX_W -| LABEL_W -| 4;

    // Row 3: IP, Row 4: MAC, Row 5: Hostname
    const text_fields = [3]struct { label: []const u8, buf: []const u8, len: usize, idx: u8 }{
        .{ .label = "  IP Address   ", .buf = &form.ip_buf, .len = form.ip_len, .idx = 0 },
        .{ .label = "  MAC Address  ", .buf = &form.mac_buf, .len = form.mac_len, .idx = 1 },
        .{ .label = "  Hostname     ", .buf = &form.hostname_buf, .len = form.hostname_len, .idx = 2 },
    };

    for (text_fields, 0..) |f, fi| {
        const fr: u16 = row + 3 + @as(u16, @intCast(fi));
        _ = win.print(&.{.{ .text = f.label, .style = label_style }}, .{ .col_offset = col + 1, .row_offset = fr, .wrap = .none });
        const is_active = form.active_field == f.idx;
        const fs = if (is_active) active_style else field_style;
        const value = f.buf[0..f.len];
        const field_x = col + 1 + LABEL_W;
        const val_len = @as(u16, @intCast(@min(value.len, FIELD_W)));
        const pad = FIELD_W -| val_len;
        const padded = try fa.alloc(u8, pad);
        @memset(padded, ' ');
        _ = win.print(&.{.{ .text = value[0..val_len], .style = fs }}, .{ .col_offset = field_x, .row_offset = fr, .wrap = .none });
        _ = win.print(&.{.{ .text = padded, .style = fs }}, .{ .col_offset = field_x + val_len, .row_offset = fr, .wrap = .none });
        if (is_active) {
            const cur_pos = @min(form.cursor, f.len);
            const ch: []const u8 = if (cur_pos < f.len) f.buf[cur_pos..][0..1] else " ";
            _ = win.print(&.{.{ .text = ch, .style = cursor_style }}, .{ .col_offset = field_x + @as(u16, @intCast(cur_pos)), .row_offset = fr, .wrap = .none });
        }
    }

    // Row 6: blank line
    // Row 7: DHCP Options [+] add button
    const add_row: u16 = row + 7;
    const add_active = form.active_field == 3;
    const add_fs = if (add_active) active_style else field_style;
    _ = win.print(&.{.{ .text = "  DHCP Options ", .style = label_style }}, .{ .col_offset = col + 1, .row_offset = add_row, .wrap = .none });
    const add_text = "[+] Add ";
    _ = win.print(&.{.{ .text = add_text, .style = add_fs }}, .{ .col_offset = col + 1 + LABEL_W, .row_offset = add_row, .wrap = .none });

    // Rows 8+: existing options
    var oi: usize = 0;
    while (oi < form.option_count) : (oi += 1) {
        const or_row = add_row + 1 + @as(u16, @intCast(oi));
        if (or_row >= row + BOX_H - 3) break; // leave room for saved + hints + border
        const o = &form.options[oi];
        const is_sel = form.active_field == @as(u8, @intCast(4 + oi));
        const os = if (is_sel) active_style else opt_style;
        const code = o.code_buf[0..o.code_len];
        const val = o.value_buf[0..o.value_len];
        // Label on left: "  Option NNN"
        const opt_label = std.fmt.allocPrint(fa, "  Option {s:>3}", .{if (code.len > 0) code else "?"}) catch "  Option   ?";
        _ = win.print(&.{.{ .text = opt_label, .style = label_style }}, .{ .col_offset = col + 1, .row_offset = or_row, .wrap = .none });
        // Value on right, aligned with field boxes.
        const val_text = if (val.len > 0) val else "";
        const val_trunc = val_text[0..@min(val_text.len, FIELD_W)];
        const val_pad = FIELD_W -| @as(u16, @intCast(val_trunc.len));
        const val_padded = try fa.alloc(u8, val_pad);
        @memset(val_padded, ' ');
        _ = win.print(&.{.{ .text = val_trunc, .style = os }}, .{ .col_offset = col + 1 + LABEL_W, .row_offset = or_row, .wrap = .none });
        _ = win.print(&.{.{ .text = val_padded, .style = os }}, .{ .col_offset = col + 1 + LABEL_W + @as(u16, @intCast(val_trunc.len)), .row_offset = or_row, .wrap = .none });
    }

    // Saved/error.
    if (form.err_len > 0) {
        _ = win.print(&.{.{ .text = form.err_buf[0..form.err_len], .style = err_style }}, .{ .col_offset = col + 2, .row_offset = row + BOX_H - 3, .wrap = .none });
    } else if (form.saved) {
        const saved_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 80, 220, 80 } }, .bg = bg_color, .bold = true };
        _ = win.print(&.{.{ .text = "Saved!", .style = saved_style }}, .{ .col_offset = col + BOX_W -| 9, .row_offset = row + BOX_H - 3, .wrap = .none });
    }

    // Hints.
    const hint = if (form.active_field >= 4) "  Enter:edit  d:delete  Esc:close" else "  Tab:next  Enter:save  Esc:close";
    _ = win.print(&.{.{ .text = hint, .style = hint_style }}, .{ .col_offset = col + 1, .row_offset = row + BOX_H - 2, .wrap = .none });
}

/// Normalize and validate reservation form fields. Returns error message or null.
fn validateReservationForm(form: *ReservationForm) ?[]const u8 {
    // IP: required, must be valid IPv4.
    if (form.ip_len == 0) return "IP address is required";
    _ = config_mod.parseIpv4(form.ip_buf[0..form.ip_len]) catch return "Invalid IP address";

    // MAC: required, normalize dashes to colons and lowercase.
    if (form.mac_len == 0) return "MAC address is required";
    for (form.mac_buf[0..form.mac_len]) |*ch| {
        if (ch.* == '-') ch.* = ':';
        if (ch.* >= 'A' and ch.* <= 'F') ch.* = ch.* - 'A' + 'a';
    }
    // Validate format: xx:xx:xx:xx:xx:xx (17 chars, hex pairs with colons).
    const mac = form.mac_buf[0..form.mac_len];
    if (mac.len != 17) return "MAC must be xx:xx:xx:xx:xx:xx";
    for (mac, 0..) |ch, i| {
        if (i % 3 == 2) {
            if (ch != ':') return "MAC must be xx:xx:xx:xx:xx:xx";
        } else {
            if (!((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f')))
                return "MAC must be hex (0-9, a-f)";
        }
    }

    // Hostname: optional, auto-lowercase, alphanumeric + dashes.
    if (form.hostname_len > 0) {
        for (form.hostname_buf[0..form.hostname_len]) |*ch| {
            if (ch.* >= 'A' and ch.* <= 'Z') ch.* = ch.* - 'A' + 'a';
        }
        const hn = form.hostname_buf[0..form.hostname_len];
        if (!((hn[0] >= 'a' and hn[0] <= 'z') or (hn[0] >= '0' and hn[0] <= '9')))
            return "Hostname must start with alphanumeric";
        for (hn) |ch| {
            if (!((ch >= 'a' and ch <= 'z') or (ch >= '0' and ch <= '9') or ch == '-'))
                return "Hostname: only a-z, 0-9, dashes";
        }
    }

    return null;
}

/// Save the form: update StateStore + config.yaml. Returns an error message on failure.
fn saveReservation(server: *AdminServer, form: *ReservationForm) ?[]const u8 {
    if (validateReservationForm(form)) |err| return err;

    const ip = form.ip_buf[0..form.ip_len];
    const mac = form.mac_buf[0..form.mac_len];
    const hostname_raw = form.hostname_buf[0..form.hostname_len];
    const hostname: ?[]const u8 = if (hostname_raw.len > 0) hostname_raw else null;

    // If editing (has orig_mac) and MAC changed, remove old entry first.
    const orig_mac = form.orig_mac[0..form.orig_mac_len];
    if (orig_mac.len > 0 and !std.mem.eql(u8, orig_mac, mac)) {
        server.store.removeLease(orig_mac);
        if (config_write.findPoolForIp(server.cfg, ip)) |pool| {
            _ = config_write.removeReservation(server.allocator, pool, orig_mac);
            // Notify sync peers that the old MAC reservation was deleted.
            if (server.sync_mgr) |s| s.notifyReservationDelete(pool, orig_mac);
        }
    }

    // Build dhcp_options map from form entries.
    var opts: ?std.StringHashMap([]const u8) = null;
    if (form.option_count > 0) {
        var map = std.StringHashMap([]const u8).init(server.allocator);
        for (form.options[0..form.option_count]) |opt| {
            if (opt.code_len == 0) continue;
            const k = server.allocator.dupe(u8, opt.code_buf[0..opt.code_len]) catch return "OutOfMemory";
            const v = server.allocator.dupe(u8, opt.value_buf[0..opt.value_len]) catch {
                server.allocator.free(k);
                return "OutOfMemory";
            };
            map.put(k, v) catch {
                server.allocator.free(k);
                server.allocator.free(v);
                return "OutOfMemory";
            };
        }
        opts = map;
    }
    defer if (opts) |*m| {
        var it = m.iterator();
        while (it.next()) |entry| {
            server.allocator.free(entry.key_ptr.*);
            server.allocator.free(entry.value_ptr.*);
        }
        m.deinit();
    };

    // Update StateStore.
    server.store.addReservation(mac, ip, hostname, null) catch |err| {
        return @errorName(err);
    };

    // Update config.yaml.
    if (config_write.findPoolForIp(server.cfg, ip)) |pool| {
        _ = config_write.upsertReservation(server.allocator, pool, mac, ip, hostname, null, opts) catch |err| {
            return @errorName(err);
        };
        // Set config_modified timestamp for sync (before writeConfig so it gets persisted).
        for (pool.reservations) |*r| {
            if (std.mem.eql(u8, r.mac, mac)) {
                r.config_modified = std.time.timestamp();
                break;
            }
        }
        config_write.writeConfig(server.allocator, server.cfg, server.cfg_path) catch |err| {
            return @errorName(err);
        };
        // Notify sync peers of reservation change.
        if (server.sync_mgr) |s| {
            for (pool.reservations) |*r| {
                if (std.mem.eql(u8, r.mac, mac)) {
                    s.notifyReservationUpdate(pool, r);
                    break;
                }
            }
        }
    } else {
        return "IP not in any configured pool";
    }

    // Send FORCERENEW so the client picks up updated reservation settings.
    if (server.dhcp_server) |ds| {
        if (config_mod.parseIpv4(ip)) |ip_bytes| {
            ds.sendForceRenew(ip_bytes);
        } else |_| {}
    }

    return null;
}

fn handleFormKey(server: *AdminServer, state: *TuiState, key: vaxis.Key) void {
    var form = &state.form;
    form.err_len = 0; // clear error/saved on any keypress
    form.saved = false;

    if (key.matches(vaxis.Key.escape, .{})) {
        state.mode = .normal;
        return;
    }

    if (key.matches(vaxis.Key.enter, .{})) {
        // Field 3 = [+] Add new DHCP option.
        if (form.active_field == 3) {
            form.opt_edit_code_len = 0;
            form.opt_edit_value_len = 0;
            form.opt_edit_field = 0;
            form.opt_edit_cursor = 0;
            form.opt_edit_index = null; // adding
            state.mode = .res_option_edit;
            return;
        }
        // Field 4+ = edit existing DHCP option.
        if (form.active_field >= 4) {
            const oi = form.active_field - 4;
            if (oi < form.option_count) {
                const o = &form.options[oi];
                @memcpy(form.opt_edit_code[0..o.code_len], o.code_buf[0..o.code_len]);
                form.opt_edit_code_len = o.code_len;
                @memcpy(form.opt_edit_value[0..o.value_len], o.value_buf[0..o.value_len]);
                form.opt_edit_value_len = o.value_len;
                form.opt_edit_field = 0;
                form.opt_edit_cursor = o.code_len;
                form.opt_edit_index = oi;
                state.mode = .res_option_edit;
            }
            return;
        }
        // Fields 0-2: save reservation.
        if (server.cfg.admin_ssh.read_only) {
            const msg = "read-only mode — changes not permitted";
            form.err_len = @min(msg.len, form.err_buf.len);
            @memcpy(form.err_buf[0..form.err_len], msg[0..form.err_len]);
            return;
        }
        if (saveReservation(server, form)) |err_msg| {
            form.err_len = @min(err_msg.len, form.err_buf.len);
            @memcpy(form.err_buf[0..form.err_len], err_msg[0..form.err_len]);
            return;
        }
        form.saved = true;
        return;
    }

    // 'd' deletes selected DHCP option (field 4+).
    if (key.matches('d', .{}) and form.active_field >= 4) {
        const oi = form.active_field - 4;
        if (oi < form.option_count) {
            var i: usize = oi;
            while (i + 1 < form.option_count) : (i += 1) {
                form.options[i] = form.options[i + 1];
            }
            form.option_count -= 1;
            if (form.active_field > 3 and form.active_field >= form.totalFields()) {
                form.active_field -= 1;
            }
        }
        return;
    }

    // Field navigation: wraps through 0..totalFields()-1.
    const total = form.totalFields();
    if (key.matches(vaxis.Key.tab, .{}) or key.matches(vaxis.Key.down, .{})) {
        form.active_field = if (form.active_field + 1 >= total) 0 else form.active_field + 1;
        form.cursor = form.activeLen();
        return;
    }
    if (key.matches(vaxis.Key.tab, .{ .shift = true }) or key.matches(vaxis.Key.up, .{})) {
        form.active_field = if (form.active_field == 0) total - 1 else form.active_field - 1;
        form.cursor = form.activeLen();
        return;
    }

    // Fields 3+ are not text fields.
    if (form.active_field >= 3) return;

    // Cursor movement.
    if (key.matches(vaxis.Key.left, .{})) {
        if (form.cursor > 0) form.cursor -= 1;
        return;
    }
    if (key.matches(vaxis.Key.right, .{})) {
        if (form.cursor < form.activeLen()) form.cursor += 1;
        return;
    }
    if (key.matches(vaxis.Key.home, .{})) {
        form.cursor = 0;
        return;
    }
    if (key.matches(vaxis.Key.end, .{})) {
        form.cursor = form.activeLen();
        return;
    }

    // Text editing at cursor position.
    const fb = resFormFieldBuf(form) orelse return;
    if (key.matches(vaxis.Key.backspace, .{})) {
        if (form.cursor > 0 and fb.len.* > 0) {
            const pos = form.cursor;
            if (pos < fb.len.*) std.mem.copyForwards(u8, fb.buf[pos - 1 ..], fb.buf[pos..fb.len.*]);
            fb.len.* -= 1;
            form.cursor -= 1;
        }
    } else if (key.matches(vaxis.Key.delete, .{})) {
        if (form.cursor < fb.len.*) {
            std.mem.copyForwards(u8, fb.buf[form.cursor..], fb.buf[form.cursor + 1 .. fb.len.*]);
            fb.len.* -= 1;
        }
    } else if (key.codepoint >= 0x20 and key.codepoint <= 0x7E) {
        // Filter allowed characters based on reservation field type.
        const ch: u8 = @intCast(key.codepoint);
        const allowed = switch (form.active_field) {
            0 => (ch >= '0' and ch <= '9') or ch == '.', // IP
            1 => (ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f') or (ch >= 'A' and ch <= 'F') or ch == ':' or ch == '-', // MAC
            2 => (ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '-', // Hostname
            else => true,
        };
        if (!allowed) return;
        if (fb.len.* < fb.buf.len - 1) {
            const pos = form.cursor;
            if (pos < fb.len.*) std.mem.copyBackwards(u8, fb.buf[pos + 1 ..], fb.buf[pos..fb.len.*]);
            fb.buf[pos] = @intCast(key.codepoint);
            fb.len.* += 1;
            form.cursor += 1;
        }
    }
}

fn resFormFieldBuf(form: *ReservationForm) ?struct { buf: []u8, len: *usize } {
    return switch (form.active_field) {
        0 => .{ .buf = &form.ip_buf, .len = &form.ip_len },
        1 => .{ .buf = &form.mac_buf, .len = &form.mac_len },
        2 => .{ .buf = &form.hostname_buf, .len = &form.hostname_len },
        else => null,
    };
}

fn renderDeleteConfirm(state: *TuiState, win: vaxis.Window) void {
    const BOX_W: u16 = 52;
    const BOX_H: u16 = 5;
    if (win.width < BOX_W or win.height < BOX_H) return;

    const col: u16 = (win.width - BOX_W) / 2;
    const row: u16 = (win.height -| BOX_H) / 2;

    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 80, 80 } }, .bg = .{ .rgb = .{ 30, 10, 10 } } };
    const text_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 220, 220, 220 } }, .bg = .{ .rgb = .{ 30, 10, 10 } } };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 150, 150, 150 } }, .bg = .{ .rgb = .{ 30, 10, 10 } } };

    // Fill background
    var r: u16 = 0;
    while (r < BOX_H) : (r += 1) {
        var fill_buf: [52]u8 = [_]u8{' '} ** 52;
        _ = win.print(&.{.{ .text = &fill_buf, .style = .{ .bg = .{ .rgb = .{ 30, 10, 10 } } } }}, .{ .col_offset = col, .row_offset = row + r, .wrap = .none });
    }
    drawBox(win, row, col, BOX_W, BOX_H, border_style);
    const close_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 80, 80 } }, .bg = .{ .rgb = .{ 30, 10, 10 } }, .bold = true };
    _ = win.print(&.{.{ .text = "[X]", .style = close_style }}, .{ .col_offset = col + BOX_W -| 5, .row_offset = row, .wrap = .none });

    const ip = state.del_ip[0..state.del_ip_len];
    var prompt_buf: [60]u8 = undefined;
    const prompt = if (state.del_is_reservation)
        std.fmt.bufPrint(&prompt_buf, "  Delete reservation for {s}? [y/N]", .{ip}) catch "  Delete reservation? [y/N]"
    else
        std.fmt.bufPrint(&prompt_buf, "  Release lease {s}? [y/N]", .{ip}) catch "  Release lease? [y/N]";
    _ = win.print(&.{.{ .text = prompt, .style = text_style }}, .{ .col_offset = col + 1, .row_offset = row + 1, .wrap = .none });
    _ = win.print(&.{.{ .text = "  y = confirm   Esc / any other key = cancel", .style = hint_style }}, .{ .col_offset = col + 1, .row_offset = row + 3, .wrap = .none });
}

fn handleDeleteConfirmKey(server: *AdminServer, state: *TuiState, key: vaxis.Key) void {
    if (key.matches('y', .{})) {
        const mac = state.del_mac[0..state.del_mac_len];
        const ip = state.del_ip[0..state.del_ip_len];
        // Send FORCERENEW before removing the lease so the client re-initiates.
        if (server.dhcp_server) |ds| {
            if (config_mod.parseIpv4(ip)) |ip_bytes| {
                ds.sendForceRenew(ip_bytes);
            } else |_| {}
        }
        server.store.forceRemoveLease(mac);
        if (state.del_is_reservation) {
            // Reservation: also remove from config and persist.
            if (config_write.findPoolForIp(server.cfg, ip)) |pool| {
                _ = config_write.removeReservation(server.allocator, pool, mac);
                config_write.writeConfig(server.allocator, server.cfg, server.cfg_path) catch |err| {
                    log.warn("delete reservation: failed to write config: {s}", .{@errorName(err)});
                };
                // Notify sync peers of reservation deletion.
                if (server.sync_mgr) |s| s.notifyReservationDelete(pool, mac);
            }
        } else {
            // Dynamic lease: notify sync peers of deletion.
            if (server.sync_mgr) |s| s.notifyLeaseDelete(mac);
        }
    }
    state.mode = .normal;
}

// ---------------------------------------------------------------------------
// Pool helpers (duplicated from metrics.zig to avoid circular imports)
// ---------------------------------------------------------------------------

fn poolCapacity(pool: *const config_mod.PoolConfig) u64 {
    const start = if (pool.pool_start.len > 0) config_mod.parseIpv4(pool.pool_start) catch null else null;
    const end = if (pool.pool_end.len > 0) config_mod.parseIpv4(pool.pool_end) catch null else null;
    const subnet_bytes = config_mod.parseIpv4(pool.subnet) catch return 0;
    const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
    const broadcast_int = subnet_int | ~pool.subnet_mask;
    const start_int: u32 = if (start) |s| std.mem.readInt(u32, &s, .big) else subnet_int + 1;
    const end_int: u32 = if (end) |e| std.mem.readInt(u32, &e, .big) else broadcast_int - 1;
    if (end_int < start_int) return 0;
    return end_int - start_int + 1;
}

fn isIpInPool(ip_str: []const u8, pool: *const config_mod.PoolConfig) bool {
    const ip_bytes = config_mod.parseIpv4(ip_str) catch return false;
    const ip_int = std.mem.readInt(u32, &ip_bytes, .big);
    const subnet_bytes = config_mod.parseIpv4(pool.subnet) catch return false;
    const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
    return (ip_int & pool.subnet_mask) == (subnet_int & pool.subnet_mask);
}

// ---------------------------------------------------------------------------
// Pool config tab: list, detail view, edit form, diff/confirm, save logic
// ---------------------------------------------------------------------------

/// Field metadata for the pool form: label + flags.  Index order matches
/// poolFormFieldVal / poolFormFieldBuf switch cases.  Section headers and
/// visual ordering are controlled by `pool_layout` below.
const PoolFieldMeta = struct {
    label: []const u8,
    sensitive: bool = false, // hidden in read-only detail view
};

const pool_field_meta = [_]PoolFieldMeta{
    .{ .label = "Subnet" }, // 0
    .{ .label = "Router" }, // 1
    .{ .label = "Pool Start" }, // 2
    .{ .label = "Pool End" }, // 3
    .{ .label = "Lease Time" }, // 4  (was 5)
    .{ .label = "MTU" }, // 5  (was 7)
    .{ .label = "Domain Name" }, // 6  (was 4)
    .{ .label = "Time Offset" }, // 7  (was 6)
    .{ .label = "TFTP Boot File" }, // 8
    .{ .label = "HTTP Boot URL" }, // 9
    .{ .label = "Enable" }, // 10
    .{ .label = "Server" }, // 11
    .{ .label = "Zone" }, // 12
    .{ .label = "Key Name", .sensitive = true }, // 13
    .{ .label = "Key File", .sensitive = true }, // 14
};

/// A single item in the unified pool form layout.  The layout array drives
/// both rendering and active-field numbering so that Tab/arrow navigation
/// follows the visual order exactly.
const PoolLayoutKind = enum { section, field, inline_section };
const InlineTarget = enum { domain_search, dns, wins, ntp, log, tftp, routes, options, mac_classes };

const PoolLayoutItem = struct {
    kind: PoolLayoutKind,
    label: []const u8 = "",
    field_idx: ?u8 = null,
    inline_target: ?InlineTarget = null,
};

const pool_layout = [_]PoolLayoutItem{
    .{ .kind = .section, .label = "Network" },
    .{ .kind = .field, .field_idx = 0 }, // Subnet
    .{ .kind = .field, .field_idx = 1 }, // Router
    .{ .kind = .field, .field_idx = 2 }, // Pool Start
    .{ .kind = .field, .field_idx = 3 }, // Pool End
    .{ .kind = .field, .field_idx = 4 }, // Lease Time
    .{ .kind = .field, .field_idx = 5 }, // MTU
    .{ .kind = .section, .label = "Naming" },
    .{ .kind = .field, .field_idx = 6 }, // Domain Name
    .{ .kind = .inline_section, .label = "Search Domains", .inline_target = .domain_search },
    .{ .kind = .inline_section, .label = "DNS Servers", .inline_target = .dns },
    .{ .kind = .inline_section, .label = "WINS Servers", .inline_target = .wins },
    .{ .kind = .section, .label = "Time" },
    .{ .kind = .field, .field_idx = 7 }, // Time Offset
    .{ .kind = .inline_section, .label = "NTP Servers", .inline_target = .ntp },
    .{ .kind = .section, .label = "Logs" },
    .{ .kind = .inline_section, .label = "Log Servers", .inline_target = .log },
    .{ .kind = .section, .label = "Boot" },
    .{ .kind = .field, .field_idx = 9 }, // HTTP Boot URL
    .{ .kind = .field, .field_idx = 8 }, // TFTP Boot File
    .{ .kind = .inline_section, .label = "TFTP Servers", .inline_target = .tftp },
    .{ .kind = .section, .label = "DNS Updates" },
    .{ .kind = .field, .field_idx = 10 }, // DNS Upd Enable
    .{ .kind = .field, .field_idx = 11 }, // DNS Upd Server
    .{ .kind = .field, .field_idx = 12 }, // DNS Upd Zone
    .{ .kind = .field, .field_idx = 13 }, // DNS Upd Key Name
    .{ .kind = .field, .field_idx = 14 }, // DNS Upd Key File
    .{ .kind = .section, .label = "Routes" },
    .{ .kind = .inline_section, .label = "Static Routes", .inline_target = .routes },
    .{ .kind = .section, .label = "Other" },
    .{ .kind = .inline_section, .label = "DHCP Options", .inline_target = .options },
    .{ .kind = .section, .label = "MAC Classes" },
    .{ .kind = .inline_section, .label = "MAC Classes", .inline_target = .mac_classes },
};

/// Return the string value of a pool form field by index.
fn poolFormFieldVal(form: *const PoolForm, idx: u8) []const u8 {
    return switch (idx) {
        0 => form.subnet_buf[0..form.subnet_len],
        1 => form.router_buf[0..form.router_len],
        2 => form.pool_start_buf[0..form.pool_start_len],
        3 => form.pool_end_buf[0..form.pool_end_len],
        4 => form.lease_time_buf[0..form.lease_time_len],
        5 => form.mtu_buf[0..form.mtu_len],
        6 => form.domain_name_buf[0..form.domain_name_len],
        7 => form.time_offset_buf[0..form.time_offset_len],
        8 => form.boot_filename_buf[0..form.boot_filename_len],
        9 => form.http_boot_url_buf[0..form.http_boot_url_len],
        10 => if (form.dns_update_enable) "yes" else "no",
        11 => form.dns_update_server_buf[0..form.dns_update_server_len],
        12 => form.dns_update_zone_buf[0..form.dns_update_zone_len],
        13 => form.dns_update_key_name_buf[0..form.dns_update_key_name_len],
        14 => form.dns_update_key_file_buf[0..form.dns_update_key_file_len],
        else => "",
    };
}

/// Return a mutable pointer to the active field buffer + length for text input.
fn poolFormFieldBuf(form: *PoolForm, idx: u8) ?struct { buf: []u8, len: *usize } {
    return switch (idx) {
        0 => .{ .buf = &form.subnet_buf, .len = &form.subnet_len },
        1 => .{ .buf = &form.router_buf, .len = &form.router_len },
        2 => .{ .buf = &form.pool_start_buf, .len = &form.pool_start_len },
        3 => .{ .buf = &form.pool_end_buf, .len = &form.pool_end_len },
        4 => .{ .buf = &form.lease_time_buf, .len = &form.lease_time_len },
        5 => .{ .buf = &form.mtu_buf, .len = &form.mtu_len },
        6 => .{ .buf = &form.domain_name_buf, .len = &form.domain_name_len },
        7 => .{ .buf = &form.time_offset_buf, .len = &form.time_offset_len },
        8 => .{ .buf = &form.boot_filename_buf, .len = &form.boot_filename_len },
        9 => .{ .buf = &form.http_boot_url_buf, .len = &form.http_boot_url_len },
        // 10 = boolean toggle, not a text buffer
        11 => .{ .buf = &form.dns_update_server_buf, .len = &form.dns_update_server_len },
        12 => .{ .buf = &form.dns_update_zone_buf, .len = &form.dns_update_zone_len },
        13 => .{ .buf = &form.dns_update_key_name_buf, .len = &form.dns_update_key_name_len },
        14 => .{ .buf = &form.dns_update_key_file_buf, .len = &form.dns_update_key_file_len },
        else => null,
    };
}

/// Join a string slice with ", " into a fixed buffer. Returns the length written.
fn joinComma(comptime N: usize, buf: *[N]u8, items: []const []const u8) usize {
    var len: usize = 0;
    for (items, 0..) |item, i| {
        if (i > 0) {
            if (len + 2 <= N) {
                buf[len] = ',';
                buf[len + 1] = ' ';
                len += 2;
            }
        }
        const to_copy = @min(item.len, N - len);
        @memcpy(buf[len..][0..to_copy], item[0..to_copy]);
        len += to_copy;
    }
    return len;
}

/// Populate a PoolForm from an existing PoolConfig.
fn populatePoolForm(form: *PoolForm, pool: *const config_mod.PoolConfig) void {
    form.* = .{}; // reset all fields

    // Subnet: "x.x.x.x/N"
    const subnet_str = pool.subnet;
    @memcpy(form.subnet_buf[0..subnet_str.len], subnet_str);
    form.subnet_len = subnet_str.len;
    // Append /prefix_len
    if (form.subnet_len + 1 < form.subnet_buf.len) {
        form.subnet_buf[form.subnet_len] = '/';
        form.subnet_len += 1;
        const prefix_str = std.fmt.bufPrint(form.subnet_buf[form.subnet_len..], "{d}", .{pool.prefix_len}) catch "";
        form.subnet_len += prefix_str.len;
    }

    copyField(&form.router_buf, &form.router_len, pool.router);
    copyField(&form.pool_start_buf, &form.pool_start_len, pool.pool_start);
    copyField(&form.pool_end_buf, &form.pool_end_len, pool.pool_end);
    copyField(&form.domain_name_buf, &form.domain_name_len, pool.domain_name);

    // Copy domain search entries.
    form.domain_search_count = @min(pool.domain_search.len, form.domain_search.len);
    for (0..form.domain_search_count) |i| {
        const src = pool.domain_search[i];
        const n = @min(src.len, form.domain_search[i].buf.len);
        @memcpy(form.domain_search[i].buf[0..n], src[0..n]);
        form.domain_search[i].len = n;
    }

    // Copy DNS server entries.
    form.dns_servers_count = @min(pool.dns_servers.len, form.dns_servers.len);
    for (0..form.dns_servers_count) |i| {
        const src = pool.dns_servers[i];
        const n = @min(src.len, form.dns_servers[i].buf.len);
        @memcpy(form.dns_servers[i].buf[0..n], src[0..n]);
        form.dns_servers[i].len = n;
    }

    // lease_time as decimal string
    const lt_str = std.fmt.bufPrint(&form.lease_time_buf, "{d}", .{pool.lease_time}) catch "";
    form.lease_time_len = lt_str.len;

    if (pool.time_offset) |off| {
        const off_str = std.fmt.bufPrint(&form.time_offset_buf, "{d}", .{off}) catch "";
        form.time_offset_len = off_str.len;
    }

    if (pool.mtu) |mtu| {
        const mtu_str = std.fmt.bufPrint(&form.mtu_buf, "{d}", .{mtu}) catch "";
        form.mtu_len = mtu_str.len;
    }

    form.time_servers_len = joinComma(128, &form.time_servers_buf, pool.time_servers);

    // Copy log server entries.
    form.log_servers_count = @min(pool.log_servers.len, form.log_servers.len);
    for (0..form.log_servers_count) |i| {
        const src = pool.log_servers[i];
        const n = @min(src.len, form.log_servers[i].buf.len);
        @memcpy(form.log_servers[i].buf[0..n], src[0..n]);
        form.log_servers[i].len = n;
    }

    // Copy NTP server entries.
    form.ntp_servers_count = @min(pool.ntp_servers.len, form.ntp_servers.len);
    for (0..form.ntp_servers_count) |i| {
        const src = pool.ntp_servers[i];
        const n = @min(src.len, form.ntp_servers[i].buf.len);
        @memcpy(form.ntp_servers[i].buf[0..n], src[0..n]);
        form.ntp_servers[i].len = n;
    }

    // Copy WINS server entries.
    form.wins_servers_count = @min(pool.wins_servers.len, form.wins_servers.len);
    for (0..form.wins_servers_count) |i| {
        const src = pool.wins_servers[i];
        const n = @min(src.len, form.wins_servers[i].buf.len);
        @memcpy(form.wins_servers[i].buf[0..n], src[0..n]);
        form.wins_servers[i].len = n;
    }

    // Copy TFTP server entries.
    form.tftp_servers_count = @min(pool.tftp_servers.len, form.tftp_servers.len);
    for (0..form.tftp_servers_count) |i| {
        const src = pool.tftp_servers[i];
        const n = @min(src.len, form.tftp_servers[i].buf.len);
        @memcpy(form.tftp_servers[i].buf[0..n], src[0..n]);
        form.tftp_servers[i].len = n;
    }

    copyField(&form.boot_filename_buf, &form.boot_filename_len, pool.boot_filename);
    copyField(&form.http_boot_url_buf, &form.http_boot_url_len, pool.http_boot_url);

    form.dns_update_enable = pool.dns_update.enable;
    copyField(&form.dns_update_server_buf, &form.dns_update_server_len, pool.dns_update.server);
    copyField(&form.dns_update_zone_buf, &form.dns_update_zone_len, pool.dns_update.zone);
    copyField(&form.dns_update_key_name_buf, &form.dns_update_key_name_len, pool.dns_update.key_name);
    copyField(&form.dns_update_key_file_buf, &form.dns_update_key_file_len, pool.dns_update.key_file);

    // Copy static routes.
    form.route_count = @min(pool.static_routes.len, form.routes.len);
    for (0..form.route_count) |i| {
        const sr = &pool.static_routes[i];
        var re = &form.routes[i];
        re.* = .{};
        const dest = std.fmt.bufPrint(&re.dest_buf, "{d}.{d}.{d}.{d}/{d}", .{
            sr.destination[0], sr.destination[1], sr.destination[2], sr.destination[3], sr.prefix_len,
        }) catch "";
        re.dest_len = dest.len;
        const rtr = std.fmt.bufPrint(&re.router_buf, "{d}.{d}.{d}.{d}", .{
            sr.router[0], sr.router[1], sr.router[2], sr.router[3],
        }) catch "";
        re.router_len = rtr.len;
    }

    // Copy DHCP options.
    form.option_count = 0;
    var it = pool.dhcp_options.iterator();
    while (it.next()) |entry| {
        if (form.option_count >= form.options.len) break;
        var oe = &form.options[form.option_count];
        oe.* = .{};
        const code = entry.key_ptr.*;
        const val = entry.value_ptr.*;
        const cn = @min(code.len, oe.code_buf.len);
        @memcpy(oe.code_buf[0..cn], code[0..cn]);
        oe.code_len = cn;
        const vn = @min(val.len, oe.value_buf.len);
        @memcpy(oe.value_buf[0..vn], val[0..vn]);
        oe.value_len = vn;
        form.option_count += 1;
    }

    // Copy MAC classes.
    form.mac_class_count = @min(pool.mac_classes.len, form.mac_classes.len);
    for (0..form.mac_class_count) |i| {
        var mce = &form.mac_classes[i];
        mce.* = .{};
        const mcc = &pool.mac_classes[i];
        copyField(&mce.name_buf, &mce.name_len, mcc.name);
        copyField(&mce.match_buf, &mce.match_len, mcc.match);
        if (mcc.router) |r| copyField(&mce.router_buf, &mce.router_len, r);
        if (mcc.domain_name) |d| copyField(&mce.domain_name_buf, &mce.domain_name_len, d);
        if (mcc.time_offset) |off| {
            const off_str = std.fmt.bufPrint(&mce.time_offset_buf, "{d}", .{off}) catch "";
            mce.time_offset_len = off_str.len;
        }
        if (mcc.boot_filename) |b| copyField(&mce.boot_filename_buf, &mce.boot_filename_len, b);
        if (mcc.http_boot_url) |h| copyField(&mce.http_boot_url_buf, &mce.http_boot_url_len, h);
        // Copy domain search entries.
        mce.domain_search_count = @min(mcc.domain_search.len, mce.domain_search.len);
        for (0..mce.domain_search_count) |j| {
            const src = mcc.domain_search[j];
            const n = @min(src.len, mce.domain_search[j].buf.len);
            @memcpy(mce.domain_search[j].buf[0..n], src[0..n]);
            mce.domain_search[j].len = n;
        }
        // Copy DNS server entries.
        mce.dns_servers_count = @min(mcc.dns_servers.len, mce.dns_servers.len);
        for (0..mce.dns_servers_count) |j| {
            const src = mcc.dns_servers[j];
            const n = @min(src.len, mce.dns_servers[j].buf.len);
            @memcpy(mce.dns_servers[j].buf[0..n], src[0..n]);
            mce.dns_servers[j].len = n;
        }
        // Copy NTP server entries.
        mce.ntp_servers_count = @min(mcc.ntp_servers.len, mce.ntp_servers.len);
        for (0..mce.ntp_servers_count) |j| {
            const src = mcc.ntp_servers[j];
            const n = @min(src.len, mce.ntp_servers[j].buf.len);
            @memcpy(mce.ntp_servers[j].buf[0..n], src[0..n]);
            mce.ntp_servers[j].len = n;
        }
        // Copy log server entries.
        mce.log_servers_count = @min(mcc.log_servers.len, mce.log_servers.len);
        for (0..mce.log_servers_count) |j| {
            const src = mcc.log_servers[j];
            const n = @min(src.len, mce.log_servers[j].buf.len);
            @memcpy(mce.log_servers[j].buf[0..n], src[0..n]);
            mce.log_servers[j].len = n;
        }
        // Copy WINS server entries.
        mce.wins_servers_count = @min(mcc.wins_servers.len, mce.wins_servers.len);
        for (0..mce.wins_servers_count) |j| {
            const src = mcc.wins_servers[j];
            const n = @min(src.len, mce.wins_servers[j].buf.len);
            @memcpy(mce.wins_servers[j].buf[0..n], src[0..n]);
            mce.wins_servers[j].len = n;
        }
        // Copy TFTP server entries.
        mce.tftp_servers_count = @min(mcc.tftp_servers.len, mce.tftp_servers.len);
        for (0..mce.tftp_servers_count) |j| {
            const src = mcc.tftp_servers[j];
            const n = @min(src.len, mce.tftp_servers[j].buf.len);
            @memcpy(mce.tftp_servers[j].buf[0..n], src[0..n]);
            mce.tftp_servers[j].len = n;
        }
        // Copy static routes.
        mce.route_count = @min(mcc.static_routes.len, mce.routes.len);
        for (0..mce.route_count) |j| {
            const sr = &mcc.static_routes[j];
            var re = &mce.routes[j];
            re.* = .{};
            const dest = std.fmt.bufPrint(&re.dest_buf, "{d}.{d}.{d}.{d}/{d}", .{
                sr.destination[0], sr.destination[1], sr.destination[2], sr.destination[3], sr.prefix_len,
            }) catch "";
            re.dest_len = dest.len;
            const rtr = std.fmt.bufPrint(&re.router_buf, "{d}.{d}.{d}.{d}", .{
                sr.router[0], sr.router[1], sr.router[2], sr.router[3],
            }) catch "";
            re.router_len = rtr.len;
        }
        // Copy DHCP options.
        mce.option_count = 0;
        {
            var opt_it = mcc.dhcp_options.iterator();
            while (opt_it.next()) |entry| {
                if (mce.option_count >= mce.options.len) break;
                var oe = &mce.options[mce.option_count];
                oe.* = .{};
                const code = entry.key_ptr.*;
                const val = entry.value_ptr.*;
                const cn = @min(code.len, oe.code_buf.len);
                @memcpy(oe.code_buf[0..cn], code[0..cn]);
                oe.code_len = cn;
                const vn = @min(val.len, oe.value_buf.len);
                @memcpy(oe.value_buf[0..vn], val[0..vn]);
                oe.value_len = vn;
                mce.option_count += 1;
            }
        }
    }
}

fn copyField(buf: anytype, len: *usize, src: []const u8) void {
    const n = @min(src.len, buf.len);
    @memcpy(buf[0..n], src[0..n]);
    len.* = n;
}

// ---- Pool list tab ----

/// Format a pool range abbreviating octets that match the subnet.
/// e.g. subnet=192.168.10.0, start=192.168.10.100, end=192.168.10.200 → ".100 – .200"
///      subnet=172.20.0.0, start=172.20.0.100, end=172.20.14.200 → ".0.100 – .14.200"
fn fmtAbbrevRange(fa: std.mem.Allocator, pool: *const config_mod.PoolConfig) ![]const u8 {
    // Both empty means fully automatic range — no abbreviation needed.
    if (pool.pool_start.len == 0 and pool.pool_end.len == 0) return try fa.dupe(u8, "auto");

    // Compute effective start/end IPs (resolve "auto" to subnet+1 / broadcast-1).
    const subnet_bytes = config_mod.parseIpv4(pool.subnet) catch return "?";
    const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
    const broadcast_int = subnet_int | ~pool.subnet_mask;

    var start_buf: [16]u8 = undefined;
    const start: []const u8 = if (pool.pool_start.len > 0) pool.pool_start else blk: {
        const s = subnet_int + 1;
        break :blk std.fmt.bufPrint(&start_buf, "{d}.{d}.{d}.{d}", .{
            @as(u8, @truncate(s >> 24)), @as(u8, @truncate(s >> 16)),
            @as(u8, @truncate(s >> 8)),  @as(u8, @truncate(s)),
        }) catch return "?";
    };
    var end_buf: [16]u8 = undefined;
    const end: []const u8 = if (pool.pool_end.len > 0) pool.pool_end else blk: {
        const e = broadcast_int - 1;
        break :blk std.fmt.bufPrint(&end_buf, "{d}.{d}.{d}.{d}", .{
            @as(u8, @truncate(e >> 24)), @as(u8, @truncate(e >> 16)),
            @as(u8, @truncate(e >> 8)),  @as(u8, @truncate(e)),
        }) catch return "?";
    };

    // Find common prefix octets with subnet.
    const sub_octets = splitOctets(pool.subnet);
    const start_octets = splitOctets(start);
    const end_octets = splitOctets(end);
    // Count matching leading octets (at most 3 — always show at least the last octet).
    var common: usize = 0;
    while (common < 3) : (common += 1) {
        if (common >= sub_octets.count or common >= start_octets.count or common >= end_octets.count) break;
        if (!std.mem.eql(u8, sub_octets.items[common], start_octets.items[common]) or
            !std.mem.eql(u8, sub_octets.items[common], end_octets.items[common])) break;
    }
    // Build abbreviated strings.
    const abbrev_start = joinFromOctet(fa, &start_octets, common) catch start;
    const abbrev_end = joinFromOctet(fa, &end_octets, common) catch end;
    return std.fmt.allocPrint(fa, "{s} \xe2\x80\x93 {s}", .{ abbrev_start, abbrev_end });
}

const OctetSplit = struct {
    items: [4][]const u8,
    count: usize,
};

fn splitOctets(s: []const u8) OctetSplit {
    var result = OctetSplit{ .items = undefined, .count = 0 };
    var it = std.mem.splitScalar(u8, s, '.');
    while (it.next()) |part| {
        if (result.count >= 4) break;
        result.items[result.count] = part;
        result.count += 1;
    }
    return result;
}

fn joinFromOctet(fa: std.mem.Allocator, octets: *const OctetSplit, start_idx: usize) ![]const u8 {
    if (start_idx >= octets.count) return "";
    var buf: [16]u8 = undefined;
    var len: usize = 0;
    var i = start_idx;
    while (i < octets.count) : (i += 1) {
        buf[len] = '.';
        len += 1;
        const o = octets.items[i];
        const n = @min(o.len, buf.len - len);
        @memcpy(buf[len..][0..n], o[0..n]);
        len += n;
    }
    return try fa.dupe(u8, buf[0..len]);
}

const POOL_COL_NAMES = [_][]const u8{ "subnet", "range", "router", "lease", "res", "dns upd" };

const POOL_COL_SPECS = [6]LeaseColSpec{
    .{ .ideal = 20, .min = 12, .left_trunc = false }, // subnet  "192.168.100.0/24"
    .{ .ideal = 34, .min = 10, .left_trunc = false }, // range   "192.168.1.100 - 192.168.1.200"
    .{ .ideal = 16, .min = 7, .left_trunc = true }, // router
    .{ .ideal = 8, .min = 5, .left_trunc = false, .right_align = true }, // lease time
    .{ .ideal = 5, .min = 3, .left_trunc = false, .right_align = true }, // reservations
    .{ .ideal = 7, .min = 3, .left_trunc = false }, // dns update
};
const POOL_COL_REDUCE_ORDER = [6]usize{ 1, 5, 4, 3, 0, 2 }; // range→dns→res→lease→subnet→router

fn calcPoolColWidths(win_width: u16) [6]u16 {
    var widths: [6]u16 = undefined;
    for (POOL_COL_SPECS, 0..) |spec, i| widths[i] = spec.ideal;
    const seps: u16 = (POOL_COL_SPECS.len - 1) * LEASE_COL_SEP;
    var total: u16 = seps;
    for (widths) |w| total +|= w;
    for (POOL_COL_REDUCE_ORDER) |col| {
        if (total <= win_width) break;
        const over = total - win_width;
        const slack = widths[col] - POOL_COL_SPECS[col].min;
        const cut = @min(over, slack);
        widths[col] -= cut;
        total -= cut;
    }
    return widths;
}

fn renderPoolsTab(server: *AdminServer, state: *TuiState, win: vaxis.Window, fa: std.mem.Allocator) !void {
    const pools = server.cfg.pools;
    if (win.height < 2 or win.width < 10) return;

    if (pools.len == 0) {
        _ = win.print(&.{.{ .text = "  No pools configured.", .style = .{ .fg = .{ .rgb = .{ 180, 180, 180 } } } }}, .{ .row_offset = 1, .wrap = .none });
        return;
    }

    const widths = calcPoolColWidths(@intCast(win.width));
    const hdr_bg: vaxis.Color = .{ .rgb = .{ 30, 30, 50 } };
    const hdr_style: vaxis.Style = .{ .bold = true, .fg = .{ .rgb = .{ 200, 200, 200 } }, .bg = hdr_bg };
    const even_bg: vaxis.Color = .{ .rgb = .{ 20, 20, 30 } };
    const odd_bg: vaxis.Color = .{ .rgb = .{ 26, 26, 36 } };

    // Clamp selection.
    if (state.pool_row >= pools.len) state.pool_row = @intCast(pools.len - 1);

    // --- Header row (with sort indicators) ---
    {
        const hdr_win = win.child(.{ .y_off = 0, .height = 1, .width = win.width });
        hdr_win.fill(.{ .style = .{ .bg = hdr_bg } });
        var x: i17 = 0;
        for (0..6) |ci| {
            if (widths[ci] > 0) {
                const cell = hdr_win.child(.{ .x_off = x, .y_off = 0, .width = widths[ci], .height = 1 });
                const base = POOL_COL_NAMES[ci];
                const name = if (state.pool_sort_col == ci)
                    (if (state.pool_sort_asc)
                        std.fmt.allocPrint(fa, "{s} ^", .{base}) catch base
                    else
                        std.fmt.allocPrint(fa, "{s} v", .{base}) catch base)
                else
                    base;
                const raw = try truncateCell(fa, name, widths[ci], false);
                const text = if (POOL_COL_SPECS[ci].right_align) try rightAlignText(fa, raw, widths[ci]) else raw;
                _ = cell.print(&.{.{ .text = text, .style = hdr_style }}, .{ .wrap = .none });
            }
            x += @as(i17, widths[ci]) + LEASE_COL_SEP;
        }
    }

    // --- Build sortable row data ---
    const filter = state.pool_filter_buf[0..state.pool_filter_len];
    const PoolRowData = struct { subnet: []const u8, range: []const u8, router: []const u8, lease: []const u8, res: []const u8, dns: []const u8, orig_idx: usize };
    var row_data = std.ArrayList(PoolRowData){};
    for (pools, 0..) |*p, pi| {
        const rd = PoolRowData{
            .subnet = std.fmt.allocPrint(fa, "{s}/{d}", .{ p.subnet, p.prefix_len }) catch "?",
            .range = fmtAbbrevRange(fa, p) catch "?",
            .router = p.router,
            .lease = std.fmt.allocPrint(fa, "{d}", .{p.lease_time}) catch "?",
            .res = std.fmt.allocPrint(fa, "{d}", .{p.reservations.len}) catch "?",
            .dns = if (p.dns_update.enable) "yes" else "no",
            .orig_idx = pi,
        };
        // Apply filter.
        if (filter.len > 0) {
            const match = containsIgnoreCase(rd.subnet, filter) or
                containsIgnoreCase(rd.range, filter) or
                containsIgnoreCase(rd.router, filter) or
                containsIgnoreCase(rd.lease, filter) or
                containsIgnoreCase(rd.dns, filter);
            if (!match) continue;
        }
        try row_data.append(fa, rd);
    }

    // Sort if a column is selected.
    if (state.pool_sort_col < 6) {
        const SortCtx = struct {
            col: u8,
            asc: bool,
            fn lessThan(ctx: @This(), a: PoolRowData, b: PoolRowData) bool {
                const af = switch (ctx.col) {
                    0 => a.subnet,
                    1 => a.range,
                    2 => a.router,
                    3 => a.lease,
                    4 => a.res,
                    5 => a.dns,
                    else => "",
                };
                const bf = switch (ctx.col) {
                    0 => b.subnet,
                    1 => b.range,
                    2 => b.router,
                    3 => b.lease,
                    4 => b.res,
                    5 => b.dns,
                    else => "",
                };
                const cmp = std.mem.lessThan(u8, af, bf);
                return if (ctx.asc) cmp else !cmp;
            }
        };
        std.sort.pdq(PoolRowData, row_data.items, SortCtx{ .col = state.pool_sort_col, .asc = state.pool_sort_asc }, SortCtx.lessThan);
    }

    // --- Scroll management ---
    const visible: u16 = win.height -| 1;
    const n: u16 = if (row_data.items.len > 0xFFFF) 0xFFFF else @intCast(row_data.items.len);
    if (state.pool_row >= n) state.pool_row = n - 1;
    if (state.pool_row < state.pool_start) state.pool_start = state.pool_row;
    if (state.pool_row >= state.pool_start +| visible) state.pool_start = state.pool_row - visible + 1;

    // --- Data rows ---
    for (0..visible) |ri| {
        const row_idx = state.pool_start + @as(u16, @intCast(ri));
        if (row_idx >= row_data.items.len) break;
        const rd = row_data.items[row_idx];
        const selected = (row_idx == state.pool_row);
        const row_bg: vaxis.Color = if (selected) .{ .rgb = .{ 50, 80, 140 } } else if (ri % 2 != 0) odd_bg else even_bg;
        const row_style: vaxis.Style = .{ .bg = row_bg };

        const row_win = win.child(.{ .x_off = 0, .y_off = @intCast(ri + 1), .width = win.width, .height = 1 });
        row_win.fill(.{ .style = row_style });

        // Check if pool is disabled by sync.
        const pool_disabled = if (server.sync_mgr) |s| blk: {
            const sip = config_mod.parseIpv4(server.cfg.pools[rd.orig_idx].subnet) catch break :blk false;
            break :blk !s.isPoolEnabled(sip, server.cfg.pools[rd.orig_idx].prefix_len);
        } else false;

        if (pool_disabled) {
            // Render subnet normally in first column, then bold red mismatch text spanning the rest.
            var x: i17 = 0;
            if (widths[0] > 0) {
                const cell = row_win.child(.{ .x_off = x, .y_off = 0, .width = widths[0], .height = 1 });
                const raw = try truncateCell(fa, rd.subnet, widths[0], false);
                _ = cell.print(&.{.{ .text = raw, .style = row_style }}, .{ .wrap = .none });
            }
            x += @as(i17, widths[0]) + LEASE_COL_SEP;
            const mismatch_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 60, 60 } }, .bg = row_bg, .bold = true };
            const remaining_w = @as(u16, @intCast(@max(0, @as(i17, win.width) - x)));
            if (remaining_w > 0) {
                const mismatch_cell = row_win.child(.{ .x_off = x, .y_off = 0, .width = remaining_w, .height = 1 });
                _ = mismatch_cell.print(&.{.{ .text = "CONFIG MISMATCH, DISABLED", .style = mismatch_style }}, .{ .wrap = .none });
            }
        } else {
            const fields = [6][]const u8{ rd.subnet, rd.range, rd.router, rd.lease, rd.res, rd.dns };
            var x: i17 = 0;
            for (0..6) |ci| {
                if (widths[ci] > 0) {
                    const cell = row_win.child(.{ .x_off = x, .y_off = 0, .width = widths[ci], .height = 1 });
                    const spec = POOL_COL_SPECS[ci];
                    const raw = try truncateCell(fa, fields[ci], widths[ci], spec.left_trunc);
                    const text = if (spec.right_align) try rightAlignText(fa, raw, widths[ci]) else raw;
                    _ = cell.print(&.{.{ .text = text, .style = row_style }}, .{ .wrap = .none });
                }
                x += @as(i17, widths[ci]) + LEASE_COL_SEP;
            }
        }
    }
}

fn handlePoolsKey(server: *AdminServer, state: *TuiState, key: vaxis.Key) void {
    const pool_count = server.cfg.pools.len;
    if (pool_count == 0) return;

    if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{})) {
        if (state.pool_row + 1 < pool_count) state.pool_row += 1;
    } else if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{})) {
        state.pool_row -|= 1;
    } else if (key.matches('v', .{}) or key.matches(vaxis.Key.enter, .{})) {
        state.pool_detail_scroll = 0;
        state.mode = .pool_detail;
    } else if (key.matches('e', .{}) and !server.cfg.admin_ssh.read_only) {
        state.pool_form = .{};
        populatePoolForm(&state.pool_form, &server.cfg.pools[state.pool_row]);
        state.pool_form.editing_index = state.pool_row; // must be after populatePoolForm (which resets form)
        state.mode = .pool_form;
    } else if (key.matches('n', .{}) and !server.cfg.admin_ssh.read_only) {
        state.pool_form = .{};
        // Set default lease time.
        const lt = std.fmt.bufPrint(&state.pool_form.lease_time_buf, "3600", .{}) catch "";
        state.pool_form.lease_time_len = lt.len;
        state.mode = .pool_form;
    } else if (key.matches('d', .{}) and !server.cfg.admin_ssh.read_only) {
        state.pool_del_index = state.pool_row;
        state.mode = .pool_delete_confirm;
    } else if (key.matches('/', .{})) {
        state.pool_filter_active = true;
        state.pool_filter_len = 0;
    } else if (key.matches(vaxis.Key.escape, .{})) {
        state.pool_filter_len = 0;
    }
}

// ---- Pool detail view (read-only) ----

fn renderPoolDetail(server: *AdminServer, state: *TuiState, win: vaxis.Window, fa: std.mem.Allocator) !void {
    const pools = server.cfg.pools;
    if (state.pool_row >= pools.len) return;
    const pool = &pools[state.pool_row];
    const read_only = server.cfg.admin_ssh.read_only;

    const BOX_W: u16 = 62;
    const BOX_H: u16 = 24;
    if (win.width < BOX_W or win.height < BOX_H) return;
    const x = (win.width - BOX_W) / 2;
    const y = (win.height - BOX_H) / 2;
    const box = win.child(.{ .x_off = x, .y_off = y, .width = BOX_W, .height = BOX_H });
    box.fill(.{ .char = .{ .grapheme = " ", .width = 1 }, .style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } } });

    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 160, 255 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    drawBox(box, 0, 0, BOX_W, BOX_H, border_style);
    const label_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 140, 160, 200 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const val_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 220, 220, 220 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const section_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 80, 180, 255 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };

    const close_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 80, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };

    const title_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 200, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };

    // Title (inside border) + [X] (on border).
    const title = std.fmt.allocPrint(fa, " Pool: {s}/{d} ", .{ pool.subnet, pool.prefix_len }) catch " Pool ";
    _ = box.print(&.{.{ .text = title, .style = title_style }}, .{ .col_offset = 1, .row_offset = 1, .wrap = .none });
    _ = box.print(&.{.{ .text = "[X]", .style = close_style }}, .{ .col_offset = BOX_W -| 4, .row_offset = 0, .wrap = .none });

    // Build lines.
    // Each field = 1 line, each section = 2 lines (blank + header), plus domain search entries, plus summary.
    const MAX_LINES = pool_field_meta.len * 3 + 60;
    var lines: [MAX_LINES]struct { text: []const u8, style: vaxis.Style } = undefined;
    var lcount: usize = 0;

    // Render using pool_layout for correct section headers and ordering.
    for (pool_layout) |item| {
        switch (item.kind) {
            .section => {
                lines[lcount] = .{ .text = "", .style = val_style };
                lcount += 1;
                lines[lcount] = .{ .text = std.fmt.allocPrint(fa, "  -- {s} --", .{item.label}) catch "", .style = section_style };
                lcount += 1;
                continue;
            },
            .inline_section => {
                // Render inline entries for this section.
                const items: []const []const u8 = switch (item.inline_target.?) {
                    .domain_search => pool.domain_search,
                    .dns => pool.dns_servers,
                    .wins => pool.wins_servers,
                    .ntp => pool.ntp_servers,
                    .log => pool.log_servers,
                    .tftp => pool.tftp_servers,
                    .routes => &.{}, // handled separately below
                    .options => &.{}, // handled separately below
                    .mac_classes => &.{}, // handled separately below
                };
                if (item.inline_target.? == .mac_classes) {
                    if (pool.mac_classes.len > 0) {
                        lines[lcount] = .{ .text = std.fmt.allocPrint(fa, "  {s:<18} {d} configured", .{ item.label, pool.mac_classes.len }) catch "", .style = val_style };
                        lcount += 1;
                    }
                } else if (item.inline_target.? == .routes) {
                    if (pool.static_routes.len > 0) {
                        lines[lcount] = .{ .text = std.fmt.allocPrint(fa, "  {s:<18} {d} configured", .{ item.label, pool.static_routes.len }) catch "", .style = val_style };
                        lcount += 1;
                    }
                } else if (item.inline_target.? == .options) {
                    if (pool.dhcp_options.count() > 0) {
                        lines[lcount] = .{ .text = std.fmt.allocPrint(fa, "  {s:<18} {d} configured", .{ item.label, pool.dhcp_options.count() }) catch "", .style = val_style };
                        lcount += 1;
                    }
                } else if (items.len > 0) {
                    const joined = std.mem.join(fa, ", ", items) catch "\xe2\x80\x94";
                    lines[lcount] = .{ .text = std.fmt.allocPrint(fa, "  {s:<18} {s}", .{ item.label, joined }) catch "", .style = val_style };
                    lcount += 1;
                }
                continue;
            },
            .field => {},
        }
        const fi = item.field_idx.?;
        const meta = pool_field_meta[fi];
        if (read_only and meta.sensitive) continue;
        const val: []const u8 = switch (fi) {
            0 => std.fmt.allocPrint(fa, "{s}/{d}", .{ pool.subnet, pool.prefix_len }) catch "?",
            1 => pool.router,
            2 => if (pool.pool_start.len > 0) pool.pool_start else "\xe2\x80\x94",
            3 => if (pool.pool_end.len > 0) pool.pool_end else "\xe2\x80\x94",
            4 => if (pool.domain_name.len > 0) pool.domain_name else "\xe2\x80\x94",
            5 => std.fmt.allocPrint(fa, "{d}", .{pool.lease_time}) catch "?",
            6 => if (pool.time_offset) |off| std.fmt.allocPrint(fa, "{d}", .{off}) catch "?" else "\xe2\x80\x94",
            7 => if (pool.mtu) |mtu| std.fmt.allocPrint(fa, "{d}", .{mtu}) catch "?" else "\xe2\x80\x94",
            8 => if (pool.boot_filename.len > 0) pool.boot_filename else "\xe2\x80\x94",
            9 => if (pool.http_boot_url.len > 0) pool.http_boot_url else "\xe2\x80\x94",
            10 => if (pool.dns_update.enable) "yes" else "no",
            11 => if (pool.dns_update.server.len > 0) pool.dns_update.server else "\xe2\x80\x94",
            12 => if (pool.dns_update.zone.len > 0) pool.dns_update.zone else "\xe2\x80\x94",
            13 => if (pool.dns_update.key_name.len > 0) pool.dns_update.key_name else "\xe2\x80\x94",
            14 => if (pool.dns_update.key_file.len > 0) pool.dns_update.key_file else "\xe2\x80\x94",
            else => "\xe2\x80\x94",
        };
        const line = std.fmt.allocPrint(fa, "  {s:<18} {s}", .{ meta.label, val }) catch "";
        lines[lcount] = .{ .text = line, .style = val_style };
        lcount += 1;
    }
    // Inline server sections (shown after regular fields).
    const inline_sections = [_]struct { label: []const u8, items: []const []const u8 }{
        .{ .label = "Domains", .items = pool.domain_search },
        .{ .label = "DNS Servers", .items = pool.dns_servers },
        .{ .label = "Log Servers", .items = pool.log_servers },
        .{ .label = "NTP Servers", .items = pool.ntp_servers },
        .{ .label = "WINS Servers", .items = pool.wins_servers },
        .{ .label = "TFTP Servers", .items = pool.tftp_servers },
    };
    for (inline_sections) |sec| {
        if (sec.items.len > 0) {
            lines[lcount] = .{ .text = "", .style = val_style };
            lcount += 1;
            const sec_hdr = std.fmt.allocPrint(fa, "  -- {s} --", .{sec.label}) catch "";
            lines[lcount] = .{ .text = sec_hdr, .style = section_style };
            lcount += 1;
            for (sec.items) |item| {
                if (lcount >= MAX_LINES) break;
                const item_line = std.fmt.allocPrint(fa, "    {s}", .{item}) catch "";
                lines[lcount] = .{ .text = item_line, .style = val_style };
                lcount += 1;
            }
        }
    }
    // Summary lines.
    if (lcount < MAX_LINES) {
        lines[lcount] = .{ .text = std.fmt.allocPrint(fa, "  Reservations: {d}    Static routes: {d}", .{ pool.reservations.len, pool.static_routes.len }) catch "", .style = label_style };
        lcount += 1;
    }

    // Scrollable content (inside border: rows 2..BOX_H-2).
    const content_h = BOX_H - 4; // top border + title + hint + bottom border
    // Clamp scroll so last line + 1 blank is at the bottom.
    const max_scroll: u16 = if (lcount + 1 > content_h) @intCast(lcount + 1 - content_h) else 0;
    if (state.pool_detail_scroll > max_scroll) state.pool_detail_scroll = max_scroll;
    var row: u16 = 2;
    var li: usize = state.pool_detail_scroll;
    while (li < lcount and row < BOX_H - 2) : ({
        li += 1;
        row += 1;
    }) {
        _ = box.print(&.{.{ .text = lines[li].text, .style = lines[li].style }}, .{ .col_offset = 1, .row_offset = row, .wrap = .none });
    }

    // Hint bar (inside border, last content row).
    const hint_text = if (read_only) "  Esc: close  \xe2\x86\x91/\xe2\x86\x93: scroll" else "  e: edit  Esc: close  \xe2\x86\x91/\xe2\x86\x93: scroll";
    _ = box.print(&.{.{ .text = hint_text, .style = hint_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 2, .wrap = .none });
}

/// Check if a click at (row, col) hits the [X] close button of the current modal.
/// Handle mouse click on editable fields within modals.
fn handleModalFieldClick(state: *TuiState, win_w: u16, win_h: u16, click_row: u16) void {
    const dims = modalDims(state.mode, win_w, win_h, state);
    const modal_y = dims.y;

    switch (state.mode) {
        .reservation_form => {
            // Rows relative to modal: 3=IP, 4=MAC, 5=Hostname, 7=[+]Add, 8+=options
            const rel = click_row -| modal_y;
            if (rel >= 3 and rel <= 5) {
                state.form.active_field = @intCast(rel - 3);
                state.form.cursor = state.form.activeLen();
            } else if (rel == 7) {
                state.form.active_field = 3; // [+] add
            } else if (rel >= 8 and rel < 8 + state.form.option_count) {
                state.form.active_field = @intCast(4 + rel - 8);
            }
        },
        .pool_form => {
            // Map click position to field index using scroll_row and pool_layout walk.
            const rel = click_row -| modal_y;
            if (rel < 2) return; // title area
            const clicked_abs = state.pool_form.scroll_row + (rel - 2);
            const form = &state.pool_form;
            var abs: u16 = 0;
            var pos: u8 = 0; // navigable field index
            for (pool_layout) |item| {
                switch (item.kind) {
                    .section => {
                        abs += 2; // blank line + header
                    },
                    .field => {
                        if (abs == clicked_abs) {
                            form.active_field = pos;
                            form.cursor = activeFieldCursorLen(form, pos);
                            return;
                        }
                        abs += 1;
                        pos += 1;
                    },
                    .inline_section => {
                        const target = item.inline_target.?;
                        const count = form.inlineCount(target);
                        // [+] Add button
                        if (abs == clicked_abs) {
                            form.active_field = pos;
                            form.cursor = 0;
                            return;
                        }
                        abs += 1;
                        pos += 1;
                        // Entries
                        for (0..count) |_| {
                            if (abs == clicked_abs) {
                                form.active_field = pos;
                                form.cursor = 0;
                                return;
                            }
                            abs += 1;
                            pos += 1;
                        }
                    },
                }
            }
        },
        .pool_server_edit => {
            // Single field at row 3.
            const rel = click_row -| modal_y;
            if (rel == 3) {
                state.pool_form.server_edit_cursor = state.pool_form.server_edit_len;
            }
        },
        .res_option_edit => {
            const rel = click_row -| modal_y;
            if (rel == 3) {
                state.form.opt_edit_field = 0;
                state.form.opt_edit_cursor = state.form.opt_edit_code_len;
            } else if (rel == 4) {
                state.form.opt_edit_field = 1;
                state.form.opt_edit_cursor = state.form.opt_edit_value_len;
            }
        },
        .pool_route_edit => {
            const rel = click_row -| modal_y;
            if (rel == 3) {
                state.pool_form.route_edit_field = 0;
                state.pool_form.route_edit_cursor = state.pool_form.route_edit_dest_len;
            } else if (rel == 4) {
                state.pool_form.route_edit_field = 1;
                state.pool_form.route_edit_cursor = state.pool_form.route_edit_router_len;
            }
        },
        .pool_option_edit => {
            const rel = click_row -| modal_y;
            if (rel == 3) {
                state.pool_form.opt_edit_field = 0;
                state.pool_form.opt_edit_cursor = state.pool_form.opt_edit_code_len;
            } else if (rel == 4) {
                state.pool_form.opt_edit_field = 1;
                state.pool_form.opt_edit_cursor = state.pool_form.opt_edit_value_len;
            }
        },
        .pool_mac_class_edit => {
            // Map click to field index in the MAC class edit modal using layout walk.
            const rel = click_row -| modal_y;
            if (rel < 2) return; // title area
            const clicked_abs = state.pool_form.mac_class_edit_scroll + (rel - 2);
            const mce = &state.pool_form.mac_class_edit;
            var abs: u16 = 0;
            var mpos: u8 = 0;
            for (mac_class_layout) |mitem| {
                switch (mitem.kind) {
                    .section => abs += 2,
                    .field => {
                        if (abs == clicked_abs) {
                            state.pool_form.mac_class_edit_field = mpos;
                            state.pool_form.mac_class_edit_cursor = mcActiveFieldCursorLen(mce, mpos);
                            return;
                        }
                        abs += 1;
                        mpos += 1;
                    },
                    .inline_section => {
                        const mtarget = mitem.inline_target.?;
                        const mcount = mcInlineCount(mce, mtarget);
                        if (abs == clicked_abs) {
                            state.pool_form.mac_class_edit_field = mpos;
                            state.pool_form.mac_class_edit_cursor = 0;
                            return;
                        }
                        abs += 1;
                        mpos += 1;
                        for (0..mcount) |_| {
                            if (abs == clicked_abs) {
                                state.pool_form.mac_class_edit_field = mpos;
                                state.pool_form.mac_class_edit_cursor = 0;
                                return;
                            }
                            abs += 1;
                            mpos += 1;
                        }
                    },
                }
            }
        },
        else => {},
    }
}

fn isModalCloseClick(mode: TuiMode, win_w: u16, win_h: u16, row: u16, col: u16, state: *const TuiState) bool {
    const dims = modalDims(mode, win_w, win_h, state);
    const modal_y = dims.y;
    const modal_x = dims.x;
    const modal_w = dims.w;
    // [X] is rendered at (modal_y, modal_x + modal_w - 4), occupying 3 chars.
    return (row == modal_y and col >= modal_x + modal_w -| 4 and col < modal_x + modal_w -| 1);
}

fn modalDims(mode: TuiMode, win_w: u16, win_h: u16, state: *const TuiState) struct { x: u16, y: u16, w: u16, h: u16 } {
    switch (mode) {
        .pool_form => {
            const w = @max(60, @min(win_w * 4 / 5, win_w -| 4));
            const h = @max(14, @min(win_h * 4 / 5, win_h -| 2));
            return .{ .x = (win_w - w) / 2, .y = (win_h - h) / 2, .w = w, .h = h };
        },
        .pool_detail => {
            const w: u16 = 62;
            const h: u16 = 24;
            return .{ .x = (win_w -| w) / 2, .y = (win_h -| h) / 2, .w = w, .h = h };
        },
        .reservation_form => {
            const w: u16 = 58;
            const opt_rows: u16 = @intCast(state.form.option_count);
            const h: u16 = @min(win_h -| 2, 11 + opt_rows);
            return .{ .x = (win_w -| w) / 2, .y = (win_h -| h) / 2, .w = w, .h = h };
        },
        .delete_confirm => {
            const w: u16 = 52;
            const h: u16 = 5;
            return .{ .x = (win_w -| w) / 2, .y = (win_h -| h) / 2, .w = w, .h = h };
        },
        .pool_delete_confirm => {
            const w: u16 = 52;
            const h: u16 = 10;
            return .{ .x = (win_w -| w) / 2, .y = (win_h -| h) / 2, .w = w, .h = h };
        },
        .pool_save_confirm => {
            const w: u16 = 64;
            const h: u16 = 16;
            return .{ .x = (win_w -| w) / 2, .y = (win_h -| h) / 2, .w = w, .h = h };
        },
        .pool_server_edit => {
            const w: u16 = 48;
            const h: u16 = if (state.pool_form.err_len > 0) 8 else 7;
            return .{ .x = (win_w -| w) / 2, .y = (win_h -| h) / 2, .w = w, .h = h };
        },
        .pool_route_edit => {
            const w: u16 = 48;
            const h: u16 = if (state.pool_form.err_len > 0) 9 else 8;
            return .{ .x = (win_w -| w) / 2, .y = (win_h -| h) / 2, .w = w, .h = h };
        },
        .pool_option_edit => {
            const w: u16 = 48;
            const h: u16 = if (state.pool_form.err_len > 0) 9 else 8;
            return .{ .x = (win_w -| w) / 2, .y = (win_h -| h) / 2, .w = w, .h = h };
        },
        .pool_mac_class_edit => {
            const w = @max(58, @min(win_w * 3 / 4, win_w -| 6));
            const h = @max(14, @min(win_h * 3 / 4, win_h -| 4));
            return .{ .x = (win_w - w) / 2, .y = (win_h - h) / 2, .w = w, .h = h };
        },
        .pool_option_lookup => {
            const w: u16 = 40;
            const h: u16 = @min(win_h -| 2, 22);
            return .{ .x = (win_w -| w) / 2, .y = (win_h -| h) / 2, .w = w, .h = h };
        },
        .help => {
            const w: u16 = @min(60, @max(30, win_w -| 4));
            const h: u16 = @min(30, @max(10, win_h -| 2));
            return .{ .x = (win_w -| w) / 2, .y = (win_h -| h) / 2, .w = w, .h = h };
        },
        .res_option_edit => {
            const w: u16 = 48;
            const h: u16 = if (state.form.err_len > 0) 9 else 8;
            return .{ .x = (win_w -| w) / 2, .y = (win_h -| h) / 2, .w = w, .h = h };
        },
        .option_lookup => {
            const w: u16 = 40;
            const h: u16 = @min(win_h -| 2, 22);
            return .{ .x = (win_w -| w) / 2, .y = (win_h -| h) / 2, .w = w, .h = h };
        },
        .settings_confirm => {
            const w: u16 = 56;
            const warn_lines: u16 = if (state.settings_confirm_port_warn) 1 else 0;
            const h: u16 = 6 + state.settings_confirm_count + warn_lines;
            return .{ .x = (win_w -| w) / 2, .y = (win_h -| h) / 2, .w = w, .h = h };
        },
        .normal => return .{ .x = 0, .y = 0, .w = 0, .h = 0 },
    }
}

fn handlePoolDetailKey(server: *AdminServer, state: *TuiState, key: vaxis.Key) void {
    if (key.matches(vaxis.Key.escape, .{}) or key.matches('q', .{})) {
        state.mode = .normal;
    } else if (key.matches('e', .{}) and !server.cfg.admin_ssh.read_only) {
        // Transition to edit form for the same pool.
        state.pool_form = .{};
        populatePoolForm(&state.pool_form, &server.cfg.pools[state.pool_row]);
        state.pool_form.editing_index = state.pool_row;
        state.mode = .pool_form;
    } else if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{})) {
        state.pool_detail_scroll +|= 1;
    } else if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{})) {
        state.pool_detail_scroll -|= 1;
    }
}

// ---- Pool edit/new form ----

fn renderPoolForm(state: *TuiState, win: vaxis.Window, fa: std.mem.Allocator) !void {
    const form = &state.pool_form;
    // Size modal to ~80% of terminal, clamped to reasonable bounds.
    const BOX_W: u16 = @max(60, @min(win.width * 4 / 5, win.width -| 4));
    const BOX_H: u16 = @max(14, @min(win.height * 4 / 5, win.height -| 2));
    if (win.width < 40 or win.height < 10) return;
    const x = (win.width - BOX_W) / 2;
    const y = (win.height - BOX_H) / 2;
    const box = win.child(.{ .x_off = x, .y_off = y, .width = BOX_W, .height = BOX_H });
    box.fill(.{ .char = .{ .grapheme = " ", .width = 1 }, .style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } } });

    const bg: vaxis.Style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 160, 255 } }, .bg = bg.bg };
    drawBox(box, 0, 0, BOX_W, BOX_H, border_style);
    const section_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 80, 180, 255 } }, .bg = bg.bg, .bold = true };
    const label_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 160, 160, 190 } }, .bg = bg.bg };
    const field_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 200, 200, 200 } }, .bg = .{ .rgb = .{ 30, 30, 45 } } };
    const active_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 255, 255 } }, .bg = .{ .rgb = .{ 50, 80, 140 } } };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = bg.bg };
    const err_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 80, 80 } }, .bg = bg.bg };
    const close_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 80, 80 } }, .bg = bg.bg, .bold = true };

    const title_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 200, 80 } }, .bg = bg.bg, .bold = true };

    // Title (inside border) + [X] (on border).
    const title = if (form.isNew()) "  New Pool" else std.fmt.allocPrint(fa, "  Edit Pool: {s}", .{form.subnet_buf[0..form.subnet_len]}) catch "  Edit Pool";
    _ = box.print(&.{.{ .text = title, .style = title_style }}, .{ .col_offset = 1, .row_offset = 1, .wrap = .none });
    _ = box.print(&.{.{ .text = "[X]", .style = close_style }}, .{ .col_offset = BOX_W -| 4, .row_offset = 0, .wrap = .none });

    // Field rendering area: rows 2 .. BOX_H-3 (inside border, below title).
    const field_h = BOX_H - 4; // top border + title + hint + bottom border
    const LABEL_W: u16 = 19;
    const FIELD_W: u16 = BOX_W -| LABEL_W -| 3; // 1 left border + 2 right margin

    const opt_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 180, 200 } }, .bg = .{ .rgb = .{ 30, 30, 42 } } };

    // Compute the absolute row for the active field by walking pool_layout.
    // Each .section = 2 rows (blank + header), .field = 1 row,
    // .inline_section = 1 row ([+]) + N entry rows.
    var active_row: u16 = 0;
    var total_rows: u16 = 0;
    {
        var r: u16 = 0;
        var pos: u8 = 0;
        for (pool_layout) |item| {
            switch (item.kind) {
                .section => {
                    r += 2;
                },
                .field => {
                    if (pos == form.active_field) active_row = r;
                    r += 1;
                    pos += 1;
                },
                .inline_section => {
                    const count = form.inlineCount(item.inline_target.?);
                    if (pos == form.active_field) active_row = r;
                    r += 1; // [+] button
                    pos += 1;
                    for (0..count) |_| {
                        if (pos == form.active_field) active_row = r;
                        r += 1;
                        pos += 1;
                    }
                },
            }
        }
        total_rows = r;
    }

    // Target: center active field in the visible area.
    const half = field_h / 2;
    var scroll_row: u16 = if (active_row > half) active_row - half else 0;

    // Clamp bottom: ensure last field + 1 blank line fits.
    const max_scroll = if (total_rows + 1 > field_h) total_rows + 1 - field_h else 0;
    if (scroll_row > max_scroll) scroll_row = max_scroll;

    form.scroll_row = scroll_row;

    // ---- Render by walking pool_layout ----
    var abs_row: u16 = 0; // absolute row in the virtual content
    var draw_row: u16 = 2; // screen row (starts below border + title)
    var pos: u8 = 0; // navigable field index

    for (pool_layout) |item| {
        if (draw_row >= BOX_H - 2) break;
        switch (item.kind) {
            .section => {
                // Blank line.
                if (abs_row >= scroll_row and draw_row < BOX_H - 2) draw_row += 1;
                abs_row += 1;
                // Section header.
                if (abs_row >= scroll_row and draw_row < BOX_H - 2) {
                    const sec_text = std.fmt.allocPrint(fa, "  -- {s} --", .{item.label}) catch "";
                    _ = box.print(&.{.{ .text = sec_text, .style = section_style }}, .{ .col_offset = 1, .row_offset = draw_row, .wrap = .none });
                    draw_row += 1;
                }
                abs_row += 1;
            },
            .field => {
                const fi = item.field_idx.?;
                const is_active = pos == form.active_field;
                const is_bool = fi == 10;
                if (abs_row >= scroll_row and draw_row < BOX_H - 2) {
                    const meta = pool_field_meta[fi];
                    const style = if (is_active) active_style else field_style;
                    const val = poolFormFieldVal(form, fi);
                    const label_text = std.fmt.allocPrint(fa, "  {s:<17}", .{meta.label}) catch "";
                    _ = box.print(&.{.{ .text = label_text, .style = label_style }}, .{ .col_offset = 1, .row_offset = draw_row, .wrap = .none });

                    // Value field with horizontal scrolling for active field.
                    const fw = @as(usize, FIELD_W);
                    var vis_start: usize = 0;
                    var cursor_vis: usize = 0;
                    if (is_active and !is_bool) {
                        const cur = @min(form.cursor, val.len);
                        if (cur >= fw) {
                            vis_start = cur - fw + 1;
                        }
                        cursor_vis = cur - vis_start;
                    }
                    const vis_end = @min(val.len, vis_start + fw);
                    const vis_text = val[vis_start..vis_end];
                    const pad_len = fw - vis_text.len;
                    const padded = std.fmt.allocPrint(fa, "{s}{s}", .{ vis_text, spaces(fa, @intCast(pad_len)) catch "" }) catch vis_text;
                    _ = box.print(&.{.{ .text = padded, .style = style }}, .{ .col_offset = LABEL_W + 1, .row_offset = draw_row, .wrap = .none });

                    // Cursor block: show character under cursor with inverted colors.
                    if (is_active and !is_bool) {
                        const cursor_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 20, 20, 30 } }, .bg = .{ .rgb = .{ 100, 160, 255 } } };
                        const cursor_col = LABEL_W + 1 + @as(u16, @intCast(cursor_vis));
                        if (cursor_col < BOX_W -| 1) {
                            const cur_abs = vis_start + cursor_vis;
                            const ch: []const u8 = if (cur_abs < val.len) val[cur_abs..][0..1] else " ";
                            _ = box.print(&.{.{ .text = ch, .style = cursor_style }}, .{ .col_offset = cursor_col, .row_offset = draw_row, .wrap = .none });
                        }
                    }
                    draw_row += 1;
                }
                abs_row += 1;
                pos += 1;
            },
            .inline_section => {
                const target = item.inline_target.?;
                const count = form.inlineCount(target);
                const is_add_active = pos == form.active_field;

                // [+] Add button.
                if (abs_row >= scroll_row and draw_row < BOX_H - 2) {
                    const add_label = std.fmt.allocPrint(fa, "  {s:<17}", .{item.label}) catch "";
                    _ = box.print(&.{.{ .text = add_label, .style = label_style }}, .{ .col_offset = 1, .row_offset = draw_row, .wrap = .none });
                    const at_max = count >= PoolForm.inlineMax(target);
                    if (at_max) {
                        const max_text = std.fmt.allocPrint(fa, "(max {d})", .{PoolForm.inlineMax(target)}) catch "(max)";
                        const grey_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = .{ .rgb = .{ 30, 30, 45 } } };
                        _ = box.print(&.{.{ .text = max_text, .style = grey_style }}, .{ .col_offset = LABEL_W + 1, .row_offset = draw_row, .wrap = .none });
                    } else {
                        const add_fs = if (is_add_active) active_style else field_style;
                        _ = box.print(&.{.{ .text = "[+] Add ", .style = add_fs }}, .{ .col_offset = LABEL_W + 1, .row_offset = draw_row, .wrap = .none });
                    }
                    draw_row += 1;
                }
                abs_row += 1;
                pos += 1;

                // Inline entries.
                for (0..count) |ei| {
                    if (draw_row >= BOX_H - 2) break;
                    const is_entry_active = pos == form.active_field;
                    if (abs_row >= scroll_row and draw_row < BOX_H - 2) {
                        const line_text: []const u8 = switch (target) {
                            .domain_search => blk: {
                                const d = &form.domain_search[ei];
                                const t = d.buf[0..d.len];
                                break :blk if (t.len > 0) t else "...";
                            },
                            .dns => blk: {
                                const d = &form.dns_servers[ei];
                                break :blk if (d.len > 0) d.buf[0..d.len] else "...";
                            },
                            .wins => blk: {
                                const d = &form.wins_servers[ei];
                                break :blk if (d.len > 0) d.buf[0..d.len] else "...";
                            },
                            .ntp => blk: {
                                const d = &form.ntp_servers[ei];
                                break :blk if (d.len > 0) d.buf[0..d.len] else "...";
                            },
                            .log => blk: {
                                const d = &form.log_servers[ei];
                                break :blk if (d.len > 0) d.buf[0..d.len] else "...";
                            },
                            .tftp => blk: {
                                const d = &form.tftp_servers[ei];
                                break :blk if (d.len > 0) d.buf[0..d.len] else "...";
                            },
                            .routes => blk: {
                                const r = &form.routes[ei];
                                const dest = r.dest_buf[0..r.dest_len];
                                const router = r.router_buf[0..r.router_len];
                                break :blk std.fmt.allocPrint(fa, "{s} via {s}", .{
                                    if (dest.len > 0) dest else "...",
                                    if (router.len > 0) router else "...",
                                }) catch "";
                            },
                            .options => blk: {
                                // DHCP options render differently: label on left, value on right.
                                const o = &form.options[ei];
                                const code = o.code_buf[0..o.code_len];
                                const opt_label = std.fmt.allocPrint(fa, "  Option {s:>3}", .{if (code.len > 0) code else "?"}) catch "  Option   ?";
                                _ = box.print(&.{.{ .text = opt_label, .style = label_style }}, .{ .col_offset = 1, .row_offset = draw_row, .wrap = .none });
                                const val = o.value_buf[0..o.value_len];
                                break :blk if (val.len > 0) val else "";
                            },
                            .mac_classes => blk: {
                                // MAC classes render like options: name as label, match as value.
                                const mc = &form.mac_classes[ei];
                                const mc_name = mc.name_buf[0..mc.name_len];
                                const mc_label = std.fmt.allocPrint(fa, "  {s}", .{if (mc_name.len > 0) mc_name else "(unnamed)"}) catch "  (unnamed)";
                                _ = box.print(&.{.{ .text = mc_label, .style = label_style }}, .{ .col_offset = 1, .row_offset = draw_row, .wrap = .none });
                                const mc_match = mc.match_buf[0..mc.match_len];
                                break :blk if (mc_match.len > 0) mc_match else "...";
                            },
                        };
                        const os = if (is_entry_active) active_style else opt_style;
                        const opt_trunc = line_text[0..@min(line_text.len, FIELD_W)];
                        const opt_pad = FIELD_W -| @as(u16, @intCast(opt_trunc.len));
                        const opt_padded = try fa.alloc(u8, opt_pad);
                        @memset(opt_padded, ' ');
                        _ = box.print(&.{.{ .text = opt_trunc, .style = os }}, .{ .col_offset = LABEL_W + 1, .row_offset = draw_row, .wrap = .none });
                        _ = box.print(&.{.{ .text = opt_padded, .style = os }}, .{ .col_offset = LABEL_W + 1 + @as(u16, @intCast(opt_trunc.len)), .row_offset = draw_row, .wrap = .none });
                        draw_row += 1;
                    }
                    abs_row += 1;
                    pos += 1;
                }
            },
        }
    }

    // Hint + error (inside border).
    const af_info = form.activeFieldInfo(form.active_field);
    const is_add_btn = af_info.kind == .add_button;
    const is_inline_entry = af_info.kind == .inline_entry;
    // Check if active entry is in a reorderable section (DNS or TFTP).
    const is_reorderable = is_inline_entry and if (af_info.inline_target) |t| switch (t) {
        .dns => form.dns_servers_count > 1,
        .tftp => form.tftp_servers_count > 1,
        else => false,
    } else false;
    const hint_text: []const u8 = if (is_reorderable)
        "  Enter:edit  d:delete  +/-:reorder  Esc:cancel"
    else if (is_inline_entry)
        "  Enter:edit  d:delete  Tab:next  Esc:cancel"
    else if (is_add_btn)
        "  Enter:add  Tab:next  Shift-Tab:prev  Esc:cancel"
    else
        "  Tab:next  Shift-Tab:prev  Enter:review  Esc:cancel";
    _ = box.print(&.{.{ .text = hint_text, .style = hint_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 2, .wrap = .none });
    if (form.err_len > 0) {
        _ = box.print(&.{.{ .text = form.err_buf[0..form.err_len], .style = err_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 3, .wrap = .none });
    }
}

fn spaces(fa: std.mem.Allocator, n: u16) ![]const u8 {
    if (n == 0) return "";
    const buf = try fa.alloc(u8, n);
    @memset(buf, ' ');
    return buf;
}

/// Delete an entry from an inline entry array by shifting subsequent entries down.
fn deleteInlineEntry(comptime T: type, arr: []T, count: *usize, di: usize) void {
    if (di >= count.*) return;
    var i: usize = di;
    while (i + 1 < count.*) : (i += 1) {
        arr[i] = arr[i + 1];
    }
    count.* -= 1;
}

/// Open the shared server edit modal, optionally populating from an existing entry.
/// Uses serverEditEntryArr which respects server_edit_parent context.
fn openServerEdit(form: *PoolForm, state: *TuiState, target: ServerEditTarget, edit_index: ?usize) void {
    form.err_len = 0;
    form.server_edit_target = target;
    form.server_edit_index = edit_index;
    if (edit_index) |idx| {
        // Copy existing entry into edit buffer (uses parent-aware arrays).
        const entry_arr = serverEditEntryArr(form);
        const entry = &entry_arr[idx];
        @memcpy(form.server_edit_buf[0..entry.len], entry.buf[0..entry.len]);
        form.server_edit_len = entry.len;
        form.server_edit_cursor = entry.len;
    } else {
        form.server_edit_len = 0;
        form.server_edit_cursor = 0;
    }
    state.mode = .pool_server_edit;
}

fn handlePoolFormKey(server: *AdminServer, state: *TuiState, key: vaxis.Key) void {
    var form = &state.pool_form;
    form.err_len = 0;

    if (key.matches(vaxis.Key.escape, .{})) {
        state.mode = .normal;
        return;
    }

    // Determine what the active_field points to via pool_layout walk.
    const af_info = form.activeFieldInfo(form.active_field);

    // 'd' deletes selected inline entry.
    if (key.matches('d', .{}) and af_info.kind == .inline_entry) {
        const target = af_info.inline_target.?;
        const ei = af_info.entry_index;
        switch (target) {
            .domain_search => deleteInlineEntry(InlineEntry, &form.domain_search, &form.domain_search_count, ei),
            .dns => deleteInlineEntry(InlineEntry, &form.dns_servers, &form.dns_servers_count, ei),
            .log => deleteInlineEntry(InlineEntry, &form.log_servers, &form.log_servers_count, ei),
            .ntp => deleteInlineEntry(InlineEntry, &form.ntp_servers, &form.ntp_servers_count, ei),
            .wins => deleteInlineEntry(InlineEntry, &form.wins_servers, &form.wins_servers_count, ei),
            .tftp => deleteInlineEntry(InlineEntry, &form.tftp_servers, &form.tftp_servers_count, ei),
            .routes => {
                if (ei < form.route_count) {
                    var i: usize = ei;
                    while (i + 1 < form.route_count) : (i += 1) {
                        form.routes[i] = form.routes[i + 1];
                    }
                    form.route_count -= 1;
                }
            },
            .options => {
                if (ei < form.option_count) {
                    var i: usize = ei;
                    while (i + 1 < form.option_count) : (i += 1) {
                        form.options[i] = form.options[i + 1];
                    }
                    form.option_count -= 1;
                }
            },
            .mac_classes => {
                if (ei < form.mac_class_count) {
                    var i: usize = ei;
                    while (i + 1 < form.mac_class_count) : (i += 1) {
                        form.mac_classes[i] = form.mac_classes[i + 1];
                    }
                    form.mac_class_count -= 1;
                }
            },
        }
        if (form.active_field >= form.totalFields()) form.active_field -|= 1;
        return;
    }

    // '+' moves an entry down (DNS and TFTP only).
    if (key.matches('+', .{}) and af_info.kind == .inline_entry) {
        if (af_info.inline_target) |target| {
            const di = af_info.entry_index;
            switch (target) {
                .dns => {
                    if (di + 1 < form.dns_servers_count) {
                        const tmp = form.dns_servers[di];
                        form.dns_servers[di] = form.dns_servers[di + 1];
                        form.dns_servers[di + 1] = tmp;
                        form.active_field += 1;
                    }
                    return;
                },
                .tftp => {
                    if (di + 1 < form.tftp_servers_count) {
                        const tmp = form.tftp_servers[di];
                        form.tftp_servers[di] = form.tftp_servers[di + 1];
                        form.tftp_servers[di + 1] = tmp;
                        form.active_field += 1;
                    }
                    return;
                },
                else => {},
            }
        }
    }

    // '-' moves an entry up (DNS and TFTP only).
    if (key.matches('-', .{}) and af_info.kind == .inline_entry) {
        if (af_info.inline_target) |target| {
            const di = af_info.entry_index;
            switch (target) {
                .dns => {
                    if (di > 0) {
                        const tmp = form.dns_servers[di];
                        form.dns_servers[di] = form.dns_servers[di - 1];
                        form.dns_servers[di - 1] = tmp;
                        form.active_field -= 1;
                    }
                    return;
                },
                .tftp => {
                    if (di > 0) {
                        const tmp = form.tftp_servers[di];
                        form.tftp_servers[di] = form.tftp_servers[di - 1];
                        form.tftp_servers[di - 1] = tmp;
                        form.active_field -= 1;
                    }
                    return;
                },
                else => {},
            }
        }
    }

    if (key.matches(vaxis.Key.enter, .{})) {
        // [+] Add buttons.
        if (af_info.kind == .add_button) {
            const target = af_info.inline_target.?;
            form.server_edit_parent = .pool_form;
            switch (target) {
                .domain_search, .dns, .log, .ntp, .wins, .tftp => {
                    // Check capacity.
                    if (form.inlineCount(target) >= PoolForm.inlineMax(target)) return;
                    // Map InlineTarget to ServerEditTarget for the server edit modal.
                    const set: ServerEditTarget = switch (target) {
                        .domain_search => .domain_search,
                        .dns => .dns,
                        .log => .log,
                        .ntp => .ntp,
                        .wins => .wins,
                        .tftp => .tftp,
                        else => unreachable,
                    };
                    openServerEdit(form, state, set, null);
                    return;
                },
                .routes => {
                    form.err_len = 0;
                    form.route_edit_dest_len = 0;
                    form.route_edit_router_len = 0;
                    form.route_edit_field = 0;
                    form.route_edit_cursor = 0;
                    form.route_edit_index = null;
                    state.mode = .pool_route_edit;
                    return;
                },
                .options => {
                    form.err_len = 0;
                    form.opt_edit_code_len = 0;
                    form.opt_edit_value_len = 0;
                    form.opt_edit_field = 0;
                    form.opt_edit_cursor = 0;
                    form.opt_edit_index = null;
                    state.mode = .pool_option_edit;
                    return;
                },
                .mac_classes => {
                    if (form.mac_class_count >= 16) return;
                    form.err_len = 0;
                    form.mac_class_edit = .{};
                    form.mac_class_edit_index = null;
                    form.mac_class_edit_field = 0;
                    form.mac_class_edit_scroll = 0;
                    form.mac_class_edit_cursor = 0;
                    state.mode = .pool_mac_class_edit;
                    return;
                },
            }
        }
        // Existing inline entries -> edit.
        if (af_info.kind == .inline_entry) {
            const target = af_info.inline_target.?;
            const ei = af_info.entry_index;
            form.server_edit_parent = .pool_form;
            switch (target) {
                .domain_search, .dns, .log, .ntp, .wins, .tftp => {
                    const set: ServerEditTarget = switch (target) {
                        .domain_search => .domain_search,
                        .dns => .dns,
                        .log => .log,
                        .ntp => .ntp,
                        .wins => .wins,
                        .tftp => .tftp,
                        else => unreachable,
                    };
                    openServerEdit(form, state, set, ei);
                    return;
                },
                .routes => {
                    if (ei < form.route_count) {
                        form.err_len = 0;
                        const r = &form.routes[ei];
                        @memcpy(form.route_edit_dest[0..r.dest_len], r.dest_buf[0..r.dest_len]);
                        form.route_edit_dest_len = r.dest_len;
                        @memcpy(form.route_edit_router[0..r.router_len], r.router_buf[0..r.router_len]);
                        form.route_edit_router_len = r.router_len;
                        form.route_edit_field = 0;
                        form.route_edit_cursor = r.dest_len;
                        form.route_edit_index = ei;
                        state.mode = .pool_route_edit;
                    }
                    return;
                },
                .options => {
                    if (ei < form.option_count) {
                        form.err_len = 0;
                        const o = &form.options[ei];
                        @memcpy(form.opt_edit_code[0..o.code_len], o.code_buf[0..o.code_len]);
                        form.opt_edit_code_len = o.code_len;
                        @memcpy(form.opt_edit_value[0..o.value_len], o.value_buf[0..o.value_len]);
                        form.opt_edit_value_len = o.value_len;
                        form.opt_edit_field = 0;
                        form.opt_edit_cursor = o.code_len;
                        form.opt_edit_index = ei;
                        state.mode = .pool_option_edit;
                    }
                    return;
                },
                .mac_classes => {
                    if (ei < form.mac_class_count) {
                        form.err_len = 0;
                        form.mac_class_edit = form.mac_classes[ei];
                        form.mac_class_edit_index = ei;
                        form.mac_class_edit_field = 0;
                        form.mac_class_edit_scroll = 0;
                        form.mac_class_edit_cursor = form.mac_classes[ei].name_len;
                        state.mode = .pool_mac_class_edit;
                    }
                    return;
                },
            }
        }
        // Regular field: validate all fields before going to review.
        if (validatePoolForm(form)) |err_msg| {
            form.err_len = @min(err_msg.len, form.err_buf.len);
            @memcpy(form.err_buf[0..form.err_len], err_msg[0..form.err_len]);
            return;
        }
        form.err_len = 0;
        computePoolDiff(server, state);
        state.mode = .pool_save_confirm;
        return;
    }

    // Field navigation: Tab/Shift-Tab and Up/Down arrows.
    if (key.matches(vaxis.Key.tab, .{ .shift = true }) or key.matches(vaxis.Key.up, .{})) {
        if (form.active_field > 0) {
            form.active_field -= 1;
            form.cursor = activeFieldCursorLen(form, form.active_field);
        }
        return;
    }
    if (key.matches(vaxis.Key.tab, .{}) or key.matches(vaxis.Key.down, .{})) {
        if (form.active_field + 1 < form.totalFields()) {
            form.active_field += 1;
            form.cursor = activeFieldCursorLen(form, form.active_field);
        }
        return;
    }

    // Non-text fields: [+] buttons, inline entries.
    if (af_info.kind != .field) return;

    // dns_update_enable (pool_field_meta index 10): toggle on space or any printable
    if (af_info.field_idx == 10) {
        if (key.codepoint == ' ' or (key.codepoint >= 0x20 and key.codepoint <= 0x7E)) {
            form.dns_update_enable = !form.dns_update_enable;
        }
        return;
    }

    // Cursor movement within field (uses pool_field_meta index).
    const fi = af_info.field_idx;
    if (key.matches(vaxis.Key.left, .{})) {
        if (form.cursor > 0) form.cursor -= 1;
        return;
    }
    if (key.matches(vaxis.Key.right, .{})) {
        if (form.cursor < poolFormFieldLen(form, fi)) form.cursor += 1;
        return;
    }
    if (key.matches(vaxis.Key.home, .{})) {
        form.cursor = 0;
        return;
    }
    if (key.matches(vaxis.Key.end, .{})) {
        form.cursor = poolFormFieldLen(form, fi);
        return;
    }

    // Text editing at cursor position.
    if (key.matches(vaxis.Key.backspace, .{})) {
        if (poolFormFieldBuf(form, fi)) |fb| {
            if (form.cursor > 0 and fb.len.* > 0) {
                // Shift bytes after cursor left by one.
                const pos = form.cursor;
                if (pos < fb.len.*) {
                    std.mem.copyForwards(u8, fb.buf[pos - 1 ..], fb.buf[pos..fb.len.*]);
                }
                fb.len.* -= 1;
                form.cursor -= 1;
            }
        }
    } else if (key.matches(vaxis.Key.delete, .{})) {
        if (poolFormFieldBuf(form, fi)) |fb| {
            if (form.cursor < fb.len.*) {
                std.mem.copyForwards(u8, fb.buf[form.cursor..], fb.buf[form.cursor + 1 .. fb.len.*]);
                fb.len.* -= 1;
            }
        }
    } else if (key.codepoint >= 0x20 and key.codepoint <= 0x7E) {
        // Filter allowed characters based on field type.
        const field_idx = af_info.field_idx;
        const ch: u8 = @intCast(key.codepoint);
        const allowed = switch (field_idx) {
            0 => (ch >= '0' and ch <= '9') or ch == '.' or ch == '/', // Subnet (CIDR)
            1, 2, 3 => (ch >= '0' and ch <= '9') or ch == '.', // Router, Pool Start, Pool End (IP)
            4, 5 => ch >= '0' and ch <= '9', // Lease Time, MTU (integer)
            6 => (ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '.' or ch == '-' or ch == '_', // Domain Name
            7 => (ch >= '0' and ch <= '9') or ch == '-', // Time Offset (signed int)
            8 => (ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '.' or ch == '_' or ch == '-' or ch == '/', // Boot filename (file path)
            9 => ch >= 0x20 and ch <= 0x7E, // HTTP Boot URL (all printable)
            11 => (ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '.' or ch == '-' or ch == ':', // DNS Update Server (IP or domain)
            12 => (ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '.' or ch == '-' or ch == '_', // DNS Update Zone (domain)
            13 => (ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '_' or ch == '-', // Key Name
            14 => (ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '.' or ch == '_' or ch == '-' or ch == '/' or ch == '+' or ch == '=', // Key File (file path)
            else => true,
        };
        if (!allowed) return;
        if (poolFormFieldBuf(form, fi)) |fb| {
            if (fb.len.* < fb.buf.len) {
                // Shift bytes after cursor right by one, insert character.
                const pos = form.cursor;
                if (pos < fb.len.*) {
                    std.mem.copyBackwards(u8, fb.buf[pos + 1 ..], fb.buf[pos..fb.len.*]);
                }
                fb.buf[pos] = @intCast(key.codepoint);
                fb.len.* += 1;
                form.cursor += 1;
            }
        }
    }
}

fn poolFormFieldLen(form: *const PoolForm, idx: u8) usize {
    return (poolFormFieldVal(form, idx)).len;
}

/// Return the cursor-relevant text length for a layout-position active_field.
/// For regular fields, returns the field value length.  For [+] buttons and
/// inline entries, returns 0 (no cursor positioning needed).
fn activeFieldCursorLen(form: *const PoolForm, af: u8) usize {
    const info = form.activeFieldInfo(af);
    return switch (info.kind) {
        .field => poolFormFieldLen(form, info.field_idx),
        .add_button, .inline_entry => 0,
    };
}

fn validatePoolForm(form: *PoolForm) ?[]const u8 {
    // Subnet: must be valid CIDR.
    const subnet = form.subnet_buf[0..form.subnet_len];
    if (subnet.len == 0) return "Subnet is required (e.g. 192.168.1.0/24)";
    if (std.mem.indexOfScalar(u8, subnet, '/') == null) return "Subnet must include /prefix (e.g. 192.168.1.0/24)";
    const si = parseSubnet(subnet) orelse return "Invalid subnet format";

    // Router: must be valid IPv4 inside the subnet.
    const router = form.router_buf[0..form.router_len];
    if (router.len == 0) return "Router is required";
    const router_ip = config_mod.parseIpv4(router) catch return "Invalid router IP";
    {
        const r_int = std.mem.readInt(u32, &router_ip, .big);
        const s_int = std.mem.readInt(u32, &si.ip, .big);
        if (r_int & si.mask != s_int & si.mask) return "Router not in subnet";
    }

    // Pool start/end: optional, must be valid IPv4 inside the subnet, start <= end.
    var ps_int_opt: ?u32 = null;
    if (form.pool_start_len > 0) {
        const ps_ip = config_mod.parseIpv4(form.pool_start_buf[0..form.pool_start_len]) catch return "Invalid pool start IP";
        const ps_int = std.mem.readInt(u32, &ps_ip, .big);
        const s_int = std.mem.readInt(u32, &si.ip, .big);
        if (ps_int & si.mask != s_int & si.mask) return "Pool start not in subnet";
        ps_int_opt = ps_int;
    }
    if (form.pool_end_len > 0) {
        const pe_ip = config_mod.parseIpv4(form.pool_end_buf[0..form.pool_end_len]) catch return "Invalid pool end IP";
        const pe_int = std.mem.readInt(u32, &pe_ip, .big);
        const s_int = std.mem.readInt(u32, &si.ip, .big);
        if (pe_int & si.mask != s_int & si.mask) return "Pool end not in subnet";
        if (ps_int_opt) |ps| {
            if (ps > pe_int) return "Pool start must be <= pool end";
        }
    }

    // Domain name: auto-lowercase, validate characters.
    if (form.domain_name_len > 0) {
        for (form.domain_name_buf[0..form.domain_name_len]) |*ch| {
            if (ch.* >= 'A' and ch.* <= 'Z') ch.* = ch.* - 'A' + 'a';
        }
        const dn = form.domain_name_buf[0..form.domain_name_len];
        if (dn[0] < 'a' or dn[0] > 'z') return "Domain name must start with a letter";
        for (dn) |ch| {
            if (!((ch >= 'a' and ch <= 'z') or (ch >= '0' and ch <= '9') or ch == '.' or ch == '-' or ch == '_'))
                return "Domain name: only a-z, 0-9, dots, dashes, underscores";
        }
    }

    // Lease time: positive integer, max 2 weeks (1209600 seconds).
    const lt = form.lease_time_buf[0..form.lease_time_len];
    if (lt.len == 0) return "Lease time is required";
    const lt_val = std.fmt.parseInt(u32, lt, 10) catch return "Lease time must be a positive number";
    if (lt_val == 0) return "Lease time must be > 0";
    if (lt_val > 1_209_600) return "Lease time max is 1209600 (2 weeks)";

    // Time offset: optional signed integer.
    if (form.time_offset_len > 0) {
        _ = std.fmt.parseInt(i32, form.time_offset_buf[0..form.time_offset_len], 10) catch return "Time offset must be an integer";
    }

    // MTU: optional, 68-65535.
    if (form.mtu_len > 0) {
        const mtu_val = std.fmt.parseInt(u16, form.mtu_buf[0..form.mtu_len], 10) catch return "MTU must be a number (68-65535)";
        if (mtu_val < 68) return "MTU minimum is 68";
    }

    // Time servers (still comma-separated, hidden field).
    if (form.time_servers_len > 0) {
        if (validateIpList(form.time_servers_buf[0..form.time_servers_len])) |e| return e;
    }

    // HTTP Boot URL: optional. Scheme + valid domain + optional path.
    if (form.http_boot_url_len > 0) {
        const url = form.http_boot_url_buf[0..form.http_boot_url_len];
        const has_https = std.mem.startsWith(u8, url, "https://");
        const has_http = std.mem.startsWith(u8, url, "http://");
        if (!has_https and !has_http) return "URL must start with http:// or https://";
        const after_scheme = if (has_https) url[8..] else url[7..];
        if (after_scheme.len == 0) return "URL missing hostname";
        // Extract hostname (up to first / or end).
        const host_end = std.mem.indexOfScalar(u8, after_scheme, '/') orelse after_scheme.len;
        const hostname = after_scheme[0..host_end];
        if (hostname.len == 0) return "URL missing hostname";
        // Validate hostname as a domain: starts with alnum, a-z A-Z 0-9 . - only.
        if (!((hostname[0] >= 'a' and hostname[0] <= 'z') or (hostname[0] >= 'A' and hostname[0] <= 'Z') or
            (hostname[0] >= '0' and hostname[0] <= '9')))
            return "URL hostname must start with alphanumeric";
        for (hostname) |ch| {
            if (!((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or
                ch == '.' or ch == '-' or ch == ':'))
                return "URL hostname has invalid characters";
        }
        // Path portion: any printable ASCII is allowed.
        if (host_end < after_scheme.len) {
            for (after_scheme[host_end..]) |ch| {
                if (ch < 0x20 or ch > 0x7E) return "URL path has non-printable characters";
            }
        }
    }

    // TFTP Boot File (field 8): optional, validate as file path.
    if (form.boot_filename_len > 0) {
        for (form.boot_filename_buf[0..form.boot_filename_len]) |ch| {
            if (!((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or
                ch == '.' or ch == '_' or ch == '-' or ch == '/'))
                return "Boot file: only alphanumeric, . _ - / allowed";
        }
    }

    // DNS Update Server (field 11): optional, validate as IP or domain name.
    if (form.dns_update_server_len > 0) {
        const val = form.dns_update_server_buf[0..form.dns_update_server_len];
        const is_ip = if (config_mod.parseIpv4(val)) |_| true else |_| false;
        if (!is_ip and !isValidDomainName(val)) return "DNS update server: invalid IP or domain";
    }

    // DNS Update Zone (field 12): optional, validate as domain name.
    if (form.dns_update_zone_len > 0) {
        if (!isValidDomainName(form.dns_update_zone_buf[0..form.dns_update_zone_len]))
            return "DNS update zone: invalid domain name";
    }

    // DNS Update Key Name (field 13): optional, validate as key name.
    if (form.dns_update_key_name_len > 0) {
        const kn = form.dns_update_key_name_buf[0..form.dns_update_key_name_len];
        const first = kn[0];
        if (!((first >= 'a' and first <= 'z') or (first >= 'A' and first <= 'Z') or (first >= '0' and first <= '9')))
            return "Key name must start with alphanumeric";
        for (kn) |ch| {
            if (!((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '_' or ch == '-'))
                return "Key name: only alphanumeric, _ - allowed";
        }
    }

    // DNS Update Key File (field 14): optional, validate as file path.
    if (form.dns_update_key_file_len > 0) {
        for (form.dns_update_key_file_buf[0..form.dns_update_key_file_len]) |ch| {
            if (!((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or
                ch == '.' or ch == '_' or ch == '-' or ch == '/' or ch == '+' or ch == '='))
                return "Key file: only alphanumeric, . _ - / + = allowed";
        }
    }

    // Validate DHCP option codes (1-255).
    for (form.options[0..form.option_count]) |opt| {
        if (opt.code_len == 0) return "DHCP option code is required";
        const code = std.fmt.parseInt(u16, opt.code_buf[0..opt.code_len], 10) catch return "DHCP option code must be 1-255";
        if (code == 0 or code > 255) return "DHCP option code must be 1-255";
    }

    return null;
}

fn validateIpList(input: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, input, ", ");
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " ");
        if (trimmed.len == 0) continue;
        _ = config_mod.parseIpv4(trimmed) catch return "Invalid IP in list";
    }
    return null;
}

const SubnetInfo = struct { ip: [4]u8, prefix: u8, mask: u32 };

fn parseSubnet(s: []const u8) ?SubnetInfo {
    const slash = std.mem.indexOfScalar(u8, s, '/') orelse return null;
    const ip = config_mod.parseIpv4(s[0..slash]) catch return null;
    const prefix = std.fmt.parseInt(u8, s[slash + 1 ..], 10) catch return null;
    if (prefix == 0 or prefix > 32) return null;
    const mask: u32 = if (prefix == 32) 0xFFFFFFFF else ~(@as(u32, 0)) << @intCast(32 - prefix);
    return .{ .ip = ip, .prefix = prefix, .mask = mask };
}

// ---- Diff computation ----

fn computePoolDiff(server: *AdminServer, state: *TuiState) void {
    var confirm = &state.pool_confirm;
    confirm.* = .{};
    const form = &state.pool_form;

    if (form.isNew()) {
        confirm.is_new_pool = true;
        confirm.has_sync_break = true; // adding a pool always breaks sync (pool count changes)
        // For new pools, list all non-empty fields as changes.
        var fi: u8 = 0;
        while (fi < PoolForm.REGULAR_FIELD_COUNT) : (fi += 1) {
            const val = poolFormFieldVal(form, fi);
            if (val.len > 0) {
                if (confirm.change_count < confirm.changes.len) {
                    confirm.changes[confirm.change_count] = .{
                        .label = pool_field_meta[fi].label,
                        .old_val = "",
                        .new_val = val,
                        .kind = .drift,
                    };
                    confirm.change_count += 1;
                }
            }
        }
        if (form.domain_search_count > 0 and confirm.change_count < confirm.changes.len) {
            var buf: [32]u8 = undefined;
            const n = std.fmt.bufPrint(&buf, "{d} domain(s)", .{form.domain_search_count}) catch "domains";
            confirm.changes[confirm.change_count] = .{ .label = "Domains", .old_val = "", .new_val = n, .kind = .drift };
            confirm.change_count += 1;
        }
        const new_srv_counts = [_]struct { label: []const u8, count: usize }{
            .{ .label = "DNS Servers", .count = form.dns_servers_count },
            .{ .label = "Log Servers", .count = form.log_servers_count },
            .{ .label = "NTP Servers", .count = form.ntp_servers_count },
            .{ .label = "WINS Servers", .count = form.wins_servers_count },
            .{ .label = "TFTP Servers", .count = form.tftp_servers_count },
        };
        for (new_srv_counts) |sc| {
            if (sc.count > 0 and confirm.change_count < confirm.changes.len) {
                var sbuf: [32]u8 = undefined;
                const sn = std.fmt.bufPrint(&sbuf, "{d} server(s)", .{sc.count}) catch "servers";
                confirm.changes[confirm.change_count] = .{ .label = sc.label, .old_val = "", .new_val = sn, .kind = .drift };
                confirm.change_count += 1;
            }
        }
        if (form.route_count > 0 and confirm.change_count < confirm.changes.len) {
            var buf: [32]u8 = undefined;
            const n = std.fmt.bufPrint(&buf, "{d} route(s)", .{form.route_count}) catch "routes";
            confirm.changes[confirm.change_count] = .{ .label = "Static Routes", .old_val = "", .new_val = n, .kind = .sync_break };
            confirm.change_count += 1;
        }
        if (form.option_count > 0 and confirm.change_count < confirm.changes.len) {
            var buf: [32]u8 = undefined;
            const n = std.fmt.bufPrint(&buf, "{d} option(s)", .{form.option_count}) catch "options";
            confirm.changes[confirm.change_count] = .{ .label = "DHCP Options", .old_val = "", .new_val = n, .kind = .drift };
            confirm.change_count += 1;
        }
        for (0..form.mac_class_count) |mi| {
            if (confirm.change_count >= confirm.changes.len) break;
            const mc = &form.mac_classes[mi];
            confirm.changes[confirm.change_count] = .{
                .label = if (mc.name_len > 0) mc.name_buf[0..mc.name_len] else "MAC Class",
                .old_val = if (mc.match_len > 0) mc.match_buf[0..mc.match_len] else "?",
                .new_val = "(new)",
                .kind = .sync_break,
            };
            confirm.change_count += 1;
        }
        return;
    }

    // Editing existing pool.
    const pool = &server.cfg.pools[form.editing_index.?];
    var tmp_form: PoolForm = .{};
    populatePoolForm(&tmp_form, pool);

    // Sync-breaking: subnet(0), pool_start(2), pool_end(3), mtu(5)
    // MTU mismatch causes packet fragmentation; lease_time(4) is config drift only.
    const sync_fields = [_]u8{ 0, 2, 3, 5 };

    var fi: u8 = 0;
    while (fi < PoolForm.REGULAR_FIELD_COUNT) : (fi += 1) {
        const old_val = poolFormFieldVal(&tmp_form, fi);
        const new_val = poolFormFieldVal(form, fi);
        if (!std.mem.eql(u8, old_val, new_val)) {
            if (confirm.change_count < confirm.changes.len) {
                var is_sync = false;
                for (sync_fields) |sf| {
                    if (fi == sf) {
                        is_sync = true;
                        break;
                    }
                }
                if (is_sync) confirm.has_sync_break = true;
                confirm.changes[confirm.change_count] = .{
                    .label = pool_field_meta[fi].label,
                    .old_val = old_val,
                    .new_val = new_val,
                    .kind = if (is_sync) .sync_break else .drift,
                };
                confirm.change_count += 1;
            }
        }
        fi = fi; // suppress unused
    }

    // Compare domain search entries.
    if (form.domain_search_count != tmp_form.domain_search_count) {
        if (confirm.change_count < confirm.changes.len) {
            var old_buf: [32]u8 = undefined;
            var new_buf: [32]u8 = undefined;
            const old_n = std.fmt.bufPrint(&old_buf, "{d} domain(s)", .{tmp_form.domain_search_count}) catch "?";
            const new_n = std.fmt.bufPrint(&new_buf, "{d} domain(s)", .{form.domain_search_count}) catch "?";
            confirm.changes[confirm.change_count] = .{ .label = "Domains", .old_val = old_n, .new_val = new_n, .kind = .drift };
            confirm.change_count += 1;
        }
    } else {
        var ds_differ = false;
        for (0..form.domain_search_count) |di| {
            if (!std.mem.eql(u8, form.domain_search[di].buf[0..form.domain_search[di].len], tmp_form.domain_search[di].buf[0..tmp_form.domain_search[di].len])) {
                ds_differ = true;
                break;
            }
        }
        if (ds_differ and confirm.change_count < confirm.changes.len) {
            confirm.changes[confirm.change_count] = .{ .label = "Domains", .old_val = "(modified)", .new_val = "(modified)", .kind = .drift };
            confirm.change_count += 1;
        }
    }

    // Compare inline server entry arrays.
    const server_diffs = [_]struct { label: []const u8, count: usize, tmp_count: usize, entries: []const InlineEntry, tmp_entries: []const InlineEntry }{
        .{ .label = "DNS Servers", .count = form.dns_servers_count, .tmp_count = tmp_form.dns_servers_count, .entries = &form.dns_servers, .tmp_entries = &tmp_form.dns_servers },
        .{ .label = "Log Servers", .count = form.log_servers_count, .tmp_count = tmp_form.log_servers_count, .entries = &form.log_servers, .tmp_entries = &tmp_form.log_servers },
        .{ .label = "NTP Servers", .count = form.ntp_servers_count, .tmp_count = tmp_form.ntp_servers_count, .entries = &form.ntp_servers, .tmp_entries = &tmp_form.ntp_servers },
        .{ .label = "WINS Servers", .count = form.wins_servers_count, .tmp_count = tmp_form.wins_servers_count, .entries = &form.wins_servers, .tmp_entries = &tmp_form.wins_servers },
        .{ .label = "TFTP Servers", .count = form.tftp_servers_count, .tmp_count = tmp_form.tftp_servers_count, .entries = &form.tftp_servers, .tmp_entries = &tmp_form.tftp_servers },
    };
    for (server_diffs) |sd| {
        if (sd.count != sd.tmp_count) {
            if (confirm.change_count < confirm.changes.len) {
                confirm.changes[confirm.change_count] = .{ .label = sd.label, .old_val = "(changed)", .new_val = "(changed)", .kind = .drift };
                confirm.change_count += 1;
            }
        } else {
            var differ = false;
            for (0..sd.count) |ei| {
                if (!std.mem.eql(u8, sd.entries[ei].buf[0..sd.entries[ei].len], sd.tmp_entries[ei].buf[0..sd.tmp_entries[ei].len])) {
                    differ = true;
                    break;
                }
            }
            if (differ and confirm.change_count < confirm.changes.len) {
                confirm.changes[confirm.change_count] = .{ .label = sd.label, .old_val = "(modified)", .new_val = "(modified)", .kind = .drift };
                confirm.change_count += 1;
            }
        }
    }

    // Compare static routes.
    if (form.route_count != tmp_form.route_count) {
        if (confirm.change_count < confirm.changes.len) {
            var old_buf: [32]u8 = undefined;
            var new_buf: [32]u8 = undefined;
            const old_n = std.fmt.bufPrint(&old_buf, "{d} route(s)", .{tmp_form.route_count}) catch "?";
            const new_n = std.fmt.bufPrint(&new_buf, "{d} route(s)", .{form.route_count}) catch "?";
            confirm.has_sync_break = true;
            confirm.changes[confirm.change_count] = .{ .label = "Static Routes", .old_val = old_n, .new_val = new_n, .kind = .sync_break };
            confirm.change_count += 1;
        }
    } else {
        // Same count — check if any route changed.
        var routes_differ = false;
        for (0..form.route_count) |ri| {
            if (!std.mem.eql(u8, form.routes[ri].dest_buf[0..form.routes[ri].dest_len], tmp_form.routes[ri].dest_buf[0..tmp_form.routes[ri].dest_len]) or
                !std.mem.eql(u8, form.routes[ri].router_buf[0..form.routes[ri].router_len], tmp_form.routes[ri].router_buf[0..tmp_form.routes[ri].router_len]))
            {
                routes_differ = true;
                break;
            }
        }
        if (routes_differ and confirm.change_count < confirm.changes.len) {
            confirm.has_sync_break = true;
            confirm.changes[confirm.change_count] = .{ .label = "Static Routes", .old_val = "(modified)", .new_val = "(modified)", .kind = .sync_break };
            confirm.change_count += 1;
        }
    }

    // Compare DHCP options.
    if (form.option_count != tmp_form.option_count) {
        if (confirm.change_count < confirm.changes.len) {
            var old_buf: [32]u8 = undefined;
            var new_buf: [32]u8 = undefined;
            const old_n = std.fmt.bufPrint(&old_buf, "{d} option(s)", .{tmp_form.option_count}) catch "?";
            const new_n = std.fmt.bufPrint(&new_buf, "{d} option(s)", .{form.option_count}) catch "?";
            confirm.changes[confirm.change_count] = .{ .label = "DHCP Options", .old_val = old_n, .new_val = new_n, .kind = .drift };
            confirm.change_count += 1;
        }
    } else {
        var opts_differ = false;
        for (0..form.option_count) |oi| {
            if (!std.mem.eql(u8, form.options[oi].code_buf[0..form.options[oi].code_len], tmp_form.options[oi].code_buf[0..tmp_form.options[oi].code_len]) or
                !std.mem.eql(u8, form.options[oi].value_buf[0..form.options[oi].value_len], tmp_form.options[oi].value_buf[0..tmp_form.options[oi].value_len]))
            {
                opts_differ = true;
                break;
            }
        }
        if (opts_differ and confirm.change_count < confirm.changes.len) {
            confirm.changes[confirm.change_count] = .{ .label = "DHCP Options", .old_val = "(modified)", .new_val = "(modified)", .kind = .drift };
            confirm.change_count += 1;
        }
    }

    // Compare MAC classes — list each changed/added/removed class by name.
    {
        const max_mc = @max(form.mac_class_count, tmp_form.mac_class_count);
        for (0..max_mc) |mi| {
            if (confirm.change_count >= confirm.changes.len) break;
            if (mi >= form.mac_class_count) {
                // Removed class.
                const b = &tmp_form.mac_classes[mi];
                confirm.has_sync_break = true;
                confirm.changes[confirm.change_count] = .{
                    .label = if (b.name_len > 0) b.name_buf[0..b.name_len] else "MAC Class",
                    .old_val = if (b.match_len > 0) b.match_buf[0..b.match_len] else "?",
                    .new_val = "(removed)",
                    .kind = .sync_break,
                };
                confirm.change_count += 1;
                continue;
            }
            if (mi >= tmp_form.mac_class_count) {
                // Added class.
                const a = &form.mac_classes[mi];
                confirm.has_sync_break = true;
                confirm.changes[confirm.change_count] = .{
                    .label = if (a.name_len > 0) a.name_buf[0..a.name_len] else "MAC Class",
                    .old_val = if (a.match_len > 0) a.match_buf[0..a.match_len] else "?",
                    .new_val = "(new)",
                    .kind = .sync_break,
                };
                confirm.change_count += 1;
                continue;
            }
            // Both exist — check if changed.
            const a = &form.mac_classes[mi];
            const b = &tmp_form.mac_classes[mi];
            const changed = !std.mem.eql(u8, a.name_buf[0..a.name_len], b.name_buf[0..b.name_len]) or
                !std.mem.eql(u8, a.match_buf[0..a.match_len], b.match_buf[0..b.match_len]) or
                !std.mem.eql(u8, a.router_buf[0..a.router_len], b.router_buf[0..b.router_len]) or
                !std.mem.eql(u8, a.domain_name_buf[0..a.domain_name_len], b.domain_name_buf[0..b.domain_name_len]) or
                !std.mem.eql(u8, a.time_offset_buf[0..a.time_offset_len], b.time_offset_buf[0..b.time_offset_len]) or
                !std.mem.eql(u8, a.boot_filename_buf[0..a.boot_filename_len], b.boot_filename_buf[0..b.boot_filename_len]) or
                !std.mem.eql(u8, a.http_boot_url_buf[0..a.http_boot_url_len], b.http_boot_url_buf[0..b.http_boot_url_len]) or
                a.domain_search_count != b.domain_search_count or
                a.dns_servers_count != b.dns_servers_count or
                a.ntp_servers_count != b.ntp_servers_count or
                a.log_servers_count != b.log_servers_count or
                a.wins_servers_count != b.wins_servers_count or
                a.tftp_servers_count != b.tftp_servers_count or
                a.route_count != b.route_count or
                a.option_count != b.option_count;
            if (changed) {
                confirm.has_sync_break = true;
                confirm.changes[confirm.change_count] = .{
                    .label = if (a.name_len > 0) a.name_buf[0..a.name_len] else "MAC Class",
                    .old_val = if (a.match_len > 0) a.match_buf[0..a.match_len] else "?",
                    .new_val = "(modified)",
                    .kind = .sync_break,
                };
                confirm.change_count += 1;
            }
        }
    }
}

// ---- Confirm screen ----

fn renderPoolSaveConfirm(server: *AdminServer, state: *TuiState, win: vaxis.Window, fa: std.mem.Allocator) !void {
    const confirm = &state.pool_confirm;
    const has_sync = server.sync_mgr != null;

    const BOX_W: u16 = 64;
    const change_lines: u16 = @intCast(@min(confirm.change_count, 10));
    const warn_lines: u16 = if (confirm.has_sync_break and has_sync) 3 else 0;
    const BOX_H: u16 = 7 + change_lines + warn_lines; // border*2 + title + changes + warn + action + hints
    if (win.width < BOX_W or win.height < BOX_H) return;
    const x = (win.width - BOX_W) / 2;
    const y = (win.height - BOX_H) / 2;
    const box = win.child(.{ .x_off = x, .y_off = y, .width = BOX_W, .height = BOX_H });
    box.fill(.{ .char = .{ .grapheme = " ", .width = 1 }, .style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } } });

    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 160, 255 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    drawBox(box, 0, 0, BOX_W, BOX_H, border_style);
    const sync_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 80, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    const drift_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 220, 180, 60 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const warn_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 100, 100 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };

    const close_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 80, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    const title_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 200, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    const title = if (confirm.is_new_pool) " Confirm New Pool " else if (confirm.is_delete) " Confirm Delete " else " Confirm Changes ";
    _ = box.print(&.{.{ .text = title, .style = title_style }}, .{ .col_offset = 1, .row_offset = 1, .wrap = .none });
    _ = box.print(&.{.{ .text = "[X]", .style = close_style }}, .{ .col_offset = BOX_W -| 4, .row_offset = 0, .wrap = .none });

    if (confirm.change_count == 0 and !confirm.is_new_pool and !confirm.is_delete) {
        _ = box.print(&.{.{ .text = "  No changes detected.", .style = hint_style }}, .{ .col_offset = 1, .row_offset = 2, .wrap = .none });
        _ = box.print(&.{.{ .text = "  Esc: back", .style = hint_style }}, .{ .col_offset = 1, .row_offset = 3, .wrap = .none });
        return;
    }

    var row: u16 = 2;

    // Change list.
    var ci: usize = 0;
    while (ci < confirm.change_count and ci < 10) : (ci += 1) {
        const ch = &confirm.changes[ci];
        const prefix: []const u8 = if (ch.kind == .sync_break) "!! " else "   ";
        const style = if (ch.kind == .sync_break) sync_style else drift_style;
        const line = if (ch.old_val.len == 0)
            std.fmt.allocPrint(fa, "{s}{s}: {s}", .{ prefix, ch.label, ch.new_val }) catch ""
        else
            std.fmt.allocPrint(fa, "{s}{s}: {s} -> {s}", .{ prefix, ch.label, ch.old_val, ch.new_val }) catch "";
        _ = box.print(&.{.{ .text = line, .style = style }}, .{ .col_offset = 1, .row_offset = row, .wrap = .none });
        row += 1;
    }

    // Sync warning.
    if (confirm.has_sync_break and has_sync) {
        row += 1;
        _ = box.print(&.{.{ .text = "  !! This will break peer sync. All peers must", .style = warn_style }}, .{ .col_offset = 1, .row_offset = row, .wrap = .none });
        row += 1;
        _ = box.print(&.{.{ .text = "     be updated and restarted with matching config.", .style = warn_style }}, .{ .col_offset = 1, .row_offset = row, .wrap = .none });
        row += 1;
    }

    // Action + hint (inside border).
    _ = box.print(&.{.{ .text = "  Config will be saved and reloaded.", .style = hint_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 3, .wrap = .none });
    _ = box.print(&.{.{ .text = "  Y: confirm  N/Esc: cancel", .style = hint_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 2, .wrap = .none });
}

fn handlePoolSaveConfirmKey(server: *AdminServer, state: *TuiState, key: vaxis.Key) void {
    if (key.matches('y', .{}) or key.matches('Y', .{})) {
        if (state.pool_confirm.change_count == 0 and !state.pool_confirm.is_new_pool) {
            state.mode = .normal;
            return;
        }
        savePoolChanges(server, state);
        state.mode = .normal;
    } else if (key.matches('n', .{}) or key.matches('N', .{}) or key.matches(vaxis.Key.escape, .{})) {
        // Go back to form.
        state.mode = .pool_form;
    }
}

// ---- Save logic ----

fn savePoolChanges(server: *AdminServer, state: *TuiState) void {
    const form = &state.pool_form;

    // Track which pool index was modified (for FORCERENEW after save).
    var affected_pool_idx: ?usize = null;

    if (form.isNew()) {
        // Build a new PoolConfig from form fields.
        var pool = buildPoolFromForm(server.allocator, form) orelse return;
        pool.config_version = std.time.timestamp();
        config_write.addPool(server.allocator, server.cfg, pool) catch return;
        // New pool is appended at the end.
        affected_pool_idx = server.cfg.pools.len - 1;
    } else {
        // Update existing pool in place.
        const idx = form.editing_index.?;
        if (idx >= server.cfg.pools.len) return;
        applyFormToPool(server.allocator, &server.cfg.pools[idx], form);
        server.cfg.pools[idx].config_version = std.time.timestamp();
        affected_pool_idx = idx;
    }

    // Persist and reload.
    config_write.writeConfig(server.allocator, server.cfg, server.cfg_path) catch return;
    triggerReload(state);

    // Notify sync peers of pool config change.
    if (server.sync_mgr) |s| {
        if (affected_pool_idx) |idx| {
            if (idx < server.cfg.pools.len) {
                s.notifyPoolConfigUpdate(&server.cfg.pools[idx]);
            }
        }
    }

    // Send FORCERENEW to all active leases in the affected pool so clients
    // pick up the new settings (lease time, options, etc.).
    if (server.dhcp_server) |ds| {
        if (affected_pool_idx) |idx| {
            if (idx < server.cfg.pools.len) {
                ds.forceRenewPool(&server.cfg.pools[idx]);
            }
        }
    }
}

fn buildPoolFromForm(allocator: std.mem.Allocator, form: *const PoolForm) ?config_mod.PoolConfig {
    const subnet_info = parseSubnet(form.subnet_buf[0..form.subnet_len]) orelse return null;
    const lease_time = std.fmt.parseInt(u32, form.lease_time_buf[0..form.lease_time_len], 10) catch return null;

    // Build via helper that returns errors so errdefer can clean up on OOM.
    var pool = buildPoolFromFormInner(allocator, form, subnet_info, lease_time) catch return null;
    _ = &pool;
    return pool;
}

fn buildPoolFromFormInner(
    allocator: std.mem.Allocator,
    form: *const PoolForm,
    subnet_info: SubnetInfo,
    lease_time: u32,
) !config_mod.PoolConfig {
    var pool: config_mod.PoolConfig = undefined;
    pool.subnet = try allocator.dupe(u8, subnetIpStr(form));
    errdefer allocator.free(pool.subnet);
    pool.subnet_mask = subnet_info.mask;
    pool.prefix_len = subnet_info.prefix;
    pool.router = try allocator.dupe(u8, form.router_buf[0..form.router_len]);
    errdefer allocator.free(pool.router);
    pool.pool_start = try allocator.dupe(u8, form.pool_start_buf[0..form.pool_start_len]);
    errdefer allocator.free(pool.pool_start);
    pool.pool_end = try allocator.dupe(u8, form.pool_end_buf[0..form.pool_end_len]);
    errdefer allocator.free(pool.pool_end);
    pool.dns_servers = try dupeInlineEntries(allocator, &form.dns_servers, form.dns_servers_count);
    errdefer {
        for (pool.dns_servers) |s| allocator.free(s);
        allocator.free(pool.dns_servers);
    }
    pool.domain_name = try allocator.dupe(u8, form.domain_name_buf[0..form.domain_name_len]);
    errdefer allocator.free(pool.domain_name);
    pool.domain_search = try allocator.alloc([]const u8, form.domain_search_count);
    for (pool.domain_search) |*s| s.* = allocator.alloc(u8, 0) catch unreachable;
    errdefer {
        for (pool.domain_search) |s| allocator.free(s);
        allocator.free(pool.domain_search);
    }
    for (0..form.domain_search_count) |i| {
        pool.domain_search[i] = try allocator.dupe(u8, form.domain_search[i].buf[0..form.domain_search[i].len]);
    }
    pool.lease_time = lease_time;
    pool.time_offset = if (form.time_offset_len > 0) (std.fmt.parseInt(i32, form.time_offset_buf[0..form.time_offset_len], 10) catch null) else null;
    pool.time_servers = try splitCommaDupe(allocator, form.time_servers_buf[0..form.time_servers_len]);
    errdefer {
        for (pool.time_servers) |s| allocator.free(s);
        allocator.free(pool.time_servers);
    }
    pool.log_servers = try dupeInlineEntries(allocator, &form.log_servers, form.log_servers_count);
    errdefer {
        for (pool.log_servers) |s| allocator.free(s);
        allocator.free(pool.log_servers);
    }
    pool.ntp_servers = try dupeInlineEntries(allocator, &form.ntp_servers, form.ntp_servers_count);
    errdefer {
        for (pool.ntp_servers) |s| allocator.free(s);
        allocator.free(pool.ntp_servers);
    }
    pool.mtu = if (form.mtu_len > 0) (std.fmt.parseInt(u16, form.mtu_buf[0..form.mtu_len], 10) catch null) else null;
    pool.wins_servers = try dupeInlineEntries(allocator, &form.wins_servers, form.wins_servers_count);
    errdefer {
        for (pool.wins_servers) |s| allocator.free(s);
        allocator.free(pool.wins_servers);
    }
    pool.tftp_servers = try dupeInlineEntries(allocator, &form.tftp_servers, form.tftp_servers_count);
    errdefer {
        for (pool.tftp_servers) |s| allocator.free(s);
        allocator.free(pool.tftp_servers);
    }
    pool.boot_filename = try allocator.dupe(u8, form.boot_filename_buf[0..form.boot_filename_len]);
    errdefer allocator.free(pool.boot_filename);
    pool.http_boot_url = try allocator.dupe(u8, form.http_boot_url_buf[0..form.http_boot_url_len]);
    errdefer allocator.free(pool.http_boot_url);
    const dns_server = try allocator.dupe(u8, form.dns_update_server_buf[0..form.dns_update_server_len]);
    errdefer allocator.free(dns_server);
    const dns_zone = try allocator.dupe(u8, form.dns_update_zone_buf[0..form.dns_update_zone_len]);
    errdefer allocator.free(dns_zone);
    const dns_rev_zone = try allocator.dupe(u8, "");
    errdefer allocator.free(dns_rev_zone);
    const dns_key_name = try allocator.dupe(u8, form.dns_update_key_name_buf[0..form.dns_update_key_name_len]);
    errdefer allocator.free(dns_key_name);
    const dns_key_file = try allocator.dupe(u8, form.dns_update_key_file_buf[0..form.dns_update_key_file_len]);
    errdefer allocator.free(dns_key_file);
    pool.dns_update = .{
        .enable = form.dns_update_enable,
        .server = dns_server,
        .zone = dns_zone,
        .rev_zone = dns_rev_zone,
        .key_name = dns_key_name,
        .key_file = dns_key_file,
        .lease_time = lease_time,
    };
    pool.dhcp_options = std.StringHashMap([]const u8).init(allocator);
    // Copy DHCP options from form.
    for (0..form.option_count) |i| {
        const oe = &form.options[i];
        if (oe.code_len > 0) {
            const k = try allocator.dupe(u8, oe.code_buf[0..oe.code_len]);
            errdefer allocator.free(k);
            const v = try allocator.dupe(u8, oe.value_buf[0..oe.value_len]);
            errdefer allocator.free(v);
            try pool.dhcp_options.put(k, v);
        }
    }
    pool.reservations = try allocator.alloc(config_mod.Reservation, 0);
    // Build static routes from form.
    pool.static_routes = try buildRoutesFromForm(allocator, form);
    // Build MAC classes from form.
    pool.mac_classes = try buildMacClassesFromForm(allocator, form);
    return pool;
}

fn buildRoutesFromForm(allocator: std.mem.Allocator, form: *const PoolForm) ![]config_mod.StaticRoute {
    if (form.route_count == 0) return try allocator.alloc(config_mod.StaticRoute, 0);
    var routes = try allocator.alloc(config_mod.StaticRoute, form.route_count);
    for (0..form.route_count) |i| {
        const re = &form.routes[i];
        const dest_str = re.dest_buf[0..re.dest_len];
        const router_str = re.router_buf[0..re.router_len];
        const subnet_info = parseSubnet(dest_str) orelse {
            routes[i] = .{ .destination = .{ 0, 0, 0, 0 }, .prefix_len = 0, .router = .{ 0, 0, 0, 0 } };
            continue;
        };
        const rtr = config_mod.parseIpv4(router_str) catch [4]u8{ 0, 0, 0, 0 };
        routes[i] = .{ .destination = subnet_info.ip, .prefix_len = subnet_info.prefix, .router = rtr };
    }
    return routes;
}

/// Build an array of MacClass structs from the pool form's mac class entries.
fn buildMacClassesFromForm(allocator: std.mem.Allocator, form: *const PoolForm) ![]config_mod.MacClass {
    if (form.mac_class_count == 0) return try allocator.alloc(config_mod.MacClass, 0);
    var classes = try allocator.alloc(config_mod.MacClass, form.mac_class_count);
    var built: usize = 0;
    errdefer {
        for (classes[0..built]) |*mc| mc.deinit(allocator);
        allocator.free(classes);
    }
    for (0..form.mac_class_count) |i| {
        const mce = &form.mac_classes[i];
        var mcc: config_mod.MacClass = undefined;
        mcc.name = try allocator.dupe(u8, mce.name_buf[0..mce.name_len]);
        mcc.match = try allocator.dupe(u8, mce.match_buf[0..mce.match_len]);
        mcc.router = if (mce.router_len > 0) try allocator.dupe(u8, mce.router_buf[0..mce.router_len]) else null;
        mcc.domain_name = if (mce.domain_name_len > 0) try allocator.dupe(u8, mce.domain_name_buf[0..mce.domain_name_len]) else null;
        mcc.time_offset = if (mce.time_offset_len > 0) (std.fmt.parseInt(i32, mce.time_offset_buf[0..mce.time_offset_len], 10) catch null) else null;
        mcc.boot_filename = if (mce.boot_filename_len > 0) try allocator.dupe(u8, mce.boot_filename_buf[0..mce.boot_filename_len]) else null;
        mcc.http_boot_url = if (mce.http_boot_url_len > 0) try allocator.dupe(u8, mce.http_boot_url_buf[0..mce.http_boot_url_len]) else null;
        // Build inline entry arrays from entry structs.
        mcc.domain_search = try dupeInlineEntries(allocator, &mce.domain_search, mce.domain_search_count);
        mcc.dns_servers = try dupeInlineEntries(allocator, &mce.dns_servers, mce.dns_servers_count);
        mcc.ntp_servers = try dupeInlineEntries(allocator, &mce.ntp_servers, mce.ntp_servers_count);
        mcc.log_servers = try dupeInlineEntries(allocator, &mce.log_servers, mce.log_servers_count);
        mcc.wins_servers = try dupeInlineEntries(allocator, &mce.wins_servers, mce.wins_servers_count);
        mcc.tftp_servers = try dupeInlineEntries(allocator, &mce.tftp_servers, mce.tftp_servers_count);
        // Build static routes from route entries.
        mcc.static_routes = try buildRoutesFromEntries(allocator, &mce.routes, mce.route_count);
        // Build DHCP options from option entries.
        mcc.dhcp_options = try buildOptionsFromEntries(allocator, &mce.options, mce.option_count);
        classes[i] = mcc;
        built += 1;
    }
    return classes;
}

/// Build static routes from RouteEntry array.
fn buildRoutesFromEntries(allocator: std.mem.Allocator, entries: []const RouteEntry, count: usize) ![]config_mod.StaticRoute {
    if (count == 0) return try allocator.alloc(config_mod.StaticRoute, 0);
    var routes = try allocator.alloc(config_mod.StaticRoute, count);
    for (0..count) |i| {
        const re = &entries[i];
        const dest_str = re.dest_buf[0..re.dest_len];
        const si = parseSubnet(dest_str) orelse {
            routes[i] = .{ .destination = .{ 0, 0, 0, 0 }, .prefix_len = 0, .router = .{ 0, 0, 0, 0 } };
            continue;
        };
        const rtr = config_mod.parseIpv4(re.router_buf[0..re.router_len]) catch [4]u8{ 0, 0, 0, 0 };
        routes[i] = .{ .destination = si.ip, .prefix_len = si.prefix, .router = rtr };
    }
    return routes;
}

/// Build DHCP options from OptionEntry array.
fn buildOptionsFromEntries(allocator: std.mem.Allocator, entries: []const OptionEntry, count: usize) !std.StringHashMap([]const u8) {
    var opts = std.StringHashMap([]const u8).init(allocator);
    for (0..count) |i| {
        const oe = &entries[i];
        if (oe.code_len == 0) continue;
        const k = try allocator.dupe(u8, oe.code_buf[0..oe.code_len]);
        errdefer allocator.free(k);
        const v = try allocator.dupe(u8, oe.value_buf[0..oe.value_len]);
        errdefer allocator.free(v);
        try opts.put(k, v);
    }
    return opts;
}

/// Parse compact route text "dest1 via gw1, dest2 via gw2" into StaticRoute array.
fn parseMacClassRoutes(allocator: std.mem.Allocator, text: []const u8) ![]config_mod.StaticRoute {
    if (text.len == 0) return try allocator.alloc(config_mod.StaticRoute, 0);
    // Count routes by counting commas + 1.
    var count: usize = 1;
    for (text) |ch| {
        if (ch == ',') count += 1;
    }
    var routes = try allocator.alloc(config_mod.StaticRoute, count);
    var it = std.mem.splitScalar(u8, text, ',');
    var idx: usize = 0;
    while (it.next()) |part| {
        if (idx >= count) break;
        const trimmed = std.mem.trim(u8, part, " ");
        // Expect "dest/prefix via gateway" or "dest/prefix:gateway"
        const via_pos = std.mem.indexOf(u8, trimmed, " via ") orelse std.mem.indexOfScalar(u8, trimmed, ':');
        if (via_pos) |vp| {
            const dest_part = std.mem.trim(u8, trimmed[0..vp], " ");
            const sep_len: usize = if (std.mem.indexOf(u8, trimmed, " via ") != null) 5 else 1;
            const gw_part = std.mem.trim(u8, trimmed[vp + sep_len ..], " ");
            const si = parseSubnet(dest_part) orelse {
                routes[idx] = .{ .destination = .{ 0, 0, 0, 0 }, .prefix_len = 0, .router = .{ 0, 0, 0, 0 } };
                idx += 1;
                continue;
            };
            const rtr = config_mod.parseIpv4(gw_part) catch [4]u8{ 0, 0, 0, 0 };
            routes[idx] = .{ .destination = si.ip, .prefix_len = si.prefix, .router = rtr };
        } else {
            routes[idx] = .{ .destination = .{ 0, 0, 0, 0 }, .prefix_len = 0, .router = .{ 0, 0, 0, 0 } };
        }
        idx += 1;
    }
    // Trim to actual count (some might have been empty).
    if (idx < count) {
        const trimmed = try allocator.alloc(config_mod.StaticRoute, idx);
        @memcpy(trimmed, routes[0..idx]);
        allocator.free(routes);
        return trimmed;
    }
    return routes;
}

/// Parse compact options text "code=value, code=value" into StringHashMap.
fn parseMacClassOptions(allocator: std.mem.Allocator, text: []const u8) !std.StringHashMap([]const u8) {
    var opts = std.StringHashMap([]const u8).init(allocator);
    if (text.len == 0) return opts;
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " ");
        if (trimmed.len == 0) continue;
        const eq_pos = std.mem.indexOfScalar(u8, trimmed, '=') orelse continue;
        const code = std.mem.trim(u8, trimmed[0..eq_pos], " ");
        const value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " ");
        if (code.len == 0) continue;
        const k = try allocator.dupe(u8, code);
        errdefer allocator.free(k);
        const v = try allocator.dupe(u8, value);
        errdefer allocator.free(v);
        try opts.put(k, v);
    }
    return opts;
}

/// Allocate a string slice from inline entries.
fn dupeInlineEntries(allocator: std.mem.Allocator, entries: anytype, count: usize) ![][]const u8 {
    if (count == 0) return try allocator.alloc([]const u8, 0);
    const result = try allocator.alloc([]const u8, count);
    for (result) |*s| s.* = allocator.alloc(u8, 0) catch unreachable;
    errdefer {
        for (result) |s| allocator.free(s);
        allocator.free(result);
    }
    for (0..count) |i| {
        result[i] = try allocator.dupe(u8, entries[i].buf[0..entries[i].len]);
    }
    return result;
}

fn subnetIpStr(form: *const PoolForm) []const u8 {
    const subnet = form.subnet_buf[0..form.subnet_len];
    const slash = std.mem.indexOfScalar(u8, subnet, '/') orelse return subnet;
    return subnet[0..slash];
}

fn splitCommaDupe(allocator: std.mem.Allocator, input: []const u8) ![][]const u8 {
    if (input.len == 0) return try allocator.alloc([]const u8, 0);
    var count: usize = 0;
    var it = std.mem.splitSequence(u8, input, ",");
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " ");
        if (trimmed.len > 0) count += 1;
    }
    if (count == 0) return try allocator.alloc([]const u8, 0);
    const result = try allocator.alloc([]const u8, count);
    for (result) |*s| s.* = allocator.alloc(u8, 0) catch unreachable;
    errdefer {
        for (result) |s| allocator.free(s);
        allocator.free(result);
    }
    var it2 = std.mem.splitSequence(u8, input, ",");
    var i: usize = 0;
    while (it2.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " ");
        if (trimmed.len > 0) {
            result[i] = try allocator.dupe(u8, trimmed);
            i += 1;
        }
    }
    return result;
}

fn applyFormToPool(allocator: std.mem.Allocator, pool: *config_mod.PoolConfig, form: *const PoolForm) void {
    const subnet_info = parseSubnet(form.subnet_buf[0..form.subnet_len]) orelse return;
    const lease_time = std.fmt.parseInt(u32, form.lease_time_buf[0..form.lease_time_len], 10) catch return;

    // Free old strings and replace.
    replaceStr(allocator, &pool.subnet, subnetIpStr(form));
    pool.subnet_mask = subnet_info.mask;
    pool.prefix_len = subnet_info.prefix;
    replaceStr(allocator, &pool.router, form.router_buf[0..form.router_len]);
    replaceStr(allocator, &pool.pool_start, form.pool_start_buf[0..form.pool_start_len]);
    replaceStr(allocator, &pool.pool_end, form.pool_end_buf[0..form.pool_end_len]);
    replaceStr(allocator, &pool.domain_name, form.domain_name_buf[0..form.domain_name_len]);

    // Replace domain search entries.
    for (pool.domain_search) |s| allocator.free(s);
    allocator.free(pool.domain_search);
    pool.domain_search = allocator.alloc([]const u8, form.domain_search_count) catch (allocator.alloc([]const u8, 0) catch unreachable);
    for (0..form.domain_search_count) |i| {
        pool.domain_search[i] = allocator.dupe(u8, form.domain_search[i].buf[0..form.domain_search[i].len]) catch "";
    }

    replaceInlineEntries(allocator, &pool.dns_servers, &form.dns_servers, form.dns_servers_count);

    pool.lease_time = lease_time;
    pool.time_offset = if (form.time_offset_len > 0) (std.fmt.parseInt(i32, form.time_offset_buf[0..form.time_offset_len], 10) catch null) else null;

    replaceStrSlice(allocator, &pool.time_servers, form.time_servers_buf[0..form.time_servers_len]);
    replaceInlineEntries(allocator, &pool.log_servers, &form.log_servers, form.log_servers_count);
    replaceInlineEntries(allocator, &pool.ntp_servers, &form.ntp_servers, form.ntp_servers_count);

    pool.mtu = if (form.mtu_len > 0) (std.fmt.parseInt(u16, form.mtu_buf[0..form.mtu_len], 10) catch null) else null;
    replaceInlineEntries(allocator, &pool.wins_servers, &form.wins_servers, form.wins_servers_count);

    replaceInlineEntries(allocator, &pool.tftp_servers, &form.tftp_servers, form.tftp_servers_count);
    replaceStr(allocator, &pool.boot_filename, form.boot_filename_buf[0..form.boot_filename_len]);
    replaceStr(allocator, &pool.http_boot_url, form.http_boot_url_buf[0..form.http_boot_url_len]);

    pool.dns_update.enable = form.dns_update_enable;
    replaceStr(allocator, &pool.dns_update.server, form.dns_update_server_buf[0..form.dns_update_server_len]);
    replaceStr(allocator, &pool.dns_update.zone, form.dns_update_zone_buf[0..form.dns_update_zone_len]);
    replaceStr(allocator, &pool.dns_update.key_name, form.dns_update_key_name_buf[0..form.dns_update_key_name_len]);
    replaceStr(allocator, &pool.dns_update.key_file, form.dns_update_key_file_buf[0..form.dns_update_key_file_len]);
    pool.dns_update.lease_time = lease_time;

    // Replace static routes.
    allocator.free(pool.static_routes);
    pool.static_routes = buildRoutesFromForm(allocator, form) catch (allocator.alloc(config_mod.StaticRoute, 0) catch unreachable);

    // Replace DHCP options.
    var opt_it = pool.dhcp_options.iterator();
    while (opt_it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
        allocator.free(entry.value_ptr.*);
    }
    pool.dhcp_options.clearRetainingCapacity();
    for (0..form.option_count) |i| {
        const oe = &form.options[i];
        if (oe.code_len > 0) {
            const k = allocator.dupe(u8, oe.code_buf[0..oe.code_len]) catch continue;
            const v = allocator.dupe(u8, oe.value_buf[0..oe.value_len]) catch {
                allocator.free(k);
                continue;
            };
            pool.dhcp_options.put(k, v) catch {
                allocator.free(k);
                allocator.free(v);
                continue;
            };
        }
    }

    // Replace MAC classes.
    for (pool.mac_classes) |*mc| @constCast(mc).deinit(allocator);
    if (pool.mac_classes.len > 0) allocator.free(pool.mac_classes);
    pool.mac_classes = buildMacClassesFromForm(allocator, form) catch (allocator.alloc(config_mod.MacClass, 0) catch unreachable);
}

fn replaceStr(allocator: std.mem.Allocator, field: *[]const u8, new_val: []const u8) void {
    allocator.free(field.*);
    // field.* must always be allocator-owned (safe to free later).
    // Fall back to zero-length allocated slice on OOM (can't use a string literal).
    field.* = allocator.dupe(u8, new_val) catch (allocator.alloc(u8, 0) catch unreachable);
}

fn replaceInlineEntries(allocator: std.mem.Allocator, field: *[][]const u8, entries: anytype, count: usize) void {
    for (field.*) |s| allocator.free(s);
    allocator.free(field.*);
    field.* = allocator.alloc([]const u8, count) catch (allocator.alloc([]const u8, 0) catch unreachable);
    for (0..count) |i| {
        field.*[i] = allocator.dupe(u8, entries[i].buf[0..entries[i].len]) catch "";
    }
}

fn replaceStrSlice(allocator: std.mem.Allocator, field: *[][]const u8, csv: []const u8) void {
    for (field.*) |s| allocator.free(s);
    allocator.free(field.*);
    field.* = splitCommaDupe(allocator, csv) catch (allocator.alloc([]const u8, 0) catch unreachable);
}

fn triggerReload(state: *TuiState) void {
    const pid = std.os.linux.getpid();
    std.posix.kill(@intCast(pid), std.posix.SIG.HUP) catch {};
    state.reload_flash_until = std.time.timestamp() + 3;
}

// ---- Delete confirmation ----

fn renderPoolDeleteConfirm(server: *AdminServer, state: *TuiState, win: vaxis.Window, fa: std.mem.Allocator) !void {
    const idx = state.pool_del_index orelse return;
    if (idx >= server.cfg.pools.len) return;
    const pool = &server.cfg.pools[idx];
    const has_sync = server.sync_mgr != null;

    // Count active leases in this pool.
    var lease_count: usize = 0;
    const leases_allocated = server.store.listLeases() catch null;
    defer if (leases_allocated) |l| server.store.allocator.free(l);
    const leases: []const state_mod.Lease = leases_allocated orelse &.{};
    for (leases) |l| {
        if (isIpInPool(l.ip, pool)) lease_count += 1;
    }

    const BOX_W: u16 = 50;
    const BOX_H: u16 = if (has_sync) 10 else 8; // +2 for border
    if (win.width < BOX_W or win.height < BOX_H) return;
    const x = (win.width - BOX_W) / 2;
    const y = (win.height - BOX_H) / 2;
    const box = win.child(.{ .x_off = x, .y_off = y, .width = BOX_W, .height = BOX_H });
    box.fill(.{ .char = .{ .grapheme = " ", .width = 1 }, .style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } } });

    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 100, 100 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    drawBox(box, 0, 0, BOX_W, BOX_H, border_style);
    const text_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 220, 220, 220 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const warn_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 100, 100 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };

    const close_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 80, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    const title_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 200, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    _ = box.print(&.{.{ .text = " Delete Pool ", .style = title_style }}, .{ .col_offset = 1, .row_offset = 1, .wrap = .none });
    _ = box.print(&.{.{ .text = "[X]", .style = close_style }}, .{ .col_offset = BOX_W -| 4, .row_offset = 0, .wrap = .none });

    const label = std.fmt.allocPrint(fa, "  Delete pool {s}/{d}?", .{ pool.subnet, pool.prefix_len }) catch "  Delete pool?";
    _ = box.print(&.{.{ .text = label, .style = text_style }}, .{ .col_offset = 1, .row_offset = 2, .wrap = .none });

    var row: u16 = 3;
    if (lease_count > 0) {
        const lease_msg = std.fmt.allocPrint(fa, "  {d} active lease(s) in this pool.", .{lease_count}) catch "";
        _ = box.print(&.{.{ .text = lease_msg, .style = warn_style }}, .{ .col_offset = 1, .row_offset = row, .wrap = .none });
        row += 1;
    }
    if (has_sync) {
        _ = box.print(&.{.{ .text = "  !! This will break peer sync.", .style = warn_style }}, .{ .col_offset = 1, .row_offset = row, .wrap = .none });
        row += 1;
    }

    _ = box.print(&.{.{ .text = "  y: confirm  any other key: cancel", .style = hint_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 2, .wrap = .none });
}

fn handlePoolDeleteConfirmKey(server: *AdminServer, state: *TuiState, key: vaxis.Key) void {
    if (key.matches('y', .{})) {
        if (state.pool_del_index) |idx| {
            if (idx < server.cfg.pools.len) {
                config_write.removePool(server.allocator, server.cfg, idx);
                config_write.writeConfig(server.allocator, server.cfg, server.cfg_path) catch {};
                triggerReload(state);
                // Adjust selection.
                if (server.cfg.pools.len == 0) {
                    state.pool_row = 0;
                } else if (state.pool_row >= server.cfg.pools.len) {
                    state.pool_row = @intCast(server.cfg.pools.len - 1);
                }
            }
        }
    }
    state.mode = .normal;
}

// ---------------------------------------------------------------------------
// Settings tab
// ---------------------------------------------------------------------------

/// Known DHCP option codes for the lookup modal.
const KnownOption = struct { code: []const u8, name: []const u8 };
const known_dhcp_options = [_]KnownOption{
    .{ .code = "1", .name = "Subnet Mask" },
    .{ .code = "2", .name = "Time Offset" },
    .{ .code = "3", .name = "Router" },
    .{ .code = "4", .name = "Time Server (from NTP)" },
    .{ .code = "6", .name = "DNS Servers" },
    .{ .code = "7", .name = "Log Server" },
    .{ .code = "12", .name = "Hostname" },
    .{ .code = "15", .name = "Domain Name" },
    .{ .code = "33", .name = "Static Routes" },
    .{ .code = "42", .name = "NTP Servers" },
    .{ .code = "51", .name = "Lease Time" },
    .{ .code = "60", .name = "Vendor Class ID" },
    .{ .code = "66", .name = "TFTP Server" },
    .{ .code = "67", .name = "Boot Filename" },
    .{ .code = "119", .name = "Domain Search" },
    .{ .code = "121", .name = "Classless Static Routes" },
    .{ .code = "150", .name = "TFTP Server (Cisco)" },
    .{ .code = "252", .name = "WPAD URL" },
};

const SETTINGS_EDITABLE_COUNT: u8 = 7;

fn renderSettingsTab(server: *AdminServer, state: *TuiState, win: vaxis.Window, fa: std.mem.Allocator) !void {
    const cfg = server.cfg;
    const read_only = cfg.admin_ssh.read_only;

    // Dark background matching modals.
    win.fill(.{ .char = .{ .grapheme = " ", .width = 1 }, .style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } } });

    const bg: vaxis.Color = .{ .rgb = .{ 20, 20, 30 } };
    const sec_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 80, 180, 255 } }, .bg = bg, .bold = true };
    const lbl_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 140, 140, 170 } }, .bg = bg };
    const ro_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 120 } }, .bg = bg };
    const val_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 200, 200, 200 } }, .bg = .{ .rgb = .{ 30, 30, 45 } } };
    const sel_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 255, 255 } }, .bg = .{ .rgb = .{ 50, 80, 140 } } };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = bg };

    const dirty_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 200, 60 } }, .bg = bg, .bold = true };

    // Edit indices (visual order): 0=log_level, 1=random_alloc,
    // 2=collect, 3=http_enable, 4=http_port, 5=http_bind, 6=config_sync (if sync enabled)
    // For text fields (4, 5), always show the pending buffer when dirty; otherwise show the live config value.
    const edit_vals = [SETTINGS_EDITABLE_COUNT][]const u8{
        if (state.settings_dirty[0]) @tagName(state.settings_pending_log_level) else @tagName(cfg.log_level),
        if (state.settings_dirty[1]) (if (state.settings_pending_random_alloc) "true" else "false") else (if (cfg.pool_allocation_random) "true" else "false"),
        if (state.settings_dirty[2]) (if (state.settings_pending_collect) "true" else "false") else (if (cfg.metrics.collect) "true" else "false"),
        if (state.settings_dirty[3]) (if (state.settings_pending_http_enable) "true" else "false") else (if (cfg.metrics.http_enable) "true" else "false"),
        if (state.settings_pending_port_len > 0 or state.settings_dirty[4]) state.settings_pending_port_buf[0..state.settings_pending_port_len] else try std.fmt.allocPrint(fa, "{d}", .{cfg.metrics.http_port}),
        if (state.settings_pending_bind_len > 0 or state.settings_dirty[5]) state.settings_pending_bind_buf[0..state.settings_pending_bind_len] else cfg.metrics.http_bind,
        if (state.settings_dirty[6]) (if (state.settings_pending_config_sync) "true" else "false") else if (cfg.sync) |s| (if (s.config_sync) "true" else "false") else "false",
    };

    const LABEL_W: u16 = 24;

    // Build display lines: each is either a section header, read-only field, or editable field.
    const Line = struct { label: []const u8, value: []const u8, is_section: bool, edit_idx: ?u8 };
    var lines_buf: [30]Line = undefined;
    var lc: usize = 0;

    lines_buf[lc] = .{ .label = "", .value = "", .is_section = false, .edit_idx = null }; // blank line above General
    lc += 1;
    lines_buf[lc] = .{ .label = "-- General --", .value = "", .is_section = true, .edit_idx = null };
    lc += 1;
    lines_buf[lc] = .{ .label = "Listen Address", .value = cfg.listen_address, .is_section = false, .edit_idx = null };
    lc += 1;
    lines_buf[lc] = .{ .label = "State Directory", .value = cfg.state_dir, .is_section = false, .edit_idx = null };
    lc += 1;
    lines_buf[lc] = .{ .label = "Log Level", .value = edit_vals[0], .is_section = false, .edit_idx = 0 };
    lc += 1;
    lines_buf[lc] = .{ .label = "Random IP Allocation", .value = edit_vals[1], .is_section = false, .edit_idx = 1 };
    lc += 1;
    lines_buf[lc] = .{ .label = "Config Writable", .value = if (cfg.config_writable) "true" else "false", .is_section = false, .edit_idx = null };
    lc += 1;
    lines_buf[lc] = .{ .label = "", .value = "", .is_section = false, .edit_idx = null };
    lc += 1;
    lines_buf[lc] = .{ .label = "-- Metrics --", .value = "", .is_section = true, .edit_idx = null };
    lc += 1;
    lines_buf[lc] = .{ .label = "Collect", .value = edit_vals[2], .is_section = false, .edit_idx = 2 };
    lc += 1;
    lines_buf[lc] = .{ .label = "HTTP Enable", .value = edit_vals[3], .is_section = false, .edit_idx = 3 };
    lc += 1;
    lines_buf[lc] = .{ .label = "HTTP Port", .value = edit_vals[4], .is_section = false, .edit_idx = 4 };
    lc += 1;
    lines_buf[lc] = .{ .label = "HTTP Bind", .value = edit_vals[5], .is_section = false, .edit_idx = 5 };
    lc += 1;
    lines_buf[lc] = .{ .label = "", .value = "", .is_section = false, .edit_idx = null };
    lc += 1;
    lines_buf[lc] = .{ .label = "-- Admin SSH --", .value = "", .is_section = true, .edit_idx = null };
    lc += 1;
    lines_buf[lc] = .{ .label = "Enable", .value = if (cfg.admin_ssh.enable) "true" else "false", .is_section = false, .edit_idx = null };
    lc += 1;
    lines_buf[lc] = .{ .label = "Port", .value = try std.fmt.allocPrint(fa, "{d}", .{cfg.admin_ssh.port}), .is_section = false, .edit_idx = null };
    lc += 1;
    lines_buf[lc] = .{ .label = "Bind", .value = cfg.admin_ssh.bind, .is_section = false, .edit_idx = null };
    lc += 1;
    lines_buf[lc] = .{ .label = "Read Only", .value = if (cfg.admin_ssh.read_only) "true" else "false", .is_section = false, .edit_idx = null };
    lc += 1;

    // Sync section.
    if (cfg.sync) |s| {
        lines_buf[lc] = .{ .label = "", .value = "", .is_section = false, .edit_idx = null };
        lc += 1;
        lines_buf[lc] = .{ .label = "-- Sync --", .value = "", .is_section = true, .edit_idx = null };
        lc += 1;
        lines_buf[lc] = .{ .label = "Enable", .value = "true", .is_section = false, .edit_idx = null };
        lc += 1;
        lines_buf[lc] = .{ .label = "Config Sync", .value = edit_vals[6], .is_section = false, .edit_idx = 6 };
        lc += 1;
        lines_buf[lc] = .{ .label = "Group", .value = s.group_name, .is_section = false, .edit_idx = null };
        lc += 1;
        lines_buf[lc] = .{ .label = "Port", .value = try std.fmt.allocPrint(fa, "{d}", .{s.port}), .is_section = false, .edit_idx = null };
        lc += 1;
        if (s.multicast) |mc| {
            lines_buf[lc] = .{ .label = "Multicast", .value = mc, .is_section = false, .edit_idx = null };
            lc += 1;
        } else if (s.peers.len > 0) {
            lines_buf[lc] = .{ .label = "Peers", .value = try std.mem.join(fa, ", ", s.peers), .is_section = false, .edit_idx = null };
            lc += 1;
        }
    }

    // Populate the line-to-edit mapping for handleSettingsClick.
    state.settings_line_to_edit = [_]?u8{null} ** 40;
    state.settings_line_count = @intCast(lc);
    for (lines_buf[0..lc], 0..) |line, li| {
        if (li < state.settings_line_to_edit.len) {
            state.settings_line_to_edit[li] = line.edit_idx;
        }
    }

    // Auto-scroll only when a key action requested it (not on mouse wheel scroll).
    if (!read_only and state.settings_needs_scroll) {
        state.settings_needs_scroll = false;
        for (lines_buf[0..lc], 0..) |line, li| {
            if (line.edit_idx != null and line.edit_idx.? == state.settings_row) {
                const vr = @as(u16, @intCast(li));
                if (vr < state.settings_scroll +| 1) {
                    state.settings_scroll = vr -| 1;
                }
                if (vr + 2 > state.settings_scroll + win.height) {
                    state.settings_scroll = vr + 2 -| win.height;
                }
                break;
            }
        }
    }

    // Clamp scroll: allow one blank line past the last data line.
    const max_scroll: u16 = if (lc + 1 > win.height) @intCast(lc + 1 - win.height) else 0;
    if (state.settings_scroll > max_scroll) state.settings_scroll = max_scroll;

    // Render.
    const scroll = state.settings_scroll;
    for (lines_buf[0..lc], 0..) |line, li| {
        const vr = @as(u16, @intCast(li));
        if (vr < scroll or vr - scroll >= win.height) continue;
        const dr = vr - scroll;

        if (line.is_section) {
            _ = win.print(&.{.{ .text = try std.fmt.allocPrint(fa, "  {s}", .{line.label}), .style = sec_style }}, .{ .row_offset = dr, .wrap = .none });
            continue;
        }
        if (line.label.len == 0) continue; // blank separator

        const is_editable = line.edit_idx != null and !read_only;
        const is_selected = is_editable and line.edit_idx.? == state.settings_row;
        const is_text_field = is_selected and (line.edit_idx.? == 4 or line.edit_idx.? == 5);

        // Label with dirty indicator.
        const is_dirty = is_editable and state.settings_dirty[line.edit_idx.?];
        const dirty_mark: []const u8 = if (is_dirty) "*" else " ";
        _ = win.print(&.{.{ .text = dirty_mark, .style = dirty_style }}, .{ .col_offset = 1, .row_offset = dr, .wrap = .none });
        const label_text = try std.fmt.allocPrint(fa, " {s:<22}", .{line.label});
        _ = win.print(&.{.{ .text = label_text, .style = lbl_style }}, .{ .col_offset = 2, .row_offset = dr, .wrap = .none });

        // Value field.
        const field_w: u16 = if (win.width > LABEL_W + 4) win.width - LABEL_W - 4 else 10;
        const style = if (is_selected) sel_style else if (is_editable) val_style else ro_style;
        const val = line.value;
        const val_trunc = val[0..@min(val.len, field_w)];
        const pad_n = field_w -| @as(u16, @intCast(val_trunc.len));
        const padded = try fa.alloc(u8, pad_n);
        @memset(padded, ' ');
        _ = win.print(&.{.{ .text = val_trunc, .style = style }}, .{ .col_offset = LABEL_W + 2, .row_offset = dr, .wrap = .none });
        _ = win.print(&.{.{ .text = padded, .style = style }}, .{ .col_offset = LABEL_W + 2 + @as(u16, @intCast(val_trunc.len)), .row_offset = dr, .wrap = .none });

        // Cursor for text fields — always visible when selected (no editing mode needed).
        if (is_text_field) {
            const cursor_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 20, 20, 30 } }, .bg = .{ .rgb = .{ 100, 160, 255 } } };
            const cur = @min(state.settings_cursor, val.len);
            const ch: []const u8 = if (cur < val.len) val[cur..][0..1] else " ";
            _ = win.print(&.{.{ .text = ch, .style = cursor_style }}, .{ .col_offset = LABEL_W + 2 + @as(u16, @intCast(cur)), .row_offset = dr, .wrap = .none });
        }

        // Hint for selected editable field.
        if (is_selected and !is_text_field) {
            const hint = switch (line.edit_idx.?) {
                0 => "  \xe2\x86\x90/\xe2\x86\x92 or Space: cycle",
                1, 2, 3, 6 => "  Space: toggle",
                else => "",
            };
            _ = win.print(&.{.{ .text = hint, .style = hint_style }}, .{ .col_offset = LABEL_W + 2 + @as(u16, @intCast(val_trunc.len)) + pad_n, .row_offset = dr, .wrap = .none });
        }
    }

    // Validation error display.
    if (state.settings_err_len > 0) {
        const err_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 80, 80 } }, .bg = bg, .bold = true };
        const err_row: u16 = if (win.height > 1) win.height - 1 else 0;
        _ = win.print(&.{.{ .text = state.settings_err_buf[0..state.settings_err_len], .style = err_style }}, .{ .col_offset = 2, .row_offset = err_row, .wrap = .none });
    }
}

fn handleSettingsKey(server: *AdminServer, state: *TuiState, key: vaxis.Key) void {
    const cfg = server.cfg;
    const read_only = cfg.admin_ssh.read_only;

    // Read-only: only scroll.
    if (read_only) {
        if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{})) state.settings_scroll +|= 1;
        if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{})) state.settings_scroll -|= 1;
        return;
    }

    // Any key interaction should ensure the selected field is visible.
    state.settings_needs_scroll = true;
    // Clear validation error on any key.
    state.settings_err_len = 0;

    const is_text_field = (state.settings_row == 4 or state.settings_row == 5);
    // Max editable index: 6 (config_sync) only if sync is configured, otherwise 5 (http_bind).
    const max_edit: u8 = if (cfg.sync != null) 6 else 5;

    // Text field: handle typing, backspace, cursor movement directly.
    if (is_text_field) {
        // Ensure the pending buffer is initialized from live config if not yet touched.
        settingsInitPendingBuf(state, cfg);

        if (key.matches(vaxis.Key.backspace, .{})) {
            settingsTextBackspace(state);
            settingsMarkTextDirty(state, cfg);
            return;
        }
        if (key.matches(vaxis.Key.home, .{})) {
            state.settings_cursor = 0;
            return;
        }
        if (key.matches(vaxis.Key.end, .{})) {
            state.settings_cursor = settingsTextLen(state);
            return;
        }
        // Left/right on text fields: move cursor (not toggle/cycle).
        if (key.matches(vaxis.Key.left, .{})) {
            if (state.settings_cursor > 0) state.settings_cursor -= 1;
            return;
        }
        if (key.matches(vaxis.Key.right, .{})) {
            if (state.settings_cursor < settingsTextLen(state)) state.settings_cursor += 1;
            return;
        }
        // Printable ASCII: insert at cursor with character filtering.
        if (key.codepoint >= 0x20 and key.codepoint <= 0x7E and
            !key.matches(vaxis.Key.enter, .{}) and !key.matches(' ', .{}))
        {
            const ch: u8 = @intCast(key.codepoint);
            const allowed = switch (state.settings_row) {
                4 => ch >= '0' and ch <= '9', // Port (integer)
                5 => (ch >= '0' and ch <= '9') or ch == '.', // Bind address (IP)
                else => true,
            };
            if (!allowed) return;
            settingsTextInsert(state, ch);
            settingsMarkTextDirty(state, cfg);
            return;
        }
    }

    // Navigation and toggle/cycle keys (shared between all field types).
    if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{}) or key.matches(vaxis.Key.tab, .{})) {
        const old_row = state.settings_row;
        if (state.settings_row + 1 <= max_edit) state.settings_row += 1;
        if (state.settings_row != old_row) settingsOnRowChange(state, cfg);
    } else if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{}) or key.matches(vaxis.Key.tab, .{ .shift = true })) {
        const old_row = state.settings_row;
        state.settings_row -|= 1;
        if (state.settings_row != old_row) settingsOnRowChange(state, cfg);
    } else if (key.matches(' ', .{})) {
        // Space: toggle boolean fields, cycle log level.
        switch (state.settings_row) {
            0 => settingsCycleLogLevel(state, cfg, false),
            1 => {
                const cur = if (state.settings_dirty[1]) state.settings_pending_random_alloc else cfg.pool_allocation_random;
                state.settings_pending_random_alloc = !cur;
                state.settings_dirty[1] = (state.settings_pending_random_alloc != cfg.pool_allocation_random);
            },
            2 => {
                const cur = if (state.settings_dirty[2]) state.settings_pending_collect else cfg.metrics.collect;
                state.settings_pending_collect = !cur;
                state.settings_dirty[2] = (state.settings_pending_collect != cfg.metrics.collect);
            },
            3 => {
                const cur = if (state.settings_dirty[3]) state.settings_pending_http_enable else cfg.metrics.http_enable;
                state.settings_pending_http_enable = !cur;
                state.settings_dirty[3] = (state.settings_pending_http_enable != cfg.metrics.http_enable);
            },
            6 => {
                // config_sync toggle (only reachable when sync is configured)
                if (cfg.sync) |s| {
                    const cur = if (state.settings_dirty[6]) state.settings_pending_config_sync else s.config_sync;
                    state.settings_pending_config_sync = !cur;
                    state.settings_dirty[6] = (state.settings_pending_config_sync != s.config_sync);
                }
            },
            else => {},
        }
    } else if (!is_text_field and (key.matches(vaxis.Key.left, .{}) or key.matches(vaxis.Key.right, .{}))) {
        // Left/right on non-text fields: cycle log level.
        if (state.settings_row == 0) {
            settingsCycleLogLevel(state, cfg, key.matches(vaxis.Key.left, .{}));
        }
    } else if (key.matches(vaxis.Key.enter, .{})) {
        // Validate text fields, then show confirmation diff if any fields are dirty.
        if (!settingsValidate(state, cfg)) return;
        var any_dirty = false;
        for (state.settings_dirty) |d| {
            if (d) {
                any_dirty = true;
                break;
            }
        }
        if (!any_dirty) return;
        // Build confirmation diff and switch to settings_confirm mode.
        settingsBuildConfirm(state, cfg);
        state.mode = .settings_confirm;
    } else if (key.matches(vaxis.Key.escape, .{})) {
        // Discard all pending changes.
        state.settings_dirty = [_]bool{false} ** SETTINGS_EDITABLE_COUNT;
        state.settings_pending_port_len = 0;
        state.settings_pending_bind_len = 0;
        state.settings_cursor = 0;
        state.settings_err_len = 0;
    }
}

/// Cycle log level forward or backward.
fn settingsCycleLogLevel(state: *TuiState, cfg: *config_mod.Config, backward: bool) void {
    const levels = [_]config_mod.LogLevel{ .err, .warn, .info, .verbose, .debug };
    const cur = if (state.settings_dirty[0]) state.settings_pending_log_level else cfg.log_level;
    var idx: usize = 0;
    for (levels, 0..) |l, i| {
        if (l == cur) {
            idx = i;
            break;
        }
    }
    if (backward) {
        idx = if (idx == 0) levels.len - 1 else idx - 1;
    } else {
        idx = (idx + 1) % levels.len;
    }
    state.settings_pending_log_level = levels[idx];
    state.settings_dirty[0] = (levels[idx] != cfg.log_level);
}

/// Get the length of the currently active text field's pending buffer.
fn settingsTextLen(state: *const TuiState) usize {
    return if (state.settings_row == 4) state.settings_pending_port_len else state.settings_pending_bind_len;
}

/// Initialize the pending buffer for the current text field from the live config,
/// if it hasn't been touched yet (not dirty and pending len is 0).
fn settingsInitPendingBuf(state: *TuiState, cfg: *const config_mod.Config) void {
    if (state.settings_row == 4) {
        if (!state.settings_dirty[4] and state.settings_pending_port_len == 0) {
            const n = (std.fmt.bufPrint(&state.settings_pending_port_buf, "{d}", .{cfg.metrics.http_port}) catch "").len;
            state.settings_pending_port_len = n;
            state.settings_cursor = n;
        }
    } else if (state.settings_row == 5) {
        if (!state.settings_dirty[5] and state.settings_pending_bind_len == 0) {
            const src = cfg.metrics.http_bind;
            const n = @min(src.len, state.settings_pending_bind_buf.len);
            @memcpy(state.settings_pending_bind_buf[0..n], src[0..n]);
            state.settings_pending_bind_len = n;
            state.settings_cursor = n;
        }
    }
}

/// When the selected row changes to a text field, initialize its pending buffer
/// and set the cursor to the end.
fn settingsOnRowChange(state: *TuiState, cfg: *const config_mod.Config) void {
    if (state.settings_row == 4 or state.settings_row == 5) {
        settingsInitPendingBuf(state, cfg);
        state.settings_cursor = settingsTextLen(state);
    }
}

/// Backspace in the current text field's pending buffer.
fn settingsTextBackspace(state: *TuiState) void {
    if (state.settings_row == 4) {
        if (state.settings_cursor > 0 and state.settings_pending_port_len > 0) {
            const pos = state.settings_cursor;
            if (pos < state.settings_pending_port_len) {
                std.mem.copyForwards(u8, state.settings_pending_port_buf[pos - 1 ..], state.settings_pending_port_buf[pos..state.settings_pending_port_len]);
            }
            state.settings_pending_port_len -= 1;
            state.settings_cursor -= 1;
        }
    } else if (state.settings_row == 5) {
        if (state.settings_cursor > 0 and state.settings_pending_bind_len > 0) {
            const pos = state.settings_cursor;
            if (pos < state.settings_pending_bind_len) {
                std.mem.copyForwards(u8, state.settings_pending_bind_buf[pos - 1 ..], state.settings_pending_bind_buf[pos..state.settings_pending_bind_len]);
            }
            state.settings_pending_bind_len -= 1;
            state.settings_cursor -= 1;
        }
    }
}

/// Insert a character at the cursor in the current text field's pending buffer.
fn settingsTextInsert(state: *TuiState, ch: u8) void {
    if (state.settings_row == 4) {
        if (state.settings_pending_port_len < state.settings_pending_port_buf.len) {
            const pos = state.settings_cursor;
            if (pos < state.settings_pending_port_len) {
                std.mem.copyBackwards(u8, state.settings_pending_port_buf[pos + 1 ..], state.settings_pending_port_buf[pos..state.settings_pending_port_len]);
            }
            state.settings_pending_port_buf[pos] = ch;
            state.settings_pending_port_len += 1;
            state.settings_cursor += 1;
        }
    } else if (state.settings_row == 5) {
        if (state.settings_pending_bind_len < state.settings_pending_bind_buf.len) {
            const pos = state.settings_cursor;
            if (pos < state.settings_pending_bind_len) {
                std.mem.copyBackwards(u8, state.settings_pending_bind_buf[pos + 1 ..], state.settings_pending_bind_buf[pos..state.settings_pending_bind_len]);
            }
            state.settings_pending_bind_buf[pos] = ch;
            state.settings_pending_bind_len += 1;
            state.settings_cursor += 1;
        }
    }
}

/// Compare the pending text field value against live config and set/clear dirty flag.
fn settingsMarkTextDirty(state: *TuiState, cfg: *const config_mod.Config) void {
    if (state.settings_row == 4) {
        var live_buf: [6]u8 = undefined;
        const live = std.fmt.bufPrint(&live_buf, "{d}", .{cfg.metrics.http_port}) catch "";
        state.settings_dirty[4] = !std.mem.eql(u8, state.settings_pending_port_buf[0..state.settings_pending_port_len], live);
    } else if (state.settings_row == 5) {
        state.settings_dirty[5] = !std.mem.eql(u8, state.settings_pending_bind_buf[0..state.settings_pending_bind_len], cfg.metrics.http_bind);
    }
}

/// Validate text fields. Returns true if valid, false if not (sets error message).
fn settingsValidate(state: *TuiState, cfg: *const config_mod.Config) bool {
    _ = cfg;
    // Validate port (field 4) if dirty.
    if (state.settings_dirty[4]) {
        const port_str = state.settings_pending_port_buf[0..state.settings_pending_port_len];
        const port_val = std.fmt.parseInt(u16, port_str, 10) catch {
            const msg = "Invalid port: must be a number 1-65535";
            @memcpy(state.settings_err_buf[0..msg.len], msg);
            state.settings_err_len = msg.len;
            return false;
        };
        if (port_val == 0) {
            const msg = "Invalid port: must be a number 1-65535";
            @memcpy(state.settings_err_buf[0..msg.len], msg);
            state.settings_err_len = msg.len;
            return false;
        }
    }
    // Validate bind address (field 5) if dirty.
    if (state.settings_dirty[5]) {
        _ = config_mod.parseIpv4(state.settings_pending_bind_buf[0..state.settings_pending_bind_len]) catch {
            const msg = "Invalid bind address: must be a valid IPv4 address";
            const n = @min(msg.len, state.settings_err_buf.len);
            @memcpy(state.settings_err_buf[0..n], msg[0..n]);
            state.settings_err_len = n;
            return false;
        };
    }
    return true;
}

/// Build the confirmation diff text into settings_confirm_buf.
fn settingsBuildConfirm(state: *TuiState, cfg: *const config_mod.Config) void {
    var buf: []u8 = &state.settings_confirm_buf;
    var pos: usize = 0;
    var count: u8 = 0;
    var port_warn = false;

    if (state.settings_dirty[0]) {
        const line = std.fmt.bufPrint(buf[pos..], "Log Level: {s} -> {s}\n", .{
            @tagName(cfg.log_level), @tagName(state.settings_pending_log_level),
        }) catch "";
        pos += line.len;
        count += 1;
    }
    if (state.settings_dirty[1]) {
        const old = if (cfg.pool_allocation_random) "true" else "false";
        const new = if (state.settings_pending_random_alloc) "true" else "false";
        const line = std.fmt.bufPrint(buf[pos..], "Random IP Allocation: {s} -> {s}\n", .{ old, new }) catch "";
        pos += line.len;
        count += 1;
    }
    if (state.settings_dirty[2]) {
        const old = if (cfg.metrics.collect) "true" else "false";
        const new = if (state.settings_pending_collect) "true" else "false";
        const line = std.fmt.bufPrint(buf[pos..], "Metrics Collect: {s} -> {s}\n", .{ old, new }) catch "";
        pos += line.len;
        count += 1;
    }
    if (state.settings_dirty[3]) {
        const old = if (cfg.metrics.http_enable) "true" else "false";
        const new = if (state.settings_pending_http_enable) "true" else "false";
        const line = std.fmt.bufPrint(buf[pos..], "HTTP Enable: {s} -> {s}\n", .{ old, new }) catch "";
        pos += line.len;
        count += 1;
    }
    if (state.settings_dirty[4]) {
        const port_str = state.settings_pending_port_buf[0..state.settings_pending_port_len];
        var old_buf: [6]u8 = undefined;
        const old = std.fmt.bufPrint(&old_buf, "{d}", .{cfg.metrics.http_port}) catch "";
        const line = std.fmt.bufPrint(buf[pos..], "HTTP Port: {s} -> {s}\n", .{ old, port_str }) catch "";
        pos += line.len;
        count += 1;
        // Check if new port < 1024.
        const port_val = std.fmt.parseInt(u16, port_str, 10) catch 0;
        if (port_val > 0 and port_val < 1024) port_warn = true;
    }
    if (state.settings_dirty[5]) {
        const bind_str = state.settings_pending_bind_buf[0..state.settings_pending_bind_len];
        const line = std.fmt.bufPrint(buf[pos..], "HTTP Bind: {s} -> {s}\n", .{ cfg.metrics.http_bind, bind_str }) catch "";
        pos += line.len;
        count += 1;
    }
    if (state.settings_dirty[6]) {
        if (cfg.sync) |s| {
            const old = if (s.config_sync) "true" else "false";
            const new = if (state.settings_pending_config_sync) "true" else "false";
            const line = std.fmt.bufPrint(buf[pos..], "Config Sync: {s} -> {s}\n", .{ old, new }) catch "";
            pos += line.len;
            count += 1;
        }
    }

    state.settings_confirm_len = pos;
    state.settings_confirm_count = count;
    state.settings_confirm_port_warn = port_warn;
}

fn renderSettingsConfirm(state: *TuiState, win: vaxis.Window, fa: std.mem.Allocator) !void {
    const bg: vaxis.Color = .{ .rgb = .{ 20, 20, 30 } };
    const BOX_W: u16 = 56;
    const warn_lines: u16 = if (state.settings_confirm_port_warn) 1 else 0;
    const BOX_H: u16 = 6 + @as(u16, state.settings_confirm_count) + warn_lines;
    if (win.width < BOX_W or win.height < BOX_H) return;
    const x = (win.width - BOX_W) / 2;
    const y = (win.height - BOX_H) / 2;
    const box = win.child(.{ .x_off = x, .y_off = y, .width = BOX_W, .height = BOX_H });
    box.fill(.{ .char = .{ .grapheme = " ", .width = 1 }, .style = .{ .bg = bg } });

    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 160, 255 } }, .bg = bg };
    drawBox(box, 0, 0, BOX_W, BOX_H, border_style);
    const close_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 80, 80 } }, .bg = bg, .bold = true };
    const title_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 200, 80 } }, .bg = bg, .bold = true };
    const change_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 220, 180, 60 } }, .bg = bg };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = bg };
    const warn_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 100, 100 } }, .bg = bg };

    _ = box.print(&.{.{ .text = " Apply Settings? ", .style = title_style }}, .{ .col_offset = 1, .row_offset = 1, .wrap = .none });
    _ = box.print(&.{.{ .text = "[X]", .style = close_style }}, .{ .col_offset = BOX_W -| 4, .row_offset = 0, .wrap = .none });

    // Render each change line from the pre-built buffer.
    var row: u16 = 2;
    const confirm_text = state.settings_confirm_buf[0..state.settings_confirm_len];
    var line_iter = std.mem.splitScalar(u8, confirm_text, '\n');
    while (line_iter.next()) |line| {
        if (line.len == 0) continue;
        const display = try std.fmt.allocPrint(fa, "   {s}", .{line});
        _ = box.print(&.{.{ .text = display, .style = change_style }}, .{ .col_offset = 1, .row_offset = row, .wrap = .none });
        row += 1;
    }

    // Port < 1024 warning.
    if (state.settings_confirm_port_warn) {
        _ = box.print(&.{.{ .text = "   Port < 1024 requires privileged access", .style = warn_style }}, .{ .col_offset = 1, .row_offset = row, .wrap = .none });
        row += 1;
    }

    // Action hints.
    _ = box.print(&.{.{ .text = "  Config will be saved and reloaded.", .style = hint_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 3, .wrap = .none });
    _ = box.print(&.{.{ .text = "  Y: confirm  N/Esc: cancel", .style = hint_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 2, .wrap = .none });
}

fn handleSettingsConfirmKey(server: *AdminServer, state: *TuiState, key: vaxis.Key) void {
    if (key.matches('y', .{}) or key.matches('Y', .{})) {
        settingsApplyAndReload(server, state);
        state.mode = .normal;
    } else if (key.matches('n', .{}) or key.matches('N', .{}) or key.matches(vaxis.Key.escape, .{})) {
        // Go back to settings tab (keep dirty values).
        state.mode = .normal;
    }
}

fn handleSettingsClick(state: *TuiState, cfg: *const config_mod.Config, term_row: u16, scroll: u16) void {
    // The settings lines are rendered with row offset = line_index - scroll.
    // The body starts at row 1 (below header). So the clicked line index is
    // term_row - 1 + scroll.
    if (term_row < 1) return;
    const line_idx = (term_row - 1) + scroll;
    // Use the dynamic line-to-edit mapping populated by renderSettingsTab.
    if (line_idx >= state.settings_line_count or line_idx >= state.settings_line_to_edit.len) return;
    if (state.settings_line_to_edit[line_idx]) |edit_idx| {
        const old_row = state.settings_row;
        state.settings_row = edit_idx;
        state.settings_needs_scroll = true;
        if (state.settings_row != old_row) settingsOnRowChange(state, cfg);
    }
}

fn settingsApplyAndReload(server: *AdminServer, state: *TuiState) void {
    const cfg = server.cfg;
    // Indices: 0=log_level, 1=random_alloc, 2=collect, 3=http_enable, 4=http_port, 5=http_bind, 6=config_sync
    if (state.settings_dirty[0]) cfg.log_level = state.settings_pending_log_level;
    if (state.settings_dirty[1]) cfg.pool_allocation_random = state.settings_pending_random_alloc;
    if (state.settings_dirty[2]) cfg.metrics.collect = state.settings_pending_collect;
    if (state.settings_dirty[3]) cfg.metrics.http_enable = state.settings_pending_http_enable;
    if (state.settings_dirty[4]) {
        cfg.metrics.http_port = std.fmt.parseInt(u16, state.settings_pending_port_buf[0..state.settings_pending_port_len], 10) catch cfg.metrics.http_port;
    }
    if (state.settings_dirty[5]) {
        replaceStr(server.allocator, @constCast(&cfg.metrics.http_bind), state.settings_pending_bind_buf[0..state.settings_pending_bind_len]);
    }
    if (state.settings_dirty[6]) {
        if (cfg.sync) |*s| {
            s.config_sync = state.settings_pending_config_sync;
        }
    }
    // Clear dirty flags and pending buffer lengths so re-entry re-initializes from live config.
    state.settings_dirty = [_]bool{false} ** SETTINGS_EDITABLE_COUNT;
    state.settings_pending_port_len = 0;
    state.settings_pending_bind_len = 0;
    state.settings_cursor = 0;
    state.settings_err_len = 0;
    // Save and reload.
    config_write.writeConfig(server.allocator, server.cfg, server.cfg_path) catch return;
    triggerReload(state);
}

fn settingsSaveAndReload(server: *AdminServer, state: *TuiState) void {
    config_write.writeConfig(server.allocator, server.cfg, server.cfg_path) catch return;
    triggerReload(state);
}

// ---------------------------------------------------------------------------
// Help screen
// ---------------------------------------------------------------------------

fn renderHelp(state: *TuiState, win: vaxis.Window) void {
    const bg: vaxis.Color = .{ .rgb = .{ 20, 20, 35 } };
    // Adapt size: prefer 60 wide for two-column, shrink to fit.
    const BOX_W: u16 = @min(60, @max(30, win.width -| 4));
    const BOX_H: u16 = @min(30, @max(10, win.height -| 2));
    if (win.width < 20 or win.height < 8) return;
    const x = (win.width - BOX_W) / 2;
    const y = (win.height -| BOX_H) / 2;
    const box = win.child(.{ .x_off = x, .y_off = y, .width = BOX_W, .height = BOX_H });
    box.fill(.{ .char = .{ .grapheme = " ", .width = 1 }, .style = .{ .bg = bg } });
    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 160, 255 } }, .bg = bg };
    drawBox(box, 0, 0, BOX_W, BOX_H, border_style);
    const close_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 80, 80 } }, .bg = bg, .bold = true };
    _ = box.print(&.{.{ .text = "[X]", .style = close_style }}, .{ .col_offset = BOX_W -| 4, .row_offset = 0, .wrap = .none });

    const title_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 200, 80 } }, .bg = bg, .bold = true };
    const sec: vaxis.Style = .{ .fg = .{ .rgb = .{ 80, 180, 255 } }, .bg = bg, .bold = true };
    const key_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 220, 255 } }, .bg = bg };
    const desc_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 180, 190 } }, .bg = bg };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = bg };

    // Column layout: col1_key(12) col1_desc(14) gap(2) col2_key(12) col2_desc(rest)
    // For single-column rows: key(12) desc(rest)
    const K: u16 = 12; // key column width
    const D: u16 = 14; // description column width (first pair)
    const G: u16 = 2; // gap between pairs
    const C2: u16 = K + D + G; // start of second pair

    const Line = struct {
        kind: enum { title, section, blank, pair, single },
        k1: []const u8 = "",
        d1: []const u8 = "",
        k2: []const u8 = "",
        d2: []const u8 = "",
        sec_text: []const u8 = "",
    };

    const lines = [_]Line{
        .{ .kind = .title },
        .{ .kind = .blank },
        .{ .kind = .section, .sec_text = "Global" },
        .{ .kind = .pair, .k1 = "1/2/3/4", .d1 = "Switch tabs", .k2 = "Tab", .d2 = "Next/prev tab" },
        .{ .kind = .pair, .k1 = "Ctrl+R", .d1 = "Reload config", .k2 = "?", .d2 = "This help" },
        .{ .kind = .pair, .k1 = "q", .d1 = "Quit session", .k2 = "Ctrl+C", .d2 = "Quit session" },
        .{ .kind = .blank },
        .{ .kind = .section, .sec_text = "Leases" },
        .{ .kind = .pair, .k1 = "j/k", .d1 = "Navigate", .k2 = "/", .d2 = "Filter" },
        .{ .kind = .pair, .k1 = "I/M/H/T/E/P", .d1 = "Sort column", .k2 = "y+i/m/h", .d2 = "Yank" },
        .{ .kind = .pair, .k1 = "n", .d1 = "New reserv.", .k2 = "e", .d2 = "Edit" },
        .{ .kind = .single, .k1 = "d", .d1 = "Delete / force-release lease" },
        .{ .kind = .blank },
        .{ .kind = .section, .sec_text = "Pools" },
        .{ .kind = .pair, .k1 = "v / Enter", .d1 = "View pool", .k2 = "e", .d2 = "Edit pool" },
        .{ .kind = .pair, .k1 = "n", .d1 = "New pool", .k2 = "d", .d2 = "Delete pool" },
        .{ .kind = .single, .k1 = "/", .d1 = "Filter pools" },
        .{ .kind = .blank },
        .{ .kind = .section, .sec_text = "Forms" },
        .{ .kind = .pair, .k1 = "Up/Down/Tab", .d1 = "Navigate", .k2 = "Left/Right", .d2 = "Move cursor" },
        .{ .kind = .pair, .k1 = "Home/End", .d1 = "Start/end", .k2 = "Enter", .d2 = "Save" },
        .{ .kind = .single, .k1 = "Esc", .d1 = "Cancel / close" },
    };

    // Two-column mode if box is wide enough.
    const two_col = (BOX_W >= 58);

    // Compute total rendered rows for scroll clamping.
    var total_rows: u16 = 0;
    for (lines) |line| {
        total_rows += 1;
        if (line.kind == .pair and !two_col) total_rows += 1; // extra row in single-col
    }

    // Clamp scroll.
    const content_h = BOX_H -| 4; // border + title row + hint row + border
    const max_scroll: u16 = if (total_rows > content_h) total_rows - content_h else 0;
    if (state.help_scroll > max_scroll) state.help_scroll = max_scroll;
    const scroll = state.help_scroll;

    // Render with scroll offset.
    var logical_row: u16 = 0; // absolute row index (before scroll)
    var row: u16 = 2; // screen row in box
    for (lines) |line| {
        if (row >= BOX_H - 2) break;

        // First row of this entry.
        if (logical_row >= scroll and row < BOX_H - 2) {
            switch (line.kind) {
                .title => {
                    _ = box.print(&.{.{ .text = " Keyboard Shortcuts", .style = title_style }}, .{ .col_offset = 1, .row_offset = row, .wrap = .none });
                },
                .blank => {},
                .section => {
                    _ = box.print(&.{.{ .text = " -- ", .style = sec }}, .{ .col_offset = 1, .row_offset = row, .wrap = .none });
                    _ = box.print(&.{.{ .text = line.sec_text, .style = sec }}, .{ .col_offset = 5, .row_offset = row, .wrap = .none });
                    _ = box.print(&.{.{ .text = " --", .style = sec }}, .{ .col_offset = 5 + @as(u16, @intCast(line.sec_text.len)), .row_offset = row, .wrap = .none });
                },
                .pair => {
                    _ = box.print(&.{.{ .text = line.k1, .style = key_style }}, .{ .col_offset = 2, .row_offset = row, .wrap = .none });
                    _ = box.print(&.{.{ .text = line.d1, .style = desc_style }}, .{ .col_offset = 2 + K, .row_offset = row, .wrap = .none });
                    if (two_col) {
                        _ = box.print(&.{.{ .text = line.k2, .style = key_style }}, .{ .col_offset = 2 + C2, .row_offset = row, .wrap = .none });
                        _ = box.print(&.{.{ .text = line.d2, .style = desc_style }}, .{ .col_offset = 2 + C2 + K, .row_offset = row, .wrap = .none });
                    }
                },
                .single => {
                    _ = box.print(&.{.{ .text = line.k1, .style = key_style }}, .{ .col_offset = 2, .row_offset = row, .wrap = .none });
                    _ = box.print(&.{.{ .text = line.d1, .style = desc_style }}, .{ .col_offset = 2 + K, .row_offset = row, .wrap = .none });
                },
            }
            row += 1;
        } else if (logical_row >= scroll) {
            row += 1; // past viewport but count
        }
        logical_row += 1;

        // Second row for pair in single-column mode.
        if (line.kind == .pair and !two_col) {
            if (logical_row >= scroll and row < BOX_H - 2) {
                _ = box.print(&.{.{ .text = line.k2, .style = key_style }}, .{ .col_offset = 2, .row_offset = row, .wrap = .none });
                _ = box.print(&.{.{ .text = line.d2, .style = desc_style }}, .{ .col_offset = 2 + K, .row_offset = row, .wrap = .none });
                row += 1;
            } else if (logical_row >= scroll) {
                row += 1;
            }
            logical_row += 1;
        }
    }

    // Bottom hint inside border.
    const hint_text = if (total_rows > content_h) " j/k to scroll, any other key to close" else " Press any key to close";
    _ = box.print(&.{.{ .text = hint_text, .style = hint_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 2, .wrap = .none });
}

// ---------------------------------------------------------------------------
// Pool domain search edit modal
// ---------------------------------------------------------------------------

fn renderPoolServerEdit(state: *TuiState, win: vaxis.Window, fa: std.mem.Allocator) !void {
    const form = &state.pool_form;
    const BOX_W: u16 = 48;
    const has_err = form.err_len > 0;
    const BOX_H: u16 = if (has_err) 8 else 7;
    if (win.width < BOX_W or win.height < BOX_H) return;
    const x = (win.width - BOX_W) / 2;
    const y = (win.height -| BOX_H) / 2;
    const box = win.child(.{ .x_off = x, .y_off = y, .width = BOX_W, .height = BOX_H });
    box.fill(.{ .char = .{ .grapheme = " ", .width = 1 }, .style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } } });
    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 160, 255 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    drawBox(box, 0, 0, BOX_W, BOX_H, border_style);
    const title_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 200, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    const label_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 160, 160, 190 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const active_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 255, 255 } }, .bg = .{ .rgb = .{ 50, 80, 140 } } };
    const cursor_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 20, 20, 30 } }, .bg = .{ .rgb = .{ 100, 160, 255 } } };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const close_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 80, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };

    // Title depends on target and add vs edit.
    const is_add = form.server_edit_index == null;
    const title: []const u8 = switch (form.server_edit_target) {
        .domain_search => if (is_add) "  Add Domain" else "  Edit Domain",
        .dns => if (is_add) "  Add DNS Server" else "  Edit DNS Server",
        .log => if (is_add) "  Add Log Server" else "  Edit Log Server",
        .ntp => if (is_add) "  Add NTP Server" else "  Edit NTP Server",
        .wins => if (is_add) "  Add WINS Server" else "  Edit WINS Server",
        .tftp => if (is_add) "  Add TFTP Server" else "  Edit TFTP Server",
    };
    _ = box.print(&.{.{ .text = title, .style = title_style }}, .{ .col_offset = 1, .row_offset = 1, .wrap = .none });
    _ = box.print(&.{.{ .text = "[X]", .style = close_style }}, .{ .col_offset = BOX_W -| 4, .row_offset = 0, .wrap = .none });

    // Field label depends on target.
    const label: []const u8 = switch (form.server_edit_target) {
        .domain_search => "  Domain    ",
        .dns, .log, .ntp, .wins, .tftp => "  Server    ",
    };
    _ = box.print(&.{.{ .text = label, .style = label_style }}, .{ .col_offset = 1, .row_offset = 3, .wrap = .none });
    const val = form.server_edit_buf[0..form.server_edit_len];
    const field_fw: u16 = BOX_W -| 16;
    const val_trunc = val[0..@min(val.len, field_fw)];
    const val_pad = try fa.alloc(u8, field_fw -| @as(u16, @intCast(val_trunc.len)));
    @memset(val_pad, ' ');
    _ = box.print(&.{.{ .text = val_trunc, .style = active_style }}, .{ .col_offset = 13, .row_offset = 3, .wrap = .none });
    _ = box.print(&.{.{ .text = val_pad, .style = active_style }}, .{ .col_offset = 13 + @as(u16, @intCast(val_trunc.len)), .row_offset = 3, .wrap = .none });
    {
        const cur = @min(form.server_edit_cursor, val.len);
        const ch: []const u8 = if (cur < val.len) val[cur..][0..1] else " ";
        _ = box.print(&.{.{ .text = ch, .style = cursor_style }}, .{ .col_offset = 13 + @as(u16, @intCast(cur)), .row_offset = 3, .wrap = .none });
    }

    if (has_err) {
        const err_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 80, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
        _ = box.print(&.{.{ .text = form.err_buf[0..form.err_len], .style = err_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 3, .wrap = .none });
    }
    _ = box.print(&.{.{ .text = "  Enter: save  Esc: cancel", .style = hint_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 2, .wrap = .none });
}

fn handlePoolServerEditKey(state: *TuiState, key: vaxis.Key) void {
    var form = &state.pool_form;

    if (key.matches(vaxis.Key.escape, .{})) {
        form.err_len = 0;
        state.mode = subModalParent(form);
        return;
    }
    if (key.matches(vaxis.Key.enter, .{})) {
        form.err_len = 0;
        if (form.server_edit_len == 0) {
            const msg = "  Value is required";
            form.err_len = msg.len;
            @memcpy(form.err_buf[0..msg.len], msg);
            return;
        }
        // Auto-lowercase.
        for (form.server_edit_buf[0..form.server_edit_len]) |*ch| {
            if (ch.* >= 'A' and ch.* <= 'Z') ch.* = ch.* - 'A' + 'a';
        }
        const val = form.server_edit_buf[0..form.server_edit_len];

        if (form.server_edit_target == .domain_search) {
            // Domain search: must be a valid domain name.
            if (!isValidDomainName(val)) {
                const msg = "  Invalid domain (a-z 0-9 . - _)";
                form.err_len = msg.len;
                @memcpy(form.err_buf[0..msg.len], msg);
                return;
            }
        } else {
            // Server types: accept IPv4 or valid domain name.
            const is_ip = if (config_mod.parseIpv4(val)) |_| true else |_| false;
            if (!is_ip and !isValidDomainName(val)) {
                const msg = "  Invalid IP or domain name";
                form.err_len = msg.len;
                @memcpy(form.err_buf[0..msg.len], msg);
                return;
            }
        }

        // Save the entry to the appropriate array (parent-aware).
        const entry_arr = serverEditEntryArr(form);
        const count = serverEditCount(form);
        if (form.server_edit_index) |idx| {
            // Editing existing.
            if (idx < count.*) {
                @memcpy(entry_arr[idx].buf[0..form.server_edit_len], form.server_edit_buf[0..form.server_edit_len]);
                entry_arr[idx].len = form.server_edit_len;
            }
        } else {
            // Adding new.
            const max = serverEditMax(form);
            if (count.* < max) {
                var new_entry = &entry_arr[count.*];
                new_entry.* = .{};
                @memcpy(new_entry.buf[0..form.server_edit_len], form.server_edit_buf[0..form.server_edit_len]);
                new_entry.len = form.server_edit_len;
                count.* += 1;
            }
        }

        // DNS Update Server auto-populate: when saving DNS server at index 0 (pool form only).
        if (form.server_edit_parent == .pool_form and form.server_edit_target == .dns) {
            const save_idx = form.server_edit_index orelse (form.dns_servers_count - 1);
            if (save_idx == 0 and form.dns_update_server_len == 0) {
                @memcpy(form.dns_update_server_buf[0..form.server_edit_len], form.server_edit_buf[0..form.server_edit_len]);
                form.dns_update_server_len = form.server_edit_len;
            }
        }

        state.mode = subModalParent(form);
        return;
    }
    // Tab does nothing (single field).
    if (key.matches(vaxis.Key.tab, .{}) or key.matches(vaxis.Key.tab, .{ .shift = true })) return;

    // Text editing.
    const buf: []u8 = &form.server_edit_buf;
    const len: *usize = &form.server_edit_len;
    const max_len = buf.len;

    if (key.matches(vaxis.Key.backspace, .{})) {
        if (form.server_edit_cursor > 0 and len.* > 0) {
            const pos = form.server_edit_cursor;
            if (pos < len.*) std.mem.copyForwards(u8, buf[pos - 1 ..], buf[pos..len.*]);
            len.* -= 1;
            form.server_edit_cursor -= 1;
        }
    } else if (key.matches(vaxis.Key.left, .{})) {
        if (form.server_edit_cursor > 0) form.server_edit_cursor -= 1;
    } else if (key.matches(vaxis.Key.right, .{})) {
        if (form.server_edit_cursor < len.*) form.server_edit_cursor += 1;
    } else if (key.matches(vaxis.Key.home, .{})) {
        form.server_edit_cursor = 0;
    } else if (key.matches(vaxis.Key.end, .{})) {
        form.server_edit_cursor = len.*;
    } else if (key.codepoint >= 0x20 and key.codepoint <= 0x7E) {
        // Filter allowed characters based on server edit target type.
        const ch: u8 = @intCast(key.codepoint);
        const allowed = switch (form.server_edit_target) {
            .domain_search => (ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '.' or ch == '-' or ch == '_', // Domain name
            .dns, .ntp, .log, .wins, .tftp => (ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '.' or ch == '-' or ch == ':', // IP or domain
        };
        if (!allowed) return;
        if (len.* < max_len) {
            const pos = form.server_edit_cursor;
            if (pos < len.*) std.mem.copyBackwards(u8, buf[pos + 1 ..], buf[pos..len.*]);
            buf[pos] = @intCast(key.codepoint);
            len.* += 1;
            form.server_edit_cursor += 1;
        }
    }
}

/// Validate a domain name: starts with alnum, contains only a-z 0-9 . - _
fn isValidDomainName(val: []const u8) bool {
    if (val.len == 0) return false;
    const first = val[0];
    if (!((first >= 'a' and first <= 'z') or (first >= '0' and first <= '9'))) return false;
    for (val) |ch| {
        if (!((ch >= 'a' and ch <= 'z') or (ch >= '0' and ch <= '9') or ch == '.' or ch == '-' or ch == '_')) return false;
    }
    return true;
}

/// Get a mutable pointer to the entry array for the current server_edit_target.
/// Checks server_edit_parent to return pool form or MAC class edit arrays.
fn serverEditEntryArr(form: *PoolForm) []InlineEntry {
    if (form.server_edit_parent == .mac_class_edit) {
        const mc = &form.mac_class_edit;
        return switch (form.server_edit_target) {
            .domain_search => &mc.domain_search,
            .dns => &mc.dns_servers,
            .log => &mc.log_servers,
            .ntp => &mc.ntp_servers,
            .wins => &mc.wins_servers,
            .tftp => &mc.tftp_servers,
        };
    }
    return switch (form.server_edit_target) {
        .domain_search => &form.domain_search,
        .dns => &form.dns_servers,
        .log => &form.log_servers,
        .ntp => &form.ntp_servers,
        .wins => &form.wins_servers,
        .tftp => &form.tftp_servers,
    };
}

/// Get a mutable pointer to the count for the current server_edit_target.
/// Checks server_edit_parent to return pool form or MAC class edit count.
fn serverEditCount(form: *PoolForm) *usize {
    if (form.server_edit_parent == .mac_class_edit) {
        const mc = &form.mac_class_edit;
        return switch (form.server_edit_target) {
            .domain_search => &mc.domain_search_count,
            .dns => &mc.dns_servers_count,
            .log => &mc.log_servers_count,
            .ntp => &mc.ntp_servers_count,
            .wins => &mc.wins_servers_count,
            .tftp => &mc.tftp_servers_count,
        };
    }
    return switch (form.server_edit_target) {
        .domain_search => &form.domain_search_count,
        .dns => &form.dns_servers_count,
        .log => &form.log_servers_count,
        .ntp => &form.ntp_servers_count,
        .wins => &form.wins_servers_count,
        .tftp => &form.tftp_servers_count,
    };
}

/// Get the max capacity for the current server_edit_target.
/// Checks server_edit_parent to return pool form or MAC class edit max.
fn serverEditMax(form: *PoolForm) usize {
    if (form.server_edit_parent == .mac_class_edit) {
        const mc = &form.mac_class_edit;
        return switch (form.server_edit_target) {
            .domain_search => mc.domain_search.len,
            .dns => mc.dns_servers.len,
            .log => mc.log_servers.len,
            .ntp => mc.ntp_servers.len,
            .wins => mc.wins_servers.len,
            .tftp => mc.tftp_servers.len,
        };
    }
    return switch (form.server_edit_target) {
        .domain_search => form.domain_search.len,
        .dns => form.dns_servers.len,
        .log => form.log_servers.len,
        .ntp => form.ntp_servers.len,
        .wins => form.wins_servers.len,
        .tftp => form.tftp_servers.len,
    };
}

/// Get mutable route array + count, respecting server_edit_parent context.
fn activeRoutes(form: *PoolForm) struct { routes: []RouteEntry, count: *usize, max: usize } {
    if (form.server_edit_parent == .mac_class_edit) {
        return .{ .routes = &form.mac_class_edit.routes, .count = &form.mac_class_edit.route_count, .max = form.mac_class_edit.routes.len };
    }
    return .{ .routes = &form.routes, .count = &form.route_count, .max = form.routes.len };
}

/// Get mutable option array + count, respecting server_edit_parent context.
fn activeOptions(form: *PoolForm) struct { options: []OptionEntry, count: *usize, max: usize } {
    if (form.server_edit_parent == .mac_class_edit) {
        return .{ .options = &form.mac_class_edit.options, .count = &form.mac_class_edit.option_count, .max = form.mac_class_edit.options.len };
    }
    return .{ .options = &form.options, .count = &form.option_count, .max = form.options.len };
}

/// Return the parent mode for sub-modals based on server_edit_parent.
fn subModalParent(form: *const PoolForm) TuiMode {
    return if (form.server_edit_parent == .mac_class_edit) .pool_mac_class_edit else .pool_form;
}

// ---------------------------------------------------------------------------
// Pool route edit modal
// ---------------------------------------------------------------------------

fn renderPoolRouteEdit(state: *TuiState, win: vaxis.Window, fa: std.mem.Allocator) !void {
    const form = &state.pool_form;
    const BOX_W: u16 = 48;
    const has_err = form.err_len > 0;
    const BOX_H: u16 = if (has_err) 9 else 8;
    if (win.width < BOX_W or win.height < BOX_H) return;
    const x = (win.width - BOX_W) / 2;
    const y = (win.height -| BOX_H) / 2;
    const box = win.child(.{ .x_off = x, .y_off = y, .width = BOX_W, .height = BOX_H });
    box.fill(.{ .char = .{ .grapheme = " ", .width = 1 }, .style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } } });
    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 160, 255 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    drawBox(box, 0, 0, BOX_W, BOX_H, border_style);
    const title_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 200, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    const label_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 160, 160, 190 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const field_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 200, 200, 200 } }, .bg = .{ .rgb = .{ 30, 30, 45 } } };
    const active_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 255, 255 } }, .bg = .{ .rgb = .{ 50, 80, 140 } } };
    const cursor_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 20, 20, 30 } }, .bg = .{ .rgb = .{ 100, 160, 255 } } };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const close_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 80, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };

    const title = if (form.route_edit_index == null) "  Add Static Route" else "  Edit Static Route";
    _ = box.print(&.{.{ .text = title, .style = title_style }}, .{ .col_offset = 1, .row_offset = 1, .wrap = .none });
    _ = box.print(&.{.{ .text = "[X]", .style = close_style }}, .{ .col_offset = BOX_W -| 4, .row_offset = 0, .wrap = .none });

    // Network field.
    const dest_active = form.route_edit_field == 0;
    _ = box.print(&.{.{ .text = "  Network   ", .style = label_style }}, .{ .col_offset = 1, .row_offset = 3, .wrap = .none });
    const dest_val = form.route_edit_dest[0..form.route_edit_dest_len];
    const dest_style = if (dest_active) active_style else field_style;
    const dest_fw: u16 = BOX_W -| 16;
    const dest_trunc = dest_val[0..@min(dest_val.len, dest_fw)];
    const dest_pad = try fa.alloc(u8, dest_fw -| @as(u16, @intCast(dest_trunc.len)));
    @memset(dest_pad, ' ');
    _ = box.print(&.{.{ .text = dest_trunc, .style = dest_style }}, .{ .col_offset = 13, .row_offset = 3, .wrap = .none });
    _ = box.print(&.{.{ .text = dest_pad, .style = dest_style }}, .{ .col_offset = 13 + @as(u16, @intCast(dest_trunc.len)), .row_offset = 3, .wrap = .none });
    if (dest_active) {
        const cur = @min(form.route_edit_cursor, dest_val.len);
        const ch: []const u8 = if (cur < dest_val.len) dest_val[cur..][0..1] else " ";
        _ = box.print(&.{.{ .text = ch, .style = cursor_style }}, .{ .col_offset = 13 + @as(u16, @intCast(cur)), .row_offset = 3, .wrap = .none });
    }

    // Gateway field.
    const router_active = form.route_edit_field == 1;
    _ = box.print(&.{.{ .text = "  Gateway   ", .style = label_style }}, .{ .col_offset = 1, .row_offset = 4, .wrap = .none });
    const router_val = form.route_edit_router[0..form.route_edit_router_len];
    const router_style = if (router_active) active_style else field_style;
    const router_trunc = router_val[0..@min(router_val.len, dest_fw)];
    const router_pad = try fa.alloc(u8, dest_fw -| @as(u16, @intCast(router_trunc.len)));
    @memset(router_pad, ' ');
    _ = box.print(&.{.{ .text = router_trunc, .style = router_style }}, .{ .col_offset = 13, .row_offset = 4, .wrap = .none });
    _ = box.print(&.{.{ .text = router_pad, .style = router_style }}, .{ .col_offset = 13 + @as(u16, @intCast(router_trunc.len)), .row_offset = 4, .wrap = .none });
    if (router_active) {
        const cur = @min(form.route_edit_cursor, router_val.len);
        const ch: []const u8 = if (cur < router_val.len) router_val[cur..][0..1] else " ";
        _ = box.print(&.{.{ .text = ch, .style = cursor_style }}, .{ .col_offset = 13 + @as(u16, @intCast(cur)), .row_offset = 4, .wrap = .none });
    }

    if (has_err) {
        const err_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 80, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
        _ = box.print(&.{.{ .text = form.err_buf[0..form.err_len], .style = err_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 3, .wrap = .none });
    }
    _ = box.print(&.{.{ .text = "  Tab: switch  Enter: save  Esc: cancel", .style = hint_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 2, .wrap = .none });
}

fn handlePoolRouteEditKey(state: *TuiState, key: vaxis.Key) void {
    var form = &state.pool_form;

    if (key.matches(vaxis.Key.escape, .{})) {
        form.err_len = 0;
        state.mode = subModalParent(form);
        return;
    }
    if (key.matches(vaxis.Key.enter, .{})) {
        form.err_len = 0;
        // Validate network (must be valid CIDR).
        const dest = form.route_edit_dest[0..form.route_edit_dest_len];
        if (dest.len == 0) {
            const msg = "  Network is required";
            form.err_len = msg.len;
            @memcpy(form.err_buf[0..msg.len], msg);
            return;
        }
        _ = config_mod.parseCidr(dest) catch {
            const msg = "  Invalid CIDR (e.g. 10.0.0.0/24)";
            form.err_len = msg.len;
            @memcpy(form.err_buf[0..msg.len], msg);
            return;
        };
        // Validate gateway (must be valid IP on the pool's subnet).
        const gw = form.route_edit_router[0..form.route_edit_router_len];
        if (gw.len == 0) {
            const msg = "  Gateway is required";
            form.err_len = msg.len;
            @memcpy(form.err_buf[0..msg.len], msg);
            return;
        }
        const gw_ip = config_mod.parseIpv4(gw) catch {
            const msg = "  Invalid gateway IP";
            form.err_len = msg.len;
            @memcpy(form.err_buf[0..msg.len], msg);
            return;
        };
        // Check gateway is on the pool's subnet.
        const pool_subnet = config_mod.parseCidr(form.subnet_buf[0..form.subnet_len]) catch null;
        if (pool_subnet) |ps| {
            const gw_int = std.mem.readInt(u32, &gw_ip, .big);
            const subnet_int = std.mem.readInt(u32, &ps.ip, .big);
            if (gw_int & ps.mask != subnet_int & ps.mask) {
                const msg = std.fmt.bufPrint(&form.err_buf, "  Gateway not in {s}", .{form.subnet_buf[0..form.subnet_len]}) catch "  Gateway not on pool subnet";
                form.err_len = msg.len;
                return;
            }
        }
        // Save the route (parent-aware).
        const ar = activeRoutes(form);
        if (form.route_edit_index) |idx| {
            // Editing existing.
            if (idx < ar.count.*) {
                @memcpy(ar.routes[idx].dest_buf[0..form.route_edit_dest_len], form.route_edit_dest[0..form.route_edit_dest_len]);
                ar.routes[idx].dest_len = form.route_edit_dest_len;
                @memcpy(ar.routes[idx].router_buf[0..form.route_edit_router_len], form.route_edit_router[0..form.route_edit_router_len]);
                ar.routes[idx].router_len = form.route_edit_router_len;
            }
        } else {
            // Adding new.
            if (ar.count.* < ar.max) {
                var new_route = &ar.routes[ar.count.*];
                new_route.* = .{};
                @memcpy(new_route.dest_buf[0..form.route_edit_dest_len], form.route_edit_dest[0..form.route_edit_dest_len]);
                new_route.dest_len = form.route_edit_dest_len;
                @memcpy(new_route.router_buf[0..form.route_edit_router_len], form.route_edit_router[0..form.route_edit_router_len]);
                new_route.router_len = form.route_edit_router_len;
                ar.count.* += 1;
            }
        }
        state.mode = subModalParent(form);
        return;
    }
    if (key.matches(vaxis.Key.tab, .{}) or key.matches(vaxis.Key.tab, .{ .shift = true })) {
        form.route_edit_field = if (form.route_edit_field == 0) 1 else 0;
        form.route_edit_cursor = if (form.route_edit_field == 0) form.route_edit_dest_len else form.route_edit_router_len;
        return;
    }

    // Text editing.
    const buf: []u8 = if (form.route_edit_field == 0) &form.route_edit_dest else &form.route_edit_router;
    const len: *usize = if (form.route_edit_field == 0) &form.route_edit_dest_len else &form.route_edit_router_len;
    const max_len = buf.len;

    if (key.matches(vaxis.Key.backspace, .{})) {
        if (form.route_edit_cursor > 0 and len.* > 0) {
            const pos = form.route_edit_cursor;
            if (pos < len.*) std.mem.copyForwards(u8, buf[pos - 1 ..], buf[pos..len.*]);
            len.* -= 1;
            form.route_edit_cursor -= 1;
        }
    } else if (key.matches(vaxis.Key.left, .{})) {
        if (form.route_edit_cursor > 0) form.route_edit_cursor -= 1;
    } else if (key.matches(vaxis.Key.right, .{})) {
        if (form.route_edit_cursor < len.*) form.route_edit_cursor += 1;
    } else if (key.matches(vaxis.Key.home, .{})) {
        form.route_edit_cursor = 0;
    } else if (key.matches(vaxis.Key.end, .{})) {
        form.route_edit_cursor = len.*;
    } else if (key.codepoint >= 0x20 and key.codepoint <= 0x7E) {
        // Filter allowed characters based on route field type.
        const ch: u8 = @intCast(key.codepoint);
        const allowed = if (form.route_edit_field == 0)
            (ch >= '0' and ch <= '9') or ch == '.' or ch == '/' // Network (CIDR)
        else
            (ch >= '0' and ch <= '9') or ch == '.'; // Gateway (IP)
        if (!allowed) return;
        if (len.* < max_len) {
            const pos = form.route_edit_cursor;
            if (pos < len.*) std.mem.copyBackwards(u8, buf[pos + 1 ..], buf[pos..len.*]);
            buf[pos] = @intCast(key.codepoint);
            len.* += 1;
            form.route_edit_cursor += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Pool option edit modal
// ---------------------------------------------------------------------------

fn renderPoolOptionEdit(state: *TuiState, win: vaxis.Window, fa: std.mem.Allocator) !void {
    const form = &state.pool_form;
    const BOX_W: u16 = 48;
    const has_err = form.err_len > 0;
    const BOX_H: u16 = if (has_err) 9 else 8;
    if (win.width < BOX_W or win.height < BOX_H) return;
    const x = (win.width - BOX_W) / 2;
    const y = (win.height -| BOX_H) / 2;
    const box = win.child(.{ .x_off = x, .y_off = y, .width = BOX_W, .height = BOX_H });
    box.fill(.{ .char = .{ .grapheme = " ", .width = 1 }, .style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } } });
    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 160, 255 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    drawBox(box, 0, 0, BOX_W, BOX_H, border_style);
    const title_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 200, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    const label_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 160, 160, 190 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const field_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 200, 200, 200 } }, .bg = .{ .rgb = .{ 30, 30, 45 } } };
    const active_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 255, 255 } }, .bg = .{ .rgb = .{ 50, 80, 140 } } };
    const cursor_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 20, 20, 30 } }, .bg = .{ .rgb = .{ 100, 160, 255 } } };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const close_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 80, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };

    const title = if (form.opt_edit_index == null) "  Add DHCP Option" else "  Edit DHCP Option";
    _ = box.print(&.{.{ .text = title, .style = title_style }}, .{ .col_offset = 1, .row_offset = 1, .wrap = .none });
    _ = box.print(&.{.{ .text = "[X]", .style = close_style }}, .{ .col_offset = BOX_W -| 4, .row_offset = 0, .wrap = .none });

    // Option number field.
    const code_active = form.opt_edit_field == 0;
    _ = box.print(&.{.{ .text = "  Option #  ", .style = label_style }}, .{ .col_offset = 1, .row_offset = 3, .wrap = .none });
    const code_val = form.opt_edit_code[0..form.opt_edit_code_len];
    const code_style = if (code_active) active_style else field_style;
    const code_pad = try fa.alloc(u8, 6 -| code_val.len);
    @memset(code_pad, ' ');
    _ = box.print(&.{.{ .text = code_val, .style = code_style }}, .{ .col_offset = 13, .row_offset = 3, .wrap = .none });
    _ = box.print(&.{.{ .text = code_pad, .style = code_style }}, .{ .col_offset = 13 + @as(u16, @intCast(code_val.len)), .row_offset = 3, .wrap = .none });
    if (code_active) {
        const cur = @min(form.opt_edit_cursor, code_val.len);
        const ch: []const u8 = if (cur < code_val.len) code_val[cur..][0..1] else " ";
        _ = box.print(&.{.{ .text = ch, .style = cursor_style }}, .{ .col_offset = 13 + @as(u16, @intCast(cur)), .row_offset = 3, .wrap = .none });
    }
    // Lookup hint.
    if (code_active) {
        _ = box.print(&.{.{ .text = "  l: lookup", .style = hint_style }}, .{ .col_offset = 20, .row_offset = 3, .wrap = .none });
    }

    // Value field.
    const val_active = form.opt_edit_field == 1;
    _ = box.print(&.{.{ .text = "  Value     ", .style = label_style }}, .{ .col_offset = 1, .row_offset = 4, .wrap = .none });
    const val_text = form.opt_edit_value[0..form.opt_edit_value_len];
    const val_fw: u16 = BOX_W -| 16;
    const val_style = if (val_active) active_style else field_style;
    const val_trunc = val_text[0..@min(val_text.len, val_fw)];
    const val_pad = try fa.alloc(u8, val_fw -| @as(u16, @intCast(val_trunc.len)));
    @memset(val_pad, ' ');
    _ = box.print(&.{.{ .text = val_trunc, .style = val_style }}, .{ .col_offset = 13, .row_offset = 4, .wrap = .none });
    _ = box.print(&.{.{ .text = val_pad, .style = val_style }}, .{ .col_offset = 13 + @as(u16, @intCast(val_trunc.len)), .row_offset = 4, .wrap = .none });
    if (val_active) {
        const cur = @min(form.opt_edit_cursor, val_text.len);
        const ch: []const u8 = if (cur < val_text.len) val_text[cur..][0..1] else " ";
        _ = box.print(&.{.{ .text = ch, .style = cursor_style }}, .{ .col_offset = 13 + @as(u16, @intCast(cur)), .row_offset = 4, .wrap = .none });
    }

    if (has_err) {
        const err_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 80, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
        _ = box.print(&.{.{ .text = form.err_buf[0..form.err_len], .style = err_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 3, .wrap = .none });
    }
    _ = box.print(&.{.{ .text = "  Tab: switch  Enter: save  Esc: cancel", .style = hint_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 2, .wrap = .none });
}

fn handlePoolOptionEditKey(state: *TuiState, key: vaxis.Key) void {
    var form = &state.pool_form;

    if (key.matches(vaxis.Key.escape, .{})) {
        state.mode = subModalParent(form);
        return;
    }
    if (key.matches(vaxis.Key.enter, .{})) {
        form.err_len = 0;
        // Save the option.
        if (form.opt_edit_code_len == 0) {
            const msg = "  Option code is required";
            form.err_len = msg.len;
            @memcpy(form.err_buf[0..msg.len], msg);
            return;
        }
        // Validate code is 1-255.
        const code_val = std.fmt.parseInt(u16, form.opt_edit_code[0..form.opt_edit_code_len], 10) catch {
            const msg = "  Option code must be a number 1-255";
            form.err_len = msg.len;
            @memcpy(form.err_buf[0..msg.len], msg);
            return;
        };
        if (code_val == 0 or code_val > 255) {
            const msg = "  Option code must be 1-255";
            form.err_len = msg.len;
            @memcpy(form.err_buf[0..msg.len], msg);
            return;
        }
        // Save to parent-aware option array.
        const ao = activeOptions(form);
        if (form.opt_edit_index) |idx| {
            // Editing existing.
            if (idx < ao.count.*) {
                @memcpy(ao.options[idx].code_buf[0..form.opt_edit_code_len], form.opt_edit_code[0..form.opt_edit_code_len]);
                ao.options[idx].code_len = form.opt_edit_code_len;
                @memcpy(ao.options[idx].value_buf[0..form.opt_edit_value_len], form.opt_edit_value[0..form.opt_edit_value_len]);
                ao.options[idx].value_len = form.opt_edit_value_len;
            }
        } else {
            // Adding new.
            if (ao.count.* < ao.max) {
                var new_opt = &ao.options[ao.count.*];
                new_opt.* = .{};
                @memcpy(new_opt.code_buf[0..form.opt_edit_code_len], form.opt_edit_code[0..form.opt_edit_code_len]);
                new_opt.code_len = form.opt_edit_code_len;
                @memcpy(new_opt.value_buf[0..form.opt_edit_value_len], form.opt_edit_value[0..form.opt_edit_value_len]);
                new_opt.value_len = form.opt_edit_value_len;
                ao.count.* += 1;
            }
        }
        state.mode = subModalParent(form);
        return;
    }
    if (key.matches(vaxis.Key.tab, .{}) or key.matches(vaxis.Key.tab, .{ .shift = true })) {
        form.opt_edit_field = if (form.opt_edit_field == 0) 1 else 0;
        form.opt_edit_cursor = if (form.opt_edit_field == 0) form.opt_edit_code_len else form.opt_edit_value_len;
        return;
    }

    // 'l' on the code field opens lookup.
    if (form.opt_edit_field == 0 and key.matches('l', .{})) {
        form.opt_lookup_filter_len = 0;
        form.opt_lookup_row = 0;
        state.mode = .pool_option_lookup;
        return;
    }

    // Text editing.
    form.err_len = 0;
    const buf: []u8 = if (form.opt_edit_field == 0) &form.opt_edit_code else &form.opt_edit_value;
    const len: *usize = if (form.opt_edit_field == 0) &form.opt_edit_code_len else &form.opt_edit_value_len;
    const max_len = buf.len;

    if (key.matches(vaxis.Key.backspace, .{})) {
        if (form.opt_edit_cursor > 0 and len.* > 0) {
            const pos = form.opt_edit_cursor;
            if (pos < len.*) std.mem.copyForwards(u8, buf[pos - 1 ..], buf[pos..len.*]);
            len.* -= 1;
            form.opt_edit_cursor -= 1;
        }
    } else if (key.matches(vaxis.Key.left, .{})) {
        if (form.opt_edit_cursor > 0) form.opt_edit_cursor -= 1;
    } else if (key.matches(vaxis.Key.right, .{})) {
        if (form.opt_edit_cursor < len.*) form.opt_edit_cursor += 1;
    } else if (key.matches(vaxis.Key.home, .{})) {
        form.opt_edit_cursor = 0;
    } else if (key.matches(vaxis.Key.end, .{})) {
        form.opt_edit_cursor = len.*;
    } else if (key.codepoint >= 0x20 and key.codepoint <= 0x7E) {
        // Code field: numbers only.
        if (form.opt_edit_field == 0 and (key.codepoint < '0' or key.codepoint > '9')) return;
        if (len.* < max_len) {
            const pos = form.opt_edit_cursor;
            if (pos < len.*) std.mem.copyBackwards(u8, buf[pos + 1 ..], buf[pos..len.*]);
            buf[pos] = @intCast(key.codepoint);
            len.* += 1;
            form.opt_edit_cursor += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// MAC class edit modal — layout-driven like pool form
// ---------------------------------------------------------------------------

/// Regular text field metadata for the MAC class edit modal.
const MacClassFieldMeta = struct {
    label: []const u8,
};

/// Text-only fields in the MAC class form (indexed by mac_class_layout .field_idx).
const mac_class_field_meta = [_]MacClassFieldMeta{
    .{ .label = "Name" }, // 0 (required)
    .{ .label = "Match" }, // 1 (required, MAC prefix)
    .{ .label = "Router" }, // 2
    .{ .label = "Domain Name" }, // 3
    .{ .label = "Boot Filename" }, // 4
    .{ .label = "HTTP Boot URL" }, // 5
    .{ .label = "Time Offset" }, // 6 (signed int)
};

/// Inline target enum for MAC class form inline sections.
const McInlineTarget = enum { domain_search, dns, ntp, log, wins, tftp, routes, options };

const MacClassLayoutKind = enum { section, field, inline_section };

const MacClassLayoutItem = struct {
    kind: MacClassLayoutKind,
    label: []const u8 = "",
    field_idx: ?u8 = null,
    inline_target: ?McInlineTarget = null,
};

const mac_class_layout = [_]MacClassLayoutItem{
    .{ .kind = .section, .label = "Identity" },
    .{ .kind = .field, .field_idx = 0 }, // Name
    .{ .kind = .field, .field_idx = 1 }, // Match
    .{ .kind = .section, .label = "Overrides" },
    .{ .kind = .field, .field_idx = 2 }, // Router
    .{ .kind = .field, .field_idx = 3 }, // Domain Name
    .{ .kind = .inline_section, .label = "Search Domains", .inline_target = .domain_search },
    .{ .kind = .inline_section, .label = "DNS Servers", .inline_target = .dns },
    .{ .kind = .inline_section, .label = "NTP Servers", .inline_target = .ntp },
    .{ .kind = .inline_section, .label = "Log Servers", .inline_target = .log },
    .{ .kind = .inline_section, .label = "WINS Servers", .inline_target = .wins },
    .{ .kind = .section, .label = "Boot" },
    .{ .kind = .inline_section, .label = "TFTP Servers", .inline_target = .tftp },
    .{ .kind = .field, .field_idx = 4 }, // Boot Filename
    .{ .kind = .field, .field_idx = 5 }, // HTTP Boot URL
    .{ .kind = .section, .label = "Time" },
    .{ .kind = .field, .field_idx = 6 }, // Time Offset
    .{ .kind = .section, .label = "Routes" },
    .{ .kind = .inline_section, .label = "Static Routes", .inline_target = .routes },
    .{ .kind = .section, .label = "Other" },
    .{ .kind = .inline_section, .label = "DHCP Options", .inline_target = .options },
};

/// Return the string value of a MAC class text field by field_idx.
fn macClassFieldVal(mc: *const MacClassEntry, idx: u8) []const u8 {
    return switch (idx) {
        0 => mc.name_buf[0..mc.name_len],
        1 => mc.match_buf[0..mc.match_len],
        2 => mc.router_buf[0..mc.router_len],
        3 => mc.domain_name_buf[0..mc.domain_name_len],
        4 => mc.boot_filename_buf[0..mc.boot_filename_len],
        5 => mc.http_boot_url_buf[0..mc.http_boot_url_len],
        6 => mc.time_offset_buf[0..mc.time_offset_len],
        else => "",
    };
}

fn macClassFieldLen(mc: *const MacClassEntry, idx: u8) usize {
    return macClassFieldVal(mc, idx).len;
}

/// Return a mutable pointer to the MAC class text field buffer + length.
fn macClassFieldBuf(mc: *MacClassEntry, idx: u8) ?struct { buf: []u8, len: *usize } {
    return switch (idx) {
        0 => .{ .buf = &mc.name_buf, .len = &mc.name_len },
        1 => .{ .buf = &mc.match_buf, .len = &mc.match_len },
        2 => .{ .buf = &mc.router_buf, .len = &mc.router_len },
        3 => .{ .buf = &mc.domain_name_buf, .len = &mc.domain_name_len },
        4 => .{ .buf = &mc.boot_filename_buf, .len = &mc.boot_filename_len },
        5 => .{ .buf = &mc.http_boot_url_buf, .len = &mc.http_boot_url_len },
        6 => .{ .buf = &mc.time_offset_buf, .len = &mc.time_offset_len },
        else => null,
    };
}

/// Get the inline entry count for a MAC class inline target.
fn mcInlineCount(mc: *const MacClassEntry, target: McInlineTarget) usize {
    return switch (target) {
        .domain_search => mc.domain_search_count,
        .dns => mc.dns_servers_count,
        .ntp => mc.ntp_servers_count,
        .log => mc.log_servers_count,
        .wins => mc.wins_servers_count,
        .tftp => mc.tftp_servers_count,
        .routes => mc.route_count,
        .options => mc.option_count,
    };
}

/// Get the max capacity for a MAC class inline target.
fn mcInlineMax(target: McInlineTarget) usize {
    return switch (target) {
        .domain_search => 8,
        .dns => 8,
        .ntp => 4,
        .log => 4,
        .wins => 2,
        .tftp => 4,
        .routes => 16,
        .options => 32,
    };
}

/// Which kind of navigable item the active field in the MAC class form corresponds to.
const McActiveFieldKind = enum { field, add_button, inline_entry };
const McActiveFieldInfo = struct {
    kind: McActiveFieldKind,
    field_idx: u8 = 0,
    inline_target: ?McInlineTarget = null,
    entry_index: usize = 0,
};

/// Walk mac_class_layout to determine what the given active_field maps to.
fn mcActiveFieldInfo(mc: *const MacClassEntry, af: u8) McActiveFieldInfo {
    var pos: u8 = 0;
    for (mac_class_layout) |item| {
        switch (item.kind) {
            .section => {},
            .field => {
                if (pos == af) return .{ .kind = .field, .field_idx = item.field_idx.? };
                pos += 1;
            },
            .inline_section => {
                const target = item.inline_target.?;
                const count = mcInlineCount(mc, target);
                // [+] Add button.
                if (pos == af) return .{ .kind = .add_button, .inline_target = target };
                pos += 1;
                // Existing entries.
                for (0..count) |ei| {
                    if (pos == af) return .{ .kind = .inline_entry, .inline_target = target, .entry_index = ei };
                    pos += 1;
                }
            },
        }
    }
    return .{ .kind = .field, .field_idx = 0 };
}

/// Total navigable fields in the MAC class form.
fn mcTotalFields(mc: *const MacClassEntry) u8 {
    var pos: u8 = 0;
    for (mac_class_layout) |item| {
        switch (item.kind) {
            .section => {},
            .field => pos += 1,
            .inline_section => {
                pos += 1; // [+] button
                pos += @intCast(mcInlineCount(mc, item.inline_target.?));
            },
        }
    }
    return pos;
}

/// Cursor length for a given mac class active field position.
fn mcActiveFieldCursorLen(mc: *const MacClassEntry, af: u8) usize {
    const info = mcActiveFieldInfo(mc, af);
    return switch (info.kind) {
        .field => macClassFieldLen(mc, info.field_idx),
        .add_button, .inline_entry => 0,
    };
}

fn renderMacClassEdit(state: *TuiState, win: vaxis.Window, fa: std.mem.Allocator) !void {
    const form = &state.pool_form;
    const mc = &form.mac_class_edit;

    const BOX_W: u16 = @max(58, @min(win.width * 3 / 4, win.width -| 6));
    const BOX_H: u16 = @max(14, @min(win.height * 3 / 4, win.height -| 4));
    if (win.width < 40 or win.height < 10) return;
    const x = (win.width - BOX_W) / 2;
    const y = (win.height - BOX_H) / 2;
    const box = win.child(.{ .x_off = x, .y_off = y, .width = BOX_W, .height = BOX_H });
    box.fill(.{ .char = .{ .grapheme = " ", .width = 1 }, .style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } } });

    const bg: vaxis.Style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 160, 255 } }, .bg = bg.bg };
    drawBox(box, 0, 0, BOX_W, BOX_H, border_style);
    const section_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 80, 180, 255 } }, .bg = bg.bg, .bold = true };
    const label_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 160, 160, 190 } }, .bg = bg.bg };
    const field_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 200, 200, 200 } }, .bg = .{ .rgb = .{ 30, 30, 45 } } };
    const active_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 255, 255 } }, .bg = .{ .rgb = .{ 50, 80, 140 } } };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = bg.bg };
    const err_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 80, 80 } }, .bg = bg.bg };
    const close_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 80, 80 } }, .bg = bg.bg, .bold = true };
    const title_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 200, 80 } }, .bg = bg.bg, .bold = true };
    const opt_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 180, 200 } }, .bg = .{ .rgb = .{ 30, 30, 42 } } };

    // Title + [X].
    const title: []const u8 = if (form.mac_class_edit_index == null) "  New MAC Class" else "  Edit MAC Class";
    _ = box.print(&.{.{ .text = title, .style = title_style }}, .{ .col_offset = 1, .row_offset = 1, .wrap = .none });
    _ = box.print(&.{.{ .text = "[X]", .style = close_style }}, .{ .col_offset = BOX_W -| 4, .row_offset = 0, .wrap = .none });

    const field_h = BOX_H - 4; // top border + title + hint + bottom border
    const LABEL_W: u16 = 17;
    const FIELD_W: u16 = BOX_W -| LABEL_W -| 3;

    // Compute the absolute row for the active field by walking mac_class_layout.
    var active_row: u16 = 0;
    var total_rows: u16 = 0;
    {
        var r: u16 = 0;
        var pos: u8 = 0;
        for (mac_class_layout) |item| {
            switch (item.kind) {
                .section => r += 2,
                .field => {
                    if (pos == form.mac_class_edit_field) active_row = r;
                    r += 1;
                    pos += 1;
                },
                .inline_section => {
                    const count = mcInlineCount(mc, item.inline_target.?);
                    if (pos == form.mac_class_edit_field) active_row = r;
                    r += 1; // [+] button
                    pos += 1;
                    for (0..count) |_| {
                        if (pos == form.mac_class_edit_field) active_row = r;
                        r += 1;
                        pos += 1;
                    }
                },
            }
        }
        total_rows = r;
    }

    // Center active field in view.
    const half = field_h / 2;
    var scroll_row: u16 = if (active_row > half) active_row - half else 0;
    const max_scroll = if (total_rows + 1 > field_h) total_rows + 1 - field_h else 0;
    if (scroll_row > max_scroll) scroll_row = max_scroll;
    form.mac_class_edit_scroll = scroll_row;

    // ---- Render by walking mac_class_layout ----
    var abs_row: u16 = 0;
    var draw_row: u16 = 2;
    var pos: u8 = 0;

    for (mac_class_layout) |item| {
        if (draw_row >= BOX_H - 2) break;
        switch (item.kind) {
            .section => {
                // Blank line.
                if (abs_row >= scroll_row and draw_row < BOX_H - 2) draw_row += 1;
                abs_row += 1;
                // Section header.
                if (abs_row >= scroll_row and draw_row < BOX_H - 2) {
                    const sec_text = std.fmt.allocPrint(fa, "  -- {s} --", .{item.label}) catch "";
                    _ = box.print(&.{.{ .text = sec_text, .style = section_style }}, .{ .col_offset = 1, .row_offset = draw_row, .wrap = .none });
                    draw_row += 1;
                }
                abs_row += 1;
            },
            .field => {
                const fi = item.field_idx.?;
                const is_active = pos == form.mac_class_edit_field;
                if (abs_row >= scroll_row and draw_row < BOX_H - 2) {
                    const meta = mac_class_field_meta[fi];
                    const style = if (is_active) active_style else field_style;
                    const val = macClassFieldVal(mc, fi);
                    const label_text = std.fmt.allocPrint(fa, "  {s:<15}", .{meta.label}) catch "";
                    _ = box.print(&.{.{ .text = label_text, .style = label_style }}, .{ .col_offset = 1, .row_offset = draw_row, .wrap = .none });

                    const fw = @as(usize, FIELD_W);
                    var vis_start: usize = 0;
                    var cursor_vis: usize = 0;
                    if (is_active) {
                        const cur = @min(form.mac_class_edit_cursor, val.len);
                        if (cur >= fw) vis_start = cur - fw + 1;
                        cursor_vis = cur - vis_start;
                    }
                    const vis_end = @min(val.len, vis_start + fw);
                    const vis_text = val[vis_start..vis_end];
                    const pad_len = fw - vis_text.len;
                    const padded = std.fmt.allocPrint(fa, "{s}{s}", .{ vis_text, spaces(fa, @intCast(pad_len)) catch "" }) catch vis_text;
                    _ = box.print(&.{.{ .text = padded, .style = style }}, .{ .col_offset = LABEL_W + 1, .row_offset = draw_row, .wrap = .none });

                    // Cursor block.
                    if (is_active) {
                        const cursor_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 20, 20, 30 } }, .bg = .{ .rgb = .{ 100, 160, 255 } } };
                        const cursor_col = LABEL_W + 1 + @as(u16, @intCast(cursor_vis));
                        if (cursor_col < BOX_W -| 1) {
                            const cur_abs = vis_start + cursor_vis;
                            const ch: []const u8 = if (cur_abs < val.len) val[cur_abs..][0..1] else " ";
                            _ = box.print(&.{.{ .text = ch, .style = cursor_style }}, .{ .col_offset = cursor_col, .row_offset = draw_row, .wrap = .none });
                        }
                    }
                    draw_row += 1;
                }
                abs_row += 1;
                pos += 1;
            },
            .inline_section => {
                const target = item.inline_target.?;
                const count = mcInlineCount(mc, target);
                const is_add_active = pos == form.mac_class_edit_field;

                // [+] Add button.
                if (abs_row >= scroll_row and draw_row < BOX_H - 2) {
                    const add_label = std.fmt.allocPrint(fa, "  {s:<15}", .{item.label}) catch "";
                    _ = box.print(&.{.{ .text = add_label, .style = label_style }}, .{ .col_offset = 1, .row_offset = draw_row, .wrap = .none });
                    const at_max = count >= mcInlineMax(target);
                    if (at_max) {
                        const max_text = std.fmt.allocPrint(fa, "(max {d})", .{mcInlineMax(target)}) catch "(max)";
                        const grey_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = .{ .rgb = .{ 30, 30, 45 } } };
                        _ = box.print(&.{.{ .text = max_text, .style = grey_style }}, .{ .col_offset = LABEL_W + 1, .row_offset = draw_row, .wrap = .none });
                    } else {
                        const add_fs = if (is_add_active) active_style else field_style;
                        _ = box.print(&.{.{ .text = "[+] Add ", .style = add_fs }}, .{ .col_offset = LABEL_W + 1, .row_offset = draw_row, .wrap = .none });
                    }
                    draw_row += 1;
                }
                abs_row += 1;
                pos += 1;

                // Inline entries.
                for (0..count) |ei| {
                    if (draw_row >= BOX_H - 2) break;
                    const is_entry_active = pos == form.mac_class_edit_field;
                    if (abs_row >= scroll_row and draw_row < BOX_H - 2) {
                        const line_text: []const u8 = switch (target) {
                            .domain_search => blk: {
                                const d = &mc.domain_search[ei];
                                break :blk if (d.len > 0) d.buf[0..d.len] else "...";
                            },
                            .dns => blk: {
                                const d = &mc.dns_servers[ei];
                                break :blk if (d.len > 0) d.buf[0..d.len] else "...";
                            },
                            .ntp => blk: {
                                const d = &mc.ntp_servers[ei];
                                break :blk if (d.len > 0) d.buf[0..d.len] else "...";
                            },
                            .log => blk: {
                                const d = &mc.log_servers[ei];
                                break :blk if (d.len > 0) d.buf[0..d.len] else "...";
                            },
                            .wins => blk: {
                                const d = &mc.wins_servers[ei];
                                break :blk if (d.len > 0) d.buf[0..d.len] else "...";
                            },
                            .tftp => blk: {
                                const d = &mc.tftp_servers[ei];
                                break :blk if (d.len > 0) d.buf[0..d.len] else "...";
                            },
                            .routes => blk: {
                                const r = &mc.routes[ei];
                                const dest = r.dest_buf[0..r.dest_len];
                                const router = r.router_buf[0..r.router_len];
                                break :blk std.fmt.allocPrint(fa, "{s} via {s}", .{
                                    if (dest.len > 0) dest else "...",
                                    if (router.len > 0) router else "...",
                                }) catch "";
                            },
                            .options => blk: {
                                const o = &mc.options[ei];
                                const code = o.code_buf[0..o.code_len];
                                const opt_label = std.fmt.allocPrint(fa, "  Option {s:>3}", .{if (code.len > 0) code else "?"}) catch "  Option   ?";
                                _ = box.print(&.{.{ .text = opt_label, .style = label_style }}, .{ .col_offset = 1, .row_offset = draw_row, .wrap = .none });
                                const val = o.value_buf[0..o.value_len];
                                break :blk if (val.len > 0) val else "";
                            },
                        };
                        const os = if (is_entry_active) active_style else opt_style;
                        const opt_trunc = line_text[0..@min(line_text.len, FIELD_W)];
                        const opt_pad = FIELD_W -| @as(u16, @intCast(opt_trunc.len));
                        const opt_padded = try fa.alloc(u8, opt_pad);
                        @memset(opt_padded, ' ');
                        _ = box.print(&.{.{ .text = opt_trunc, .style = os }}, .{ .col_offset = LABEL_W + 1, .row_offset = draw_row, .wrap = .none });
                        _ = box.print(&.{.{ .text = opt_padded, .style = os }}, .{ .col_offset = LABEL_W + 1 + @as(u16, @intCast(opt_trunc.len)), .row_offset = draw_row, .wrap = .none });
                        draw_row += 1;
                    }
                    abs_row += 1;
                    pos += 1;
                }
            },
        }
    }

    // Hint + error.
    const af_info = mcActiveFieldInfo(mc, form.mac_class_edit_field);
    const is_add_btn = af_info.kind == .add_button;
    const is_inline_entry = af_info.kind == .inline_entry;
    const hint_text: []const u8 = if (is_inline_entry)
        "  Enter:edit  d:delete  Tab:next  Esc:cancel"
    else if (is_add_btn)
        "  Enter:add  Tab:next  Shift-Tab:prev  Esc:cancel"
    else
        "  Tab:next  Shift-Tab:prev  Enter:save  Esc:cancel";
    _ = box.print(&.{.{ .text = hint_text, .style = hint_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 2, .wrap = .none });
    if (form.err_len > 0) {
        _ = box.print(&.{.{ .text = form.err_buf[0..form.err_len], .style = err_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 3, .wrap = .none });
    }
}

fn handleMacClassEditKey(state: *TuiState, key: vaxis.Key) void {
    var form = &state.pool_form;
    const mc = &form.mac_class_edit;

    if (key.matches(vaxis.Key.escape, .{})) {
        form.err_len = 0;
        state.mode = .pool_form;
        return;
    }

    // Determine what the active_field points to via mac_class_layout walk.
    const af_info = mcActiveFieldInfo(mc, form.mac_class_edit_field);

    // 'd' deletes selected inline entry.
    if (key.matches('d', .{}) and af_info.kind == .inline_entry) {
        const target = af_info.inline_target.?;
        const ei = af_info.entry_index;
        switch (target) {
            .domain_search => deleteInlineEntry(InlineEntry, &form.mac_class_edit.domain_search, &form.mac_class_edit.domain_search_count, ei),
            .dns => deleteInlineEntry(InlineEntry, &form.mac_class_edit.dns_servers, &form.mac_class_edit.dns_servers_count, ei),
            .ntp => deleteInlineEntry(InlineEntry, &form.mac_class_edit.ntp_servers, &form.mac_class_edit.ntp_servers_count, ei),
            .log => deleteInlineEntry(InlineEntry, &form.mac_class_edit.log_servers, &form.mac_class_edit.log_servers_count, ei),
            .wins => deleteInlineEntry(InlineEntry, &form.mac_class_edit.wins_servers, &form.mac_class_edit.wins_servers_count, ei),
            .tftp => deleteInlineEntry(InlineEntry, &form.mac_class_edit.tftp_servers, &form.mac_class_edit.tftp_servers_count, ei),
            .routes => {
                if (ei < form.mac_class_edit.route_count) {
                    var i: usize = ei;
                    while (i + 1 < form.mac_class_edit.route_count) : (i += 1) {
                        form.mac_class_edit.routes[i] = form.mac_class_edit.routes[i + 1];
                    }
                    form.mac_class_edit.route_count -= 1;
                }
            },
            .options => {
                if (ei < form.mac_class_edit.option_count) {
                    var i: usize = ei;
                    while (i + 1 < form.mac_class_edit.option_count) : (i += 1) {
                        form.mac_class_edit.options[i] = form.mac_class_edit.options[i + 1];
                    }
                    form.mac_class_edit.option_count -= 1;
                }
            },
        }
        if (form.mac_class_edit_field >= mcTotalFields(&form.mac_class_edit)) form.mac_class_edit_field -|= 1;
        return;
    }

    if (key.matches(vaxis.Key.enter, .{})) {
        // [+] Add buttons.
        if (af_info.kind == .add_button) {
            const target = af_info.inline_target.?;
            form.server_edit_parent = .mac_class_edit;
            switch (target) {
                .domain_search, .dns, .ntp, .log, .wins, .tftp => {
                    if (mcInlineCount(mc, target) >= mcInlineMax(target)) return;
                    const set: ServerEditTarget = switch (target) {
                        .domain_search => .domain_search,
                        .dns => .dns,
                        .ntp => .ntp,
                        .log => .log,
                        .wins => .wins,
                        .tftp => .tftp,
                        else => unreachable,
                    };
                    openServerEdit(form, state, set, null);
                    return;
                },
                .routes => {
                    form.err_len = 0;
                    form.route_edit_dest_len = 0;
                    form.route_edit_router_len = 0;
                    form.route_edit_field = 0;
                    form.route_edit_cursor = 0;
                    form.route_edit_index = null;
                    state.mode = .pool_route_edit;
                    return;
                },
                .options => {
                    form.err_len = 0;
                    form.opt_edit_code_len = 0;
                    form.opt_edit_value_len = 0;
                    form.opt_edit_field = 0;
                    form.opt_edit_cursor = 0;
                    form.opt_edit_index = null;
                    state.mode = .pool_option_edit;
                    return;
                },
            }
        }
        // Existing inline entries -> edit.
        if (af_info.kind == .inline_entry) {
            const target = af_info.inline_target.?;
            const ei = af_info.entry_index;
            form.server_edit_parent = .mac_class_edit;
            switch (target) {
                .domain_search, .dns, .ntp, .log, .wins, .tftp => {
                    const set: ServerEditTarget = switch (target) {
                        .domain_search => .domain_search,
                        .dns => .dns,
                        .ntp => .ntp,
                        .log => .log,
                        .wins => .wins,
                        .tftp => .tftp,
                        else => unreachable,
                    };
                    openServerEdit(form, state, set, ei);
                    return;
                },
                .routes => {
                    if (ei < form.mac_class_edit.route_count) {
                        form.err_len = 0;
                        const r = &form.mac_class_edit.routes[ei];
                        @memcpy(form.route_edit_dest[0..r.dest_len], r.dest_buf[0..r.dest_len]);
                        form.route_edit_dest_len = r.dest_len;
                        @memcpy(form.route_edit_router[0..r.router_len], r.router_buf[0..r.router_len]);
                        form.route_edit_router_len = r.router_len;
                        form.route_edit_field = 0;
                        form.route_edit_cursor = r.dest_len;
                        form.route_edit_index = ei;
                        state.mode = .pool_route_edit;
                    }
                    return;
                },
                .options => {
                    if (ei < form.mac_class_edit.option_count) {
                        form.err_len = 0;
                        const o = &form.mac_class_edit.options[ei];
                        @memcpy(form.opt_edit_code[0..o.code_len], o.code_buf[0..o.code_len]);
                        form.opt_edit_code_len = o.code_len;
                        @memcpy(form.opt_edit_value[0..o.value_len], o.value_buf[0..o.value_len]);
                        form.opt_edit_value_len = o.value_len;
                        form.opt_edit_field = 0;
                        form.opt_edit_cursor = o.code_len;
                        form.opt_edit_index = ei;
                        state.mode = .pool_option_edit;
                    }
                    return;
                },
            }
        }

        // Regular field: Enter saves the form.
        form.err_len = 0;
        // Validate required fields.
        if (form.mac_class_edit.name_len == 0) {
            const msg = "  Name is required";
            form.err_len = msg.len;
            @memcpy(form.err_buf[0..msg.len], msg);
            return;
        }
        if (form.mac_class_edit.match_len == 0) {
            const msg = "  Match pattern is required";
            form.err_len = msg.len;
            @memcpy(form.err_buf[0..msg.len], msg);
            return;
        }
        // Validate match pattern: hex digits, colons, and wildcards (*).
        const match = form.mac_class_edit.match_buf[0..form.mac_class_edit.match_len];
        for (match) |ch| {
            if (!((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f') or
                (ch >= 'A' and ch <= 'F') or ch == ':' or ch == '*'))
            {
                const msg = "  Match: hex digits, colons, * only";
                form.err_len = msg.len;
                @memcpy(form.err_buf[0..msg.len], msg);
                return;
            }
        }
        // Validate router if present.
        if (form.mac_class_edit.router_len > 0) {
            _ = config_mod.parseIpv4(form.mac_class_edit.router_buf[0..form.mac_class_edit.router_len]) catch {
                const msg = "  Invalid router IP";
                form.err_len = msg.len;
                @memcpy(form.err_buf[0..msg.len], msg);
                return;
            };
        }
        // Save.
        if (form.mac_class_edit_index) |idx| {
            if (idx < form.mac_class_count) {
                form.mac_classes[idx] = form.mac_class_edit;
            }
        } else {
            if (form.mac_class_count < form.mac_classes.len) {
                form.mac_classes[form.mac_class_count] = form.mac_class_edit;
                form.mac_class_count += 1;
            }
        }
        state.mode = .pool_form;
        return;
    }

    // Field navigation.
    if (key.matches(vaxis.Key.tab, .{}) or key.matches(vaxis.Key.down, .{})) {
        if (form.mac_class_edit_field + 1 < mcTotalFields(&form.mac_class_edit)) {
            form.mac_class_edit_field += 1;
            form.mac_class_edit_cursor = mcActiveFieldCursorLen(&form.mac_class_edit, form.mac_class_edit_field);
        }
        return;
    }
    if (key.matches(vaxis.Key.tab, .{ .shift = true }) or key.matches(vaxis.Key.up, .{})) {
        if (form.mac_class_edit_field > 0) {
            form.mac_class_edit_field -= 1;
            form.mac_class_edit_cursor = mcActiveFieldCursorLen(&form.mac_class_edit, form.mac_class_edit_field);
        }
        return;
    }

    // Non-text fields: [+] buttons, inline entries.
    if (af_info.kind != .field) return;

    // Cursor movement.
    const fi = af_info.field_idx;
    if (key.matches(vaxis.Key.left, .{})) {
        if (form.mac_class_edit_cursor > 0) form.mac_class_edit_cursor -= 1;
        return;
    }
    if (key.matches(vaxis.Key.right, .{})) {
        if (form.mac_class_edit_cursor < macClassFieldLen(&form.mac_class_edit, fi))
            form.mac_class_edit_cursor += 1;
        return;
    }
    if (key.matches(vaxis.Key.home, .{})) {
        form.mac_class_edit_cursor = 0;
        return;
    }
    if (key.matches(vaxis.Key.end, .{})) {
        form.mac_class_edit_cursor = macClassFieldLen(&form.mac_class_edit, fi);
        return;
    }

    // Text editing.
    if (key.matches(vaxis.Key.backspace, .{})) {
        if (macClassFieldBuf(&form.mac_class_edit, fi)) |fb| {
            if (form.mac_class_edit_cursor > 0 and fb.len.* > 0) {
                const tpos = form.mac_class_edit_cursor;
                if (tpos < fb.len.*) std.mem.copyForwards(u8, fb.buf[tpos - 1 ..], fb.buf[tpos..fb.len.*]);
                fb.len.* -= 1;
                form.mac_class_edit_cursor -= 1;
            }
        }
    } else if (key.matches(vaxis.Key.delete, .{})) {
        if (macClassFieldBuf(&form.mac_class_edit, fi)) |fb| {
            if (form.mac_class_edit_cursor < fb.len.*) {
                std.mem.copyForwards(u8, fb.buf[form.mac_class_edit_cursor..], fb.buf[form.mac_class_edit_cursor + 1 .. fb.len.*]);
                fb.len.* -= 1;
            }
        }
    } else if (key.codepoint >= 0x20 and key.codepoint <= 0x7E) {
        const ch: u8 = @intCast(key.codepoint);
        // Per-field character filtering.
        const allowed = switch (fi) {
            0 => (ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '_' or ch == '-' or ch == ' ', // Name
            1 => (ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f') or (ch >= 'A' and ch <= 'F') or ch == ':' or ch == '*', // Match
            2 => (ch >= '0' and ch <= '9') or ch == '.', // Router (IP)
            3 => (ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '.' or ch == '-' or ch == '_', // Domain Name
            4 => (ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '.' or ch == '_' or ch == '-' or ch == '/', // Boot filename
            5 => ch >= 0x20 and ch <= 0x7E, // HTTP Boot URL (all printable)
            6 => (ch >= '0' and ch <= '9') or ch == '-', // Time Offset (signed int)
            else => true,
        };
        if (!allowed) return;
        if (macClassFieldBuf(&form.mac_class_edit, fi)) |fb| {
            if (fb.len.* < fb.buf.len) {
                const tpos = form.mac_class_edit_cursor;
                if (tpos < fb.len.*) std.mem.copyBackwards(u8, fb.buf[tpos + 1 ..], fb.buf[tpos..fb.len.*]);
                fb.buf[tpos] = ch;
                fb.len.* += 1;
                form.mac_class_edit_cursor += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pool option lookup modal
// ---------------------------------------------------------------------------

fn renderPoolOptionLookup(state: *TuiState, win: vaxis.Window, fa: std.mem.Allocator) !void {
    const form = &state.pool_form;
    const BOX_W: u16 = 40;
    const BOX_H: u16 = @min(win.height -| 2, 22);
    if (win.width < BOX_W or win.height < 8) return;
    const x = (win.width - BOX_W) / 2;
    const y = (win.height -| BOX_H) / 2;
    const box = win.child(.{ .x_off = x, .y_off = y, .width = BOX_W, .height = BOX_H });
    box.fill(.{ .char = .{ .grapheme = " ", .width = 1 }, .style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } } });
    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 160, 255 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    drawBox(box, 0, 0, BOX_W, BOX_H, border_style);
    const title_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 200, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    const sel_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 255, 255 } }, .bg = .{ .rgb = .{ 50, 80, 140 } } };
    const norm_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 200, 200, 200 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const filter_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 220, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const close_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 80, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };

    _ = box.print(&.{.{ .text = "  DHCP Options", .style = title_style }}, .{ .col_offset = 1, .row_offset = 1, .wrap = .none });
    _ = box.print(&.{.{ .text = "[X]", .style = close_style }}, .{ .col_offset = BOX_W -| 4, .row_offset = 0, .wrap = .none });

    // Filter bar.
    if (form.opt_lookup_filter_len > 0) {
        const filter_text = try std.fmt.allocPrint(fa, "  / {s}", .{form.opt_lookup_filter[0..form.opt_lookup_filter_len]});
        _ = box.print(&.{.{ .text = filter_text, .style = filter_style }}, .{ .col_offset = 1, .row_offset = 2, .wrap = .none });
    }

    // Count filtered options and clamp selection.
    const filter = form.opt_lookup_filter[0..form.opt_lookup_filter_len];
    var filtered_count: u16 = 0;
    for (known_dhcp_options) |ko| {
        if (filter.len > 0) {
            if (!containsIgnoreCase(ko.code, filter) and !containsIgnoreCase(ko.name, filter)) continue;
        }
        filtered_count += 1;
    }
    if (filtered_count > 0 and form.opt_lookup_row >= filtered_count) form.opt_lookup_row = filtered_count - 1;

    // Scrollable list.
    const start_row: u16 = 3;
    const visible_rows: u16 = BOX_H -| start_row -| 2;
    var scroll: u16 = 0;
    if (form.opt_lookup_row >= visible_rows) scroll = form.opt_lookup_row - visible_rows + 1;

    var visible_idx: u16 = 0;
    for (known_dhcp_options) |ko| {
        if (filter.len > 0) {
            if (!containsIgnoreCase(ko.code, filter) and !containsIgnoreCase(ko.name, filter)) continue;
        }
        if (visible_idx >= scroll and visible_idx - scroll < visible_rows) {
            const draw_row = start_row + visible_idx - scroll;
            const is_sel = visible_idx == form.opt_lookup_row;
            const style = if (is_sel) sel_style else norm_style;
            const line = try std.fmt.allocPrint(fa, "  {s:<5} {s}", .{ ko.code, ko.name });
            _ = box.print(&.{.{ .text = line, .style = style }}, .{ .col_offset = 1, .row_offset = draw_row, .wrap = .none });
        }
        visible_idx += 1;
    }

    _ = box.print(&.{.{ .text = "  /:filter  Enter:select  Esc:back", .style = hint_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 2, .wrap = .none });
}

fn handlePoolOptionLookupKey(state: *TuiState, key: vaxis.Key) void {
    var form = &state.pool_form;

    if (key.matches(vaxis.Key.escape, .{})) {
        state.mode = .pool_option_edit;
        return;
    }
    if (key.matches(vaxis.Key.enter, .{})) {
        // Select the option at the current row.
        const filter = form.opt_lookup_filter[0..form.opt_lookup_filter_len];
        var idx: u16 = 0;
        for (known_dhcp_options) |ko| {
            if (filter.len > 0) {
                if (!containsIgnoreCase(ko.code, filter) and !containsIgnoreCase(ko.name, filter)) continue;
            }
            if (idx == form.opt_lookup_row) {
                // Populate the code field.
                const n = @min(ko.code.len, form.opt_edit_code.len);
                @memcpy(form.opt_edit_code[0..n], ko.code[0..n]);
                form.opt_edit_code_len = n;
                form.opt_edit_cursor = n;
                state.mode = .pool_option_edit;
                return;
            }
            idx += 1;
        }
        state.mode = .pool_option_edit;
        return;
    }
    if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{})) {
        form.opt_lookup_row +|= 1;
    } else if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{})) {
        form.opt_lookup_row -|= 1;
    } else if (key.matches('/', .{})) {
        // Already in filter mode -- just keep typing.
    } else if (key.matches(vaxis.Key.backspace, .{})) {
        if (form.opt_lookup_filter_len > 0) {
            form.opt_lookup_filter_len -= 1;
            form.opt_lookup_row = 0;
        }
    } else if (key.codepoint >= 0x20 and key.codepoint <= 0x7E) {
        if (form.opt_lookup_filter_len < form.opt_lookup_filter.len) {
            form.opt_lookup_filter[form.opt_lookup_filter_len] = @intCast(key.codepoint);
            form.opt_lookup_filter_len += 1;
            form.opt_lookup_row = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Reservation option add/edit modal
// ---------------------------------------------------------------------------

fn renderResOptionEdit(state: *TuiState, win: vaxis.Window, fa: std.mem.Allocator) !void {
    const form = &state.form;
    const BOX_W: u16 = 48;
    const has_err = form.err_len > 0;
    const BOX_H: u16 = if (has_err) 9 else 8;
    if (win.width < BOX_W or win.height < BOX_H) return;
    const x = (win.width - BOX_W) / 2;
    const y = (win.height -| BOX_H) / 2;
    const box = win.child(.{ .x_off = x, .y_off = y, .width = BOX_W, .height = BOX_H });
    box.fill(.{ .char = .{ .grapheme = " ", .width = 1 }, .style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } } });
    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 160, 255 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    drawBox(box, 0, 0, BOX_W, BOX_H, border_style);
    const title_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 200, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    const label_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 160, 160, 190 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const field_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 200, 200, 200 } }, .bg = .{ .rgb = .{ 30, 30, 45 } } };
    const active_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 255, 255 } }, .bg = .{ .rgb = .{ 50, 80, 140 } } };
    const cursor_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 20, 20, 30 } }, .bg = .{ .rgb = .{ 100, 160, 255 } } };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const close_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 80, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };

    const title = if (form.opt_edit_index == null) "  Add DHCP Option" else "  Edit DHCP Option";
    _ = box.print(&.{.{ .text = title, .style = title_style }}, .{ .col_offset = 1, .row_offset = 1, .wrap = .none });
    _ = box.print(&.{.{ .text = "[X]", .style = close_style }}, .{ .col_offset = BOX_W -| 4, .row_offset = 0, .wrap = .none });

    // Option number field.
    const code_active = form.opt_edit_field == 0;
    _ = box.print(&.{.{ .text = "  Option #  ", .style = label_style }}, .{ .col_offset = 1, .row_offset = 3, .wrap = .none });
    const code_val = form.opt_edit_code[0..form.opt_edit_code_len];
    const code_style = if (code_active) active_style else field_style;
    const code_pad = try fa.alloc(u8, 6 -| code_val.len);
    @memset(code_pad, ' ');
    _ = box.print(&.{.{ .text = code_val, .style = code_style }}, .{ .col_offset = 13, .row_offset = 3, .wrap = .none });
    _ = box.print(&.{.{ .text = code_pad, .style = code_style }}, .{ .col_offset = 13 + @as(u16, @intCast(code_val.len)), .row_offset = 3, .wrap = .none });
    if (code_active) {
        const cur = @min(form.opt_edit_cursor, code_val.len);
        const ch: []const u8 = if (cur < code_val.len) code_val[cur..][0..1] else " ";
        _ = box.print(&.{.{ .text = ch, .style = cursor_style }}, .{ .col_offset = 13 + @as(u16, @intCast(cur)), .row_offset = 3, .wrap = .none });
    }
    // Lookup hint.
    if (code_active) {
        _ = box.print(&.{.{ .text = "  l: lookup", .style = hint_style }}, .{ .col_offset = 20, .row_offset = 3, .wrap = .none });
    }

    // Value field.
    const val_active = form.opt_edit_field == 1;
    _ = box.print(&.{.{ .text = "  Value     ", .style = label_style }}, .{ .col_offset = 1, .row_offset = 4, .wrap = .none });
    const val_text = form.opt_edit_value[0..form.opt_edit_value_len];
    const val_fw: u16 = BOX_W -| 16;
    const val_style = if (val_active) active_style else field_style;
    const val_trunc = val_text[0..@min(val_text.len, val_fw)];
    const val_pad = try fa.alloc(u8, val_fw -| @as(u16, @intCast(val_trunc.len)));
    @memset(val_pad, ' ');
    _ = box.print(&.{.{ .text = val_trunc, .style = val_style }}, .{ .col_offset = 13, .row_offset = 4, .wrap = .none });
    _ = box.print(&.{.{ .text = val_pad, .style = val_style }}, .{ .col_offset = 13 + @as(u16, @intCast(val_trunc.len)), .row_offset = 4, .wrap = .none });
    if (val_active) {
        const cur = @min(form.opt_edit_cursor, val_text.len);
        const ch: []const u8 = if (cur < val_text.len) val_text[cur..][0..1] else " ";
        _ = box.print(&.{.{ .text = ch, .style = cursor_style }}, .{ .col_offset = 13 + @as(u16, @intCast(cur)), .row_offset = 4, .wrap = .none });
    }

    if (has_err) {
        const err_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 80, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
        _ = box.print(&.{.{ .text = form.err_buf[0..form.err_len], .style = err_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 3, .wrap = .none });
    }
    _ = box.print(&.{.{ .text = "  Tab: switch  Enter: save  Esc: cancel", .style = hint_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 2, .wrap = .none });
}

fn handleResOptionEditKey(state: *TuiState, key: vaxis.Key) void {
    var form = &state.form;

    if (key.matches(vaxis.Key.escape, .{})) {
        form.err_len = 0;
        state.mode = .reservation_form;
        return;
    }
    if (key.matches(vaxis.Key.enter, .{})) {
        form.err_len = 0;
        // Save the option.
        if (form.opt_edit_code_len == 0) {
            const msg = "  Option code is required";
            form.err_len = msg.len;
            @memcpy(form.err_buf[0..msg.len], msg);
            return;
        }
        // Validate code is 1-255.
        const code_val = std.fmt.parseInt(u16, form.opt_edit_code[0..form.opt_edit_code_len], 10) catch {
            const msg = "  Option code must be a number 1-255";
            form.err_len = msg.len;
            @memcpy(form.err_buf[0..msg.len], msg);
            return;
        };
        if (code_val == 0 or code_val > 255) {
            const msg = "  Option code must be 1-255";
            form.err_len = msg.len;
            @memcpy(form.err_buf[0..msg.len], msg);
            return;
        }
        if (form.opt_edit_index) |idx| {
            // Editing existing.
            if (idx < form.option_count) {
                @memcpy(form.options[idx].code_buf[0..form.opt_edit_code_len], form.opt_edit_code[0..form.opt_edit_code_len]);
                form.options[idx].code_len = form.opt_edit_code_len;
                @memcpy(form.options[idx].value_buf[0..form.opt_edit_value_len], form.opt_edit_value[0..form.opt_edit_value_len]);
                form.options[idx].value_len = form.opt_edit_value_len;
            }
        } else {
            // Adding new.
            if (form.option_count < form.options.len) {
                var new_opt = &form.options[form.option_count];
                new_opt.* = .{};
                @memcpy(new_opt.code_buf[0..form.opt_edit_code_len], form.opt_edit_code[0..form.opt_edit_code_len]);
                new_opt.code_len = form.opt_edit_code_len;
                @memcpy(new_opt.value_buf[0..form.opt_edit_value_len], form.opt_edit_value[0..form.opt_edit_value_len]);
                new_opt.value_len = form.opt_edit_value_len;
                form.option_count += 1;
            }
        }
        state.mode = .reservation_form;
        return;
    }
    if (key.matches(vaxis.Key.tab, .{}) or key.matches(vaxis.Key.tab, .{ .shift = true })) {
        form.opt_edit_field = if (form.opt_edit_field == 0) 1 else 0;
        form.opt_edit_cursor = if (form.opt_edit_field == 0) form.opt_edit_code_len else form.opt_edit_value_len;
        return;
    }

    // 'l' on the code field opens lookup.
    if (form.opt_edit_field == 0 and key.matches('l', .{})) {
        form.opt_lookup_filter_len = 0;
        form.opt_lookup_row = 0;
        state.mode = .option_lookup;
        return;
    }

    // Text editing.
    form.err_len = 0;
    const buf: []u8 = if (form.opt_edit_field == 0) &form.opt_edit_code else &form.opt_edit_value;
    const len: *usize = if (form.opt_edit_field == 0) &form.opt_edit_code_len else &form.opt_edit_value_len;
    const max_len = buf.len;

    if (key.matches(vaxis.Key.backspace, .{})) {
        if (form.opt_edit_cursor > 0 and len.* > 0) {
            const pos = form.opt_edit_cursor;
            if (pos < len.*) std.mem.copyForwards(u8, buf[pos - 1 ..], buf[pos..len.*]);
            len.* -= 1;
            form.opt_edit_cursor -= 1;
        }
    } else if (key.matches(vaxis.Key.left, .{})) {
        if (form.opt_edit_cursor > 0) form.opt_edit_cursor -= 1;
    } else if (key.matches(vaxis.Key.right, .{})) {
        if (form.opt_edit_cursor < len.*) form.opt_edit_cursor += 1;
    } else if (key.matches(vaxis.Key.home, .{})) {
        form.opt_edit_cursor = 0;
    } else if (key.matches(vaxis.Key.end, .{})) {
        form.opt_edit_cursor = len.*;
    } else if (key.codepoint >= 0x20 and key.codepoint <= 0x7E) {
        // Code field: numbers only.
        if (form.opt_edit_field == 0 and (key.codepoint < '0' or key.codepoint > '9')) return;
        if (len.* < max_len) {
            const pos = form.opt_edit_cursor;
            if (pos < len.*) std.mem.copyBackwards(u8, buf[pos + 1 ..], buf[pos..len.*]);
            buf[pos] = @intCast(key.codepoint);
            len.* += 1;
            form.opt_edit_cursor += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Option lookup modal
// ---------------------------------------------------------------------------

fn renderOptionLookup(state: *TuiState, win: vaxis.Window, fa: std.mem.Allocator) !void {
    const form = &state.form;
    const BOX_W: u16 = 40;
    const BOX_H: u16 = @min(win.height -| 2, 22);
    if (win.width < BOX_W or win.height < 8) return;
    const x = (win.width - BOX_W) / 2;
    const y = (win.height -| BOX_H) / 2;
    const box = win.child(.{ .x_off = x, .y_off = y, .width = BOX_W, .height = BOX_H });
    box.fill(.{ .char = .{ .grapheme = " ", .width = 1 }, .style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } } });
    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 160, 255 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    drawBox(box, 0, 0, BOX_W, BOX_H, border_style);
    const title_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 200, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    const sel_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 255, 255 } }, .bg = .{ .rgb = .{ 50, 80, 140 } } };
    const norm_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 200, 200, 200 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const filter_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 220, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const close_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 80, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };

    _ = box.print(&.{.{ .text = "  DHCP Options", .style = title_style }}, .{ .col_offset = 1, .row_offset = 1, .wrap = .none });
    _ = box.print(&.{.{ .text = "[X]", .style = close_style }}, .{ .col_offset = BOX_W -| 4, .row_offset = 0, .wrap = .none });

    // Filter bar.
    if (form.opt_lookup_filter_len > 0) {
        const filter_text = try std.fmt.allocPrint(fa, "  / {s}", .{form.opt_lookup_filter[0..form.opt_lookup_filter_len]});
        _ = box.print(&.{.{ .text = filter_text, .style = filter_style }}, .{ .col_offset = 1, .row_offset = 2, .wrap = .none });
    }

    // Count filtered options and clamp selection.
    const filter = form.opt_lookup_filter[0..form.opt_lookup_filter_len];
    var filtered_count: u16 = 0;
    for (known_dhcp_options) |ko| {
        if (filter.len > 0) {
            if (!containsIgnoreCase(ko.code, filter) and !containsIgnoreCase(ko.name, filter)) continue;
        }
        filtered_count += 1;
    }
    if (filtered_count > 0 and form.opt_lookup_row >= filtered_count) form.opt_lookup_row = filtered_count - 1;

    // Scrollable list.
    const start_row: u16 = 3;
    const visible_rows: u16 = BOX_H -| start_row -| 2;
    var scroll: u16 = 0;
    if (form.opt_lookup_row >= visible_rows) scroll = form.opt_lookup_row - visible_rows + 1;

    var visible_idx: u16 = 0;
    for (known_dhcp_options) |ko| {
        if (filter.len > 0) {
            if (!containsIgnoreCase(ko.code, filter) and !containsIgnoreCase(ko.name, filter)) continue;
        }
        if (visible_idx >= scroll and visible_idx - scroll < visible_rows) {
            const draw_row = start_row + visible_idx - scroll;
            const is_sel = visible_idx == form.opt_lookup_row;
            const style = if (is_sel) sel_style else norm_style;
            const line = try std.fmt.allocPrint(fa, "  {s:<5} {s}", .{ ko.code, ko.name });
            _ = box.print(&.{.{ .text = line, .style = style }}, .{ .col_offset = 1, .row_offset = draw_row, .wrap = .none });
        }
        visible_idx += 1;
    }

    _ = box.print(&.{.{ .text = "  /:filter  Enter:select  Esc:back", .style = hint_style }}, .{ .col_offset = 1, .row_offset = BOX_H - 2, .wrap = .none });
}

fn handleOptionLookupKey(state: *TuiState, key: vaxis.Key) void {
    var form = &state.form;

    if (key.matches(vaxis.Key.escape, .{})) {
        state.mode = .res_option_edit;
        return;
    }
    if (key.matches(vaxis.Key.enter, .{})) {
        // Select the option at the current row.
        const filter = form.opt_lookup_filter[0..form.opt_lookup_filter_len];
        var idx: u16 = 0;
        for (known_dhcp_options) |ko| {
            if (filter.len > 0) {
                if (!containsIgnoreCase(ko.code, filter) and !containsIgnoreCase(ko.name, filter)) continue;
            }
            if (idx == form.opt_lookup_row) {
                // Populate the code field.
                const n = @min(ko.code.len, form.opt_edit_code.len);
                @memcpy(form.opt_edit_code[0..n], ko.code[0..n]);
                form.opt_edit_code_len = n;
                form.opt_edit_cursor = n;
                state.mode = .res_option_edit;
                return;
            }
            idx += 1;
        }
        state.mode = .res_option_edit;
        return;
    }
    if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{})) {
        form.opt_lookup_row +|= 1;
    } else if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{})) {
        form.opt_lookup_row -|= 1;
    } else if (key.matches('/', .{})) {
        // Already in filter mode — just keep typing.
    } else if (key.matches(vaxis.Key.backspace, .{})) {
        if (form.opt_lookup_filter_len > 0) {
            form.opt_lookup_filter_len -= 1;
            form.opt_lookup_row = 0;
        }
    } else if (key.codepoint >= 0x20 and key.codepoint <= 0x7E) {
        if (form.opt_lookup_filter_len < form.opt_lookup_filter.len) {
            form.opt_lookup_filter[form.opt_lookup_filter_len] = @intCast(key.codepoint);
            form.opt_lookup_filter_len += 1;
            form.opt_lookup_row = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

test "calcDynColWidth: result covers window width" {
    // 6-column layout at common terminal widths
    for ([_]u16{ 80, 100, 120, 132, 200 }) |w| {
        const cw = calcDynColWidth(w, 6);
        try std.testing.expect(@as(u32, cw) * 6 >= @as(u32, w) -| 1);
    }
}

test "calcDynColWidth: zero columns returns full width" {
    try std.testing.expectEqual(@as(u16, 80), calcDynColWidth(80, 0));
}

test "calcDynColWidth: single column returns full width" {
    const cw = calcDynColWidth(80, 1);
    try std.testing.expectEqual(@as(u16, 80), cw);
}

test "calcLeaseColWidths: fits within window" {
    const seps: u16 = 5;
    for ([_]u16{ 80, 100, 120, 200 }) |w| {
        const cols = calcLeaseColWidths(w);
        var total: u16 = seps;
        for (cols) |col_w| total += col_w;
        try std.testing.expect(total <= w);
    }
}

test "calcLeaseColWidths: ideal layout at wide terminal" {
    // At 200 chars, all columns should be at their ideal widths.
    const cols = calcLeaseColWidths(200);
    for (LEASE_COL_SPECS, 0..) |spec, i| {
        try std.testing.expectEqual(spec.ideal, cols[i]);
    }
}

test "calcLeaseColWidths: respects minimums at narrow terminal" {
    const cols = calcLeaseColWidths(40);
    for (LEASE_COL_SPECS, 0..) |spec, i| {
        try std.testing.expect(cols[i] >= spec.min);
    }
}

test "truncateCell: no truncation when fits" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const fa = arena.allocator();

    const result = try truncateCell(fa, "192.168.1.1", 15, true);
    try std.testing.expectEqualStrings("192.168.1.1", result);
}

test "truncateCell: right truncation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const fa = arena.allocator();

    const result = try truncateCell(fa, "very-long-hostname.example.com", 12, false);
    try std.testing.expectEqualStrings("very-long-h…", result);
    try std.testing.expectEqual(@as(usize, 11 + 3), result.len); // content(11) + "…"(3 bytes UTF-8)
}

test "truncateCell: left truncation for addresses" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const fa = arena.allocator();

    // "192.168.100.200" (len=15), width=10: content_len=9, take last 9 chars = "8.100.200"
    const result = try truncateCell(fa, "192.168.100.200", 10, true);
    try std.testing.expectEqualStrings("…8.100.200", result);
}

test "truncateCell: width=1 returns ellipsis" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const fa = arena.allocator();

    const result = try truncateCell(fa, "hello", 1, false);
    try std.testing.expectEqualStrings("…", result);
}

test "containsIgnoreCase: basic matching" {
    try std.testing.expect(containsIgnoreCase("Hello World", "hello"));
    try std.testing.expect(containsIgnoreCase("Hello World", "WORLD"));
    try std.testing.expect(containsIgnoreCase("Hello World", "lo Wo"));
    try std.testing.expect(!containsIgnoreCase("Hello World", "xyz"));
}

test "containsIgnoreCase: IP and MAC patterns" {
    try std.testing.expect(containsIgnoreCase("192.168.1.1", "192"));
    try std.testing.expect(containsIgnoreCase("aa:bb:cc:dd:ee:ff", "DD:EE"));
    try std.testing.expect(!containsIgnoreCase("192.168.1.1", "10.0"));
}

test "containsIgnoreCase: edge cases" {
    try std.testing.expect(containsIgnoreCase("abc", "")); // empty needle = always match
    try std.testing.expect(!containsIgnoreCase("", "abc")); // empty haystack, non-empty needle
    try std.testing.expect(containsIgnoreCase("", "")); // both empty
    try std.testing.expect(containsIgnoreCase("x", "x")); // exact match
    try std.testing.expect(!containsIgnoreCase("x", "xy")); // needle longer than haystack
}

test "LeaseSort.ipLess: numeric ordering" {
    try std.testing.expect(LeaseSort.ipLess("10.0.0.1", "10.0.0.2"));
    try std.testing.expect(!LeaseSort.ipLess("10.0.0.2", "10.0.0.1"));
    try std.testing.expect(!LeaseSort.ipLess("10.0.0.1", "10.0.0.1")); // equal = not less
    try std.testing.expect(LeaseSort.ipLess("192.168.1.1", "192.168.1.100"));
    try std.testing.expect(LeaseSort.ipLess("10.0.0.1", "192.168.0.0")); // 10.x < 192.x
    try std.testing.expect(LeaseSort.ipLess("0.0.0.0", "255.255.255.255"));
}

test "LeaseSort.expiresLess: timestamp ordering" {
    const mk = struct {
        fn lease(ip: []const u8, exp: i64, res: bool) state_mod.Lease {
            return .{ .mac = "aa:bb:cc:dd:ee:ff", .ip = ip, .hostname = null, .expires = exp, .reserved = res, .client_id = null };
        }
    };
    const a = mk.lease("10.0.0.1", 1000, false);
    const b = mk.lease("10.0.0.2", 2000, false);
    const r = mk.lease("10.0.0.3", 0, true); // reserved = expires as maxInt

    try std.testing.expect(LeaseSort.expiresLess(a, b)); // 1000 < 2000
    try std.testing.expect(!LeaseSort.expiresLess(b, a));
    try std.testing.expect(!LeaseSort.expiresLess(a, a)); // equal = not less
    try std.testing.expect(LeaseSort.expiresLess(b, r)); // dynamic < reserved (maxInt)
    try std.testing.expect(!LeaseSort.expiresLess(r, a)); // reserved not < dynamic
}

// ---------------------------------------------------------------------------
// Regression: SSH read return codes
// ---------------------------------------------------------------------------

test "SSH_AGAIN is not SSH_ERROR: regression for immediate TUI exit" {
    // The TUI event loop exits only when ssh_channel_read_timeout returns -1
    // (SSH_ERROR). SSH_AGAIN (-2) means no data available yet in non-blocking
    // mode and must NOT break the loop.
    //
    // This test pins the libssh constant values so that any change to those
    // constants (however unlikely) is caught immediately.
    try std.testing.expectEqual(@as(c_int, -1), c.SSH_ERROR);
    try std.testing.expectEqual(@as(c_int, -2), c.SSH_AGAIN);
    // Belt: confirm they are distinct so the if (n_raw == -1) branch works.
    try std.testing.expect(c.SSH_AGAIN != c.SSH_ERROR);
}

// ---------------------------------------------------------------------------
// handleLeaseKey navigation
// ---------------------------------------------------------------------------

test "handleLeaseKey: j/k move cursor down and up" {
    var state: TuiState = .{};
    var ctx: vaxis.widgets.Table.TableContext = .{
        .selected_bg = .{ .rgb = .{ 50, 50, 80 } },
        .active_bg = .{ .rgb = .{ 50, 80, 140 } },
    };

    // Move down from row 0.
    handleLeaseKey(&state, &ctx, .{ .codepoint = 'j' });
    try std.testing.expectEqual(@as(u16, 1), ctx.row);
    handleLeaseKey(&state, &ctx, .{ .codepoint = 'j' });
    try std.testing.expectEqual(@as(u16, 2), ctx.row);

    // Move up.
    handleLeaseKey(&state, &ctx, .{ .codepoint = 'k' });
    try std.testing.expectEqual(@as(u16, 1), ctx.row);

    // Move up past 0 saturates at 0.
    handleLeaseKey(&state, &ctx, .{ .codepoint = 'k' });
    handleLeaseKey(&state, &ctx, .{ .codepoint = 'k' });
    try std.testing.expectEqual(@as(u16, 0), ctx.row);
}

test "handleLeaseKey: page_down and page_up step by 20" {
    var state: TuiState = .{};
    var ctx: vaxis.widgets.Table.TableContext = .{
        .selected_bg = .{ .rgb = .{ 50, 50, 80 } },
        .active_bg = .{ .rgb = .{ 50, 80, 140 } },
    };

    handleLeaseKey(&state, &ctx, .{ .codepoint = vaxis.Key.page_down });
    try std.testing.expectEqual(@as(u16, 20), ctx.row);

    handleLeaseKey(&state, &ctx, .{ .codepoint = vaxis.Key.page_up });
    try std.testing.expectEqual(@as(u16, 0), ctx.row);

    // page_up from 0 saturates.
    handleLeaseKey(&state, &ctx, .{ .codepoint = vaxis.Key.page_up });
    try std.testing.expectEqual(@as(u16, 0), ctx.row);
}

// ---------------------------------------------------------------------------
// LeaseSort.lessThan direction
// ---------------------------------------------------------------------------

test "LeaseSort.lessThan: desc reverses asc order" {
    const mk = struct {
        fn lease(ip: []const u8) state_mod.Lease {
            return .{ .mac = "aa:bb:cc:dd:ee:ff", .ip = ip, .hostname = null, .expires = 9999, .reserved = false, .client_id = null };
        }
    };
    const lo = mk.lease("10.0.0.1");
    const hi = mk.lease("10.0.0.2");

    // Empty config — pool sort not needed here, testing IP column only.
    var cfg: config_mod.Config = undefined;
    cfg.pools = &.{};

    const ctx_asc = LeaseSort{ .col = .ip, .dir = .asc, .cfg = &cfg };
    const ctx_desc = LeaseSort{ .col = .ip, .dir = .desc, .cfg = &cfg };

    try std.testing.expect(ctx_asc.lessThan(lo, hi)); // 10.0.0.1 < 10.0.0.2 asc
    try std.testing.expect(!ctx_asc.lessThan(hi, lo));
    try std.testing.expect(!ctx_desc.lessThan(lo, hi)); // desc flips it
    try std.testing.expect(ctx_desc.lessThan(hi, lo));
}

test "LeaseSort.lessThan: sort by hostname with null treated as empty" {
    const mk = struct {
        fn lease(ip: []const u8, hn: ?[]const u8) state_mod.Lease {
            return .{ .mac = "aa:bb:cc:dd:ee:ff", .ip = ip, .hostname = hn, .expires = 9999, .reserved = false, .client_id = null };
        }
    };
    var cfg: config_mod.Config = undefined;
    cfg.pools = &.{};

    const ctx = LeaseSort{ .col = .hostname, .dir = .asc, .cfg = &cfg };
    const a = mk.lease("10.0.0.1", "alpha");
    const b = mk.lease("10.0.0.2", "beta");
    const n = mk.lease("10.0.0.3", null); // null hostname sorts as ""

    try std.testing.expect(ctx.lessThan(a, b)); // "alpha" < "beta"
    try std.testing.expect(!ctx.lessThan(b, a));
    try std.testing.expect(ctx.lessThan(n, a)); // "" < "alpha"
    try std.testing.expect(!ctx.lessThan(a, n));
}

// ---------------------------------------------------------------------------
// poolCapacity
// ---------------------------------------------------------------------------

test "poolCapacity: /24 with explicit 100-200 range" {
    var pool: config_mod.PoolConfig = undefined;
    pool.subnet = "192.168.1.0";
    pool.subnet_mask = 0xFFFFFF00;
    pool.pool_start = "192.168.1.100";
    pool.pool_end = "192.168.1.200";
    try std.testing.expectEqual(@as(u64, 101), poolCapacity(&pool)); // 200 - 100 + 1
}

test "poolCapacity: empty range (end < start) returns 0" {
    var pool: config_mod.PoolConfig = undefined;
    pool.subnet = "192.168.1.0";
    pool.subnet_mask = 0xFFFFFF00;
    pool.pool_start = "192.168.1.200";
    pool.pool_end = "192.168.1.100";
    try std.testing.expectEqual(@as(u64, 0), poolCapacity(&pool));
}

test "poolCapacity: empty strings use subnet+1 to broadcast-1" {
    var pool: config_mod.PoolConfig = undefined;
    pool.subnet = "192.168.1.0";
    pool.subnet_mask = 0xFFFFFF00; // /24: subnet=.0, broadcast=.255
    pool.pool_start = "";
    pool.pool_end = "";
    // start = .1, end = .254 → 254 addresses
    try std.testing.expectEqual(@as(u64, 254), poolCapacity(&pool));
}

// ---------------------------------------------------------------------------
// isIpInPool
// ---------------------------------------------------------------------------

test "isIpInPool: address inside /24 subnet" {
    var pool: config_mod.PoolConfig = undefined;
    pool.subnet = "192.168.1.0";
    pool.subnet_mask = 0xFFFFFF00;
    try std.testing.expect(isIpInPool("192.168.1.50", &pool));
    try std.testing.expect(isIpInPool("192.168.1.1", &pool));
    try std.testing.expect(isIpInPool("192.168.1.254", &pool));
}

test "isIpInPool: address outside /24 subnet" {
    var pool: config_mod.PoolConfig = undefined;
    pool.subnet = "192.168.1.0";
    pool.subnet_mask = 0xFFFFFF00;
    try std.testing.expect(!isIpInPool("192.168.2.1", &pool));
    try std.testing.expect(!isIpInPool("10.0.0.1", &pool));
}

// ---------------------------------------------------------------------------
// findPoolLabel
// ---------------------------------------------------------------------------

test "findPoolLabel: returns subnet string for matching pool" {
    var pool: config_mod.PoolConfig = undefined;
    pool.subnet = "192.168.1.0";
    pool.subnet_mask = 0xFFFFFF00;

    var pools = [_]config_mod.PoolConfig{pool};
    var cfg: config_mod.Config = undefined;
    cfg.pools = &pools;

    const label = findPoolLabel(&cfg, "192.168.1.100");
    try std.testing.expect(label != null);
    try std.testing.expectEqualStrings("192.168.1.0", label.?);
}

test "findPoolLabel: returns null for IP not in any pool" {
    var pool: config_mod.PoolConfig = undefined;
    pool.subnet = "192.168.1.0";
    pool.subnet_mask = 0xFFFFFF00;

    var pools = [_]config_mod.PoolConfig{pool};
    var cfg: config_mod.Config = undefined;
    cfg.pools = &pools;

    try std.testing.expect(findPoolLabel(&cfg, "10.0.0.1") == null);
}

test "findPoolLabel: matches correct pool among multiple" {
    var pool1: config_mod.PoolConfig = undefined;
    pool1.subnet = "192.168.1.0";
    pool1.subnet_mask = 0xFFFFFF00;

    var pool2: config_mod.PoolConfig = undefined;
    pool2.subnet = "10.0.0.0";
    pool2.subnet_mask = 0xFF000000; // /8

    var pools = [_]config_mod.PoolConfig{ pool1, pool2 };
    var cfg: config_mod.Config = undefined;
    cfg.pools = &pools;

    const l1 = findPoolLabel(&cfg, "192.168.1.50");
    try std.testing.expect(l1 != null);
    try std.testing.expectEqualStrings("192.168.1.0", l1.?);

    const l2 = findPoolLabel(&cfg, "10.5.5.5");
    try std.testing.expect(l2 != null);
    try std.testing.expectEqualStrings("10.0.0.0", l2.?);
}

// ---------------------------------------------------------------------------
// rightAlignText
// ---------------------------------------------------------------------------

test "rightAlignText: pads short text with leading spaces" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const fa = arena.allocator();

    const result = try rightAlignText(fa, "10.0.0.0/8", 18);
    try std.testing.expectEqual(@as(usize, 18), result.len);
    try std.testing.expectEqualStrings("        10.0.0.0/8", result);
}

test "rightAlignText: exact fit returns text unchanged" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const fa = arena.allocator();

    const result = try rightAlignText(fa, "192.168.100.0/24", 16);
    try std.testing.expectEqualStrings("192.168.100.0/24", result);
}

test "rightAlignText: oversized text returned as-is (caller truncates first)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const fa = arena.allocator();

    const result = try rightAlignText(fa, "192.168.100.0/24", 10);
    try std.testing.expectEqualStrings("192.168.100.0/24", result);
}

// ---------------------------------------------------------------------------
// Quarantine sentinel filtering
// ---------------------------------------------------------------------------

test "quarantine sentinel detection: conflict: prefix" {
    // Probe-conflict entries use MAC = "conflict:<ip>".  renderLeaseTab detects
    // them by this prefix and renders them with type="conflict", blank MAC/hostname.
    try std.testing.expect(std.mem.startsWith(u8, "conflict:192.168.1.5", "conflict:"));
    try std.testing.expect(!std.mem.startsWith(u8, "aa:bb:cc:dd:ee:ff", "conflict:"));
    try std.testing.expect(!std.mem.startsWith(u8, "", "conflict:"));
}

// ---------------------------------------------------------------------------
// findPool returns pool struct (CIDR display)
// ---------------------------------------------------------------------------

test "findPool: returns pool for matching IP" {
    var pool: config_mod.PoolConfig = undefined;
    pool.subnet = "192.168.1.0";
    pool.subnet_mask = 0xFFFFFF00;
    pool.prefix_len = 24;

    var pools = [_]config_mod.PoolConfig{pool};
    var cfg: config_mod.Config = undefined;
    cfg.pools = &pools;

    const p = findPool(&cfg, "192.168.1.100");
    try std.testing.expect(p != null);
    try std.testing.expectEqualStrings("192.168.1.0", p.?.subnet);
    try std.testing.expectEqual(@as(u8, 24), p.?.prefix_len);
}

test "findPool: returns null for unmatched IP" {
    var pool: config_mod.PoolConfig = undefined;
    pool.subnet = "192.168.1.0";
    pool.subnet_mask = 0xFFFFFF00;
    pool.prefix_len = 24;

    var pools = [_]config_mod.PoolConfig{pool};
    var cfg: config_mod.Config = undefined;
    cfg.pools = &pools;

    try std.testing.expect(findPool(&cfg, "10.0.0.1") == null);
}

// ---------------------------------------------------------------------------
// statsVr: virtual-row → display-row mapping
// ---------------------------------------------------------------------------

test "statsVr: row before scroll returns null" {
    try std.testing.expect(statsVr(0, 5, 20) == null);
    try std.testing.expect(statsVr(4, 5, 20) == null);
}

test "statsVr: row at scroll offset returns 0" {
    try std.testing.expectEqual(@as(?u16, 0), statsVr(5, 5, 20));
}

test "statsVr: row within viewport maps correctly" {
    try std.testing.expectEqual(@as(?u16, 3), statsVr(8, 5, 20));
    try std.testing.expectEqual(@as(?u16, 19), statsVr(24, 5, 20));
}

test "statsVr: row at height boundary returns null" {
    // scroll=5, height=20 → last valid vr is 5+19=24; vr=25 is out
    try std.testing.expect(statsVr(25, 5, 20) == null);
    try std.testing.expect(statsVr(100, 5, 20) == null);
}

test "statsVr: no scroll (scroll=0) maps identity" {
    try std.testing.expectEqual(@as(?u16, 0), statsVr(0, 0, 10));
    try std.testing.expectEqual(@as(?u16, 9), statsVr(9, 0, 10));
    try std.testing.expect(statsVr(10, 0, 10) == null);
}

// ---------------------------------------------------------------------------
// handleStatsKey: scroll navigation
// ---------------------------------------------------------------------------

test "handleStatsKey: j increments scroll" {
    var state = TuiState{};
    state.stats_scroll = 5;
    handleStatsKey(&state, vaxis.Key{ .codepoint = 'j', .mods = .{} });
    try std.testing.expectEqual(@as(u16, 6), state.stats_scroll);
}

test "handleStatsKey: k decrements scroll" {
    var state = TuiState{};
    state.stats_scroll = 5;
    handleStatsKey(&state, vaxis.Key{ .codepoint = 'k', .mods = .{} });
    try std.testing.expectEqual(@as(u16, 4), state.stats_scroll);
}

test "handleStatsKey: k at zero saturates to 0" {
    var state = TuiState{};
    state.stats_scroll = 0;
    handleStatsKey(&state, vaxis.Key{ .codepoint = 'k', .mods = .{} });
    try std.testing.expectEqual(@as(u16, 0), state.stats_scroll);
}

test "handleStatsKey: page_down increments by 20" {
    var state = TuiState{};
    state.stats_scroll = 3;
    handleStatsKey(&state, vaxis.Key{ .codepoint = vaxis.Key.page_down, .mods = .{} });
    try std.testing.expectEqual(@as(u16, 23), state.stats_scroll);
}

test "handleStatsKey: page_up decrements by 20, saturates at 0" {
    var state = TuiState{};
    state.stats_scroll = 10;
    handleStatsKey(&state, vaxis.Key{ .codepoint = vaxis.Key.page_up, .mods = .{} });
    try std.testing.expectEqual(@as(u16, 0), state.stats_scroll);
}

test "handleStatsKey: down arrow increments scroll" {
    var state = TuiState{};
    state.stats_scroll = 0;
    handleStatsKey(&state, vaxis.Key{ .codepoint = vaxis.Key.down, .mods = .{} });
    try std.testing.expectEqual(@as(u16, 1), state.stats_scroll);
}

test "handleStatsKey: up arrow at zero saturates" {
    var state = TuiState{};
    state.stats_scroll = 0;
    handleStatsKey(&state, vaxis.Key{ .codepoint = vaxis.Key.up, .mods = .{} });
    try std.testing.expectEqual(@as(u16, 0), state.stats_scroll);
}

// ---------------------------------------------------------------------------
// Pool tab helper tests
// ---------------------------------------------------------------------------

test "parseSubnet: valid /24" {
    const result = parseSubnet("192.168.1.0/24").?;
    try std.testing.expectEqual(@as(u8, 24), result.prefix);
    try std.testing.expectEqual(@as(u32, 0xFFFFFF00), result.mask);
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 0 }, result.ip);
}

test "parseSubnet: valid /32" {
    const result = parseSubnet("10.0.0.1/32").?;
    try std.testing.expectEqual(@as(u8, 32), result.prefix);
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), result.mask);
}

test "parseSubnet: valid /16" {
    const result = parseSubnet("172.20.0.0/16").?;
    try std.testing.expectEqual(@as(u8, 16), result.prefix);
    try std.testing.expectEqual(@as(u32, 0xFFFF0000), result.mask);
}

test "parseSubnet: missing slash returns null" {
    try std.testing.expect(parseSubnet("192.168.1.0") == null);
}

test "parseSubnet: invalid prefix returns null" {
    try std.testing.expect(parseSubnet("192.168.1.0/0") == null);
    try std.testing.expect(parseSubnet("192.168.1.0/33") == null);
}

test "parseSubnet: invalid IP returns null" {
    try std.testing.expect(parseSubnet("999.168.1.0/24") == null);
}

test "splitOctets: four octets" {
    const result = splitOctets("192.168.10.100");
    try std.testing.expectEqual(@as(usize, 4), result.count);
    try std.testing.expectEqualStrings("192", result.items[0]);
    try std.testing.expectEqualStrings("168", result.items[1]);
    try std.testing.expectEqualStrings("10", result.items[2]);
    try std.testing.expectEqualStrings("100", result.items[3]);
}

test "splitOctets: fewer than four" {
    const result = splitOctets("10.0");
    try std.testing.expectEqual(@as(usize, 2), result.count);
}

test "joinFromOctet: skip common octets" {
    const octets = splitOctets("192.168.10.100");
    const result = try joinFromOctet(std.testing.allocator, &octets, 3);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings(".100", result);
}

test "joinFromOctet: skip two common octets" {
    const octets = splitOctets("172.20.5.200");
    const result = try joinFromOctet(std.testing.allocator, &octets, 2);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings(".5.200", result);
}

test "joinFromOctet: no common octets" {
    const octets = splitOctets("10.0.0.1");
    const result = try joinFromOctet(std.testing.allocator, &octets, 0);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings(".10.0.0.1", result);
}

test "hitTestCol: click within first column" {
    const widths = [3]u16{ 10, 20, 15 };
    try std.testing.expectEqual(@as(?usize, 0), hitTestCol(u16, &widths, 1, 5));
}

test "hitTestCol: click in separator returns next column" {
    const widths = [3]u16{ 10, 20, 15 };
    // col 10 = separator after first column; col 11 = start of second
    try std.testing.expectEqual(@as(?usize, 1), hitTestCol(u16, &widths, 1, 11));
}

test "hitTestCol: click past all columns returns null" {
    const widths = [2]u16{ 10, 20 };
    try std.testing.expectEqual(@as(?usize, null), hitTestCol(u16, &widths, 1, 50));
}

test "validatePoolForm: valid minimal config" {
    var form = PoolForm{};
    @memcpy(form.subnet_buf[0..14], "192.168.1.0/24");
    form.subnet_len = 14;
    @memcpy(form.router_buf[0..11], "192.168.1.1");
    form.router_len = 11;
    @memcpy(form.lease_time_buf[0..4], "3600");
    form.lease_time_len = 4;
    try std.testing.expect(validatePoolForm(&form) == null);
}

test "validatePoolForm: missing subnet" {
    var form = PoolForm{};
    @memcpy(form.router_buf[0..11], "192.168.1.1");
    form.router_len = 11;
    @memcpy(form.lease_time_buf[0..4], "3600");
    form.lease_time_len = 4;
    try std.testing.expect(validatePoolForm(&form) != null);
}

test "validatePoolForm: subnet missing slash" {
    var form = PoolForm{};
    @memcpy(form.subnet_buf[0..11], "192.168.1.0");
    form.subnet_len = 11;
    @memcpy(form.router_buf[0..11], "192.168.1.1");
    form.router_len = 11;
    @memcpy(form.lease_time_buf[0..4], "3600");
    form.lease_time_len = 4;
    try std.testing.expect(validatePoolForm(&form) != null);
}

test "validatePoolForm: invalid router IP" {
    var form = PoolForm{};
    @memcpy(form.subnet_buf[0..14], "192.168.1.0/24");
    form.subnet_len = 14;
    @memcpy(form.router_buf[0..3], "abc");
    form.router_len = 3;
    @memcpy(form.lease_time_buf[0..4], "3600");
    form.lease_time_len = 4;
    try std.testing.expect(validatePoolForm(&form) != null);
}

test "validatePoolForm: invalid lease time" {
    var form = PoolForm{};
    @memcpy(form.subnet_buf[0..14], "192.168.1.0/24");
    form.subnet_len = 14;
    @memcpy(form.router_buf[0..11], "192.168.1.1");
    form.router_len = 11;
    @memcpy(form.lease_time_buf[0..3], "abc");
    form.lease_time_len = 3;
    try std.testing.expect(validatePoolForm(&form) != null);
}

test "validateIpList: valid comma-separated IPs" {
    try std.testing.expect(validateIpList("8.8.8.8, 8.8.4.4") == null);
}

test "validateIpList: invalid IP in list" {
    try std.testing.expect(validateIpList("8.8.8.8, bad") != null);
}

test "splitCommaDupe: empty input returns empty slice" {
    const result = try splitCommaDupe(std.testing.allocator, "");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "splitCommaDupe: single item" {
    const result = try splitCommaDupe(std.testing.allocator, "8.8.8.8");
    defer {
        for (result) |s| std.testing.allocator.free(s);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqualStrings("8.8.8.8", result[0]);
}

test "splitCommaDupe: multiple items with whitespace" {
    const result = try splitCommaDupe(std.testing.allocator, "8.8.8.8 , 1.1.1.1 , 9.9.9.9");
    defer {
        for (result) |s| std.testing.allocator.free(s);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expectEqualStrings("8.8.8.8", result[0]);
    try std.testing.expectEqualStrings("1.1.1.1", result[1]);
    try std.testing.expectEqualStrings("9.9.9.9", result[2]);
}

test "joinComma: joins array items" {
    var buf: [64]u8 = undefined;
    const items = [_][]const u8{ "a", "bb", "ccc" };
    const len = joinComma(64, &buf, &items);
    try std.testing.expectEqualStrings("a, bb, ccc", buf[0..len]);
}

test "joinComma: empty array" {
    var buf: [64]u8 = undefined;
    const items = [_][]const u8{};
    const len = joinComma(64, &buf, &items);
    try std.testing.expectEqual(@as(usize, 0), len);
}

test "calcPoolColWidths: fits at normal terminal width" {
    const widths = calcPoolColWidths(120);
    var total: u16 = 0;
    for (widths) |w| total += w;
    total += 5; // 5 separators
    try std.testing.expect(total <= 120);
}

test "fmtAbbrevRange: both endpoints explicit, same /24 subnet" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const fa = arena.allocator();
    var pool = config_mod.PoolConfig{
        .subnet = "192.168.10.0",
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = "192.168.10.1",
        .pool_start = "192.168.10.100",
        .pool_end = "192.168.10.200",
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
        .dhcp_options = std.StringHashMap([]const u8).init(fa),
        .reservations = &.{},
        .static_routes = &.{},
    };
    const result = try fmtAbbrevRange(fa, &pool);
    // Both IPs share 192.168.10 with subnet → abbreviated to .100 – .200
    try std.testing.expect(std.mem.indexOf(u8, result, ".100") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, ".200") != null);
}

test "fmtAbbrevRange: start only, end auto-computed" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const fa = arena.allocator();
    var pool = config_mod.PoolConfig{
        .subnet = "10.99.99.0",
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = "10.99.99.1",
        .pool_start = "10.99.99.10",
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
        .dhcp_options = std.StringHashMap([]const u8).init(fa),
        .reservations = &.{},
        .static_routes = &.{},
    };
    const result = try fmtAbbrevRange(fa, &pool);
    // Start=10.99.99.10 abbreviated to .10; end=10.99.99.254 abbreviated to .254
    try std.testing.expect(std.mem.indexOf(u8, result, ".10") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, ".254") != null);
    // Must NOT contain "(auto)"
    try std.testing.expect(std.mem.indexOf(u8, result, "(auto)") == null);
}

test "fmtAbbrevRange: both auto returns 'auto'" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const fa = arena.allocator();
    var pool = config_mod.PoolConfig{
        .subnet = "10.0.0.0",
        .subnet_mask = 0xFFFFFF00,
        .prefix_len = 24,
        .router = "10.0.0.1",
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
        .dhcp_options = std.StringHashMap([]const u8).init(fa),
        .reservations = &.{},
        .static_routes = &.{},
    };
    const result = try fmtAbbrevRange(fa, &pool);
    try std.testing.expectEqualStrings("auto", result);
}

test "calcPoolColWidths: narrow terminal reduces columns" {
    const widths = calcPoolColWidths(50);
    var total: u16 = 0;
    for (widths) |w| total += w;
    total += 5;
    try std.testing.expect(total <= 50);
    // All columns should be at least their minimum
    for (POOL_COL_SPECS, 0..) |spec, i| {
        try std.testing.expect(widths[i] >= spec.min);
    }
}

// ---------------------------------------------------------------------------
// Route/Option entry tests
// ---------------------------------------------------------------------------

test "InlineEntry: default is empty" {
    const de = InlineEntry{};
    try std.testing.expectEqual(@as(usize, 0), de.len);
}

test "RouteEntry: default is empty" {
    const re = RouteEntry{};
    try std.testing.expectEqual(@as(usize, 0), re.dest_len);
    try std.testing.expectEqual(@as(usize, 0), re.router_len);
}

test "OptionEntry: default is empty" {
    const oe = OptionEntry{};
    try std.testing.expectEqual(@as(usize, 0), oe.code_len);
    try std.testing.expectEqual(@as(usize, 0), oe.value_len);
}

test "PoolForm: REGULAR_FIELD_COUNT matches pool_field_meta length" {
    try std.testing.expectEqual(@as(usize, PoolForm.REGULAR_FIELD_COUNT), pool_field_meta.len);
}

test "PoolForm: totalFields accounts for all inline sections" {
    var form = PoolForm{};
    // No entries: 15 regular + 9 [+] buttons (DS,DNS,Log,NTP,WINS,TFTP,Route,Option,MacClass) = 24
    try std.testing.expectEqual(@as(u8, 24), form.totalFields());
    form.domain_search_count = 1;
    form.dns_servers_count = 2;
    form.route_count = 2;
    form.option_count = 3;
    form.mac_class_count = 1;
    // 15 + 9 + 1 + 2 + 2 + 3 + 1 = 33
    try std.testing.expectEqual(@as(u8, 33), form.totalFields());
}

test "PoolForm: fieldPosition helpers" {
    var form = PoolForm{};
    form.domain_search_count = 1;
    form.dns_servers_count = 2;
    form.route_count = 2;
    form.option_count = 1;
    // Layout: 6 Network, Domain Name, [+]DS+1, [+]DNS+2, [+]WINS,
    // Time Offset, [+]NTP, [+]Log, HTTP Boot URL, TFTP Boot File, [+]TFTP,
    // 5 DNS Update, [+]Routes+2, [+]Options+1.
    try std.testing.expectEqual(@as(u8, 7), form.fieldPosition(.domain_search, .add_button));
    try std.testing.expectEqual(@as(u8, 8), form.fieldPosition(.domain_search, .first_entry));
    try std.testing.expectEqual(@as(u8, 9), form.fieldPosition(.dns, .add_button));
    try std.testing.expectEqual(@as(u8, 10), form.fieldPosition(.dns, .first_entry));
    try std.testing.expectEqual(@as(u8, 12), form.fieldPosition(.wins, .add_button));
    try std.testing.expectEqual(@as(u8, 14), form.fieldPosition(.ntp, .add_button));
    try std.testing.expectEqual(@as(u8, 15), form.fieldPosition(.log, .add_button));
    try std.testing.expectEqual(@as(u8, 18), form.fieldPosition(.tftp, .add_button));
    try std.testing.expectEqual(@as(u8, 24), form.fieldPosition(.routes, .add_button));
    try std.testing.expectEqual(@as(u8, 25), form.fieldPosition(.routes, .first_entry));
    try std.testing.expectEqual(@as(u8, 27), form.fieldPosition(.options, .add_button));
    try std.testing.expectEqual(@as(u8, 28), form.fieldPosition(.options, .first_entry));
}

test "buildRoutesFromForm: empty routes" {
    const form = PoolForm{};
    const routes = try buildRoutesFromForm(std.testing.allocator, &form);
    defer std.testing.allocator.free(routes);
    try std.testing.expectEqual(@as(usize, 0), routes.len);
}

test "buildRoutesFromForm: valid route" {
    var form = PoolForm{};
    form.route_count = 1;
    const dest = "10.0.0.0/24";
    @memcpy(form.routes[0].dest_buf[0..dest.len], dest);
    form.routes[0].dest_len = dest.len;
    const rtr = "10.0.0.1";
    @memcpy(form.routes[0].router_buf[0..rtr.len], rtr);
    form.routes[0].router_len = rtr.len;

    const routes = try buildRoutesFromForm(std.testing.allocator, &form);
    defer std.testing.allocator.free(routes);
    try std.testing.expectEqual(@as(usize, 1), routes.len);
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 0 }, routes[0].destination);
    try std.testing.expectEqual(@as(u8, 24), routes[0].prefix_len);
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 1 }, routes[0].router);
}

test "handlePoolRouteEditKey: save new route" {
    var state = TuiState{};
    state.mode = .pool_route_edit;
    state.pool_form.route_count = 0;
    state.pool_form.route_edit_index = null; // adding new

    // Type "10.0.0.0/24" into dest.
    const dest = "10.0.0.0/24";
    @memcpy(state.pool_form.route_edit_dest[0..dest.len], dest);
    state.pool_form.route_edit_dest_len = dest.len;
    const rtr = "10.0.0.1";
    @memcpy(state.pool_form.route_edit_router[0..rtr.len], rtr);
    state.pool_form.route_edit_router_len = rtr.len;

    // Press Enter to save.
    handlePoolRouteEditKey(&state, vaxis.Key{ .codepoint = vaxis.Key.enter, .mods = .{} });
    try std.testing.expectEqual(@as(usize, 1), state.pool_form.route_count);
    try std.testing.expect(state.mode == .pool_form);
    try std.testing.expectEqualStrings("10.0.0.0/24", state.pool_form.routes[0].dest_buf[0..state.pool_form.routes[0].dest_len]);
}

test "handlePoolFormKey: delete inline route" {
    var state = TuiState{};
    state.mode = .pool_form;
    state.pool_form.route_count = 1;
    const dest = "10.0.0.0/24";
    @memcpy(state.pool_form.routes[0].dest_buf[0..dest.len], dest);
    state.pool_form.routes[0].dest_len = dest.len;

    // Navigate to first route entry.
    state.pool_form.active_field = state.pool_form.fieldPosition(.routes, .first_entry);

    // Press 'd' to delete.
    handlePoolFormKey(undefined, &state, vaxis.Key{ .codepoint = 'd', .mods = .{} });
    try std.testing.expectEqual(@as(usize, 0), state.pool_form.route_count);
}

test "handlePoolOptionEditKey: save new option" {
    var state = TuiState{};
    state.mode = .pool_option_edit;
    state.pool_form.option_count = 0;
    state.pool_form.opt_edit_index = null; // adding new

    const code = "150";
    @memcpy(state.pool_form.opt_edit_code[0..code.len], code);
    state.pool_form.opt_edit_code_len = code.len;
    const val = "10.0.0.1";
    @memcpy(state.pool_form.opt_edit_value[0..val.len], val);
    state.pool_form.opt_edit_value_len = val.len;

    handlePoolOptionEditKey(&state, vaxis.Key{ .codepoint = vaxis.Key.enter, .mods = .{} });
    try std.testing.expectEqual(@as(usize, 1), state.pool_form.option_count);
    try std.testing.expect(state.mode == .pool_form);
    try std.testing.expectEqualStrings("150", state.pool_form.options[0].code_buf[0..state.pool_form.options[0].code_len]);
}

test "handlePoolFormKey: delete inline option" {
    var state = TuiState{};
    state.mode = .pool_form;
    state.pool_form.option_count = 1;
    const code = "150";
    @memcpy(state.pool_form.options[0].code_buf[0..code.len], code);
    state.pool_form.options[0].code_len = code.len;

    // Navigate to first option entry.
    state.pool_form.active_field = state.pool_form.fieldPosition(.options, .first_entry);

    // Press 'd' to delete.
    handlePoolFormKey(undefined, &state, vaxis.Key{ .codepoint = 'd', .mods = .{} });
    try std.testing.expectEqual(@as(usize, 0), state.pool_form.option_count);
}

test "handlePoolServerEditKey: save new domain search entry" {
    var state = TuiState{};
    state.mode = .pool_server_edit;
    state.pool_form.domain_search_count = 0;
    state.pool_form.server_edit_target = .domain_search;
    state.pool_form.server_edit_index = null; // adding new

    const domain = "example.local";
    @memcpy(state.pool_form.server_edit_buf[0..domain.len], domain);
    state.pool_form.server_edit_len = domain.len;

    // Press Enter to save.
    handlePoolServerEditKey(&state, vaxis.Key{ .codepoint = vaxis.Key.enter, .mods = .{} });
    try std.testing.expectEqual(@as(usize, 1), state.pool_form.domain_search_count);
    try std.testing.expect(state.mode == .pool_form);
    try std.testing.expectEqualStrings("example.local", state.pool_form.domain_search[0].buf[0..state.pool_form.domain_search[0].len]);
}

test "handlePoolFormKey: delete inline domain search" {
    var state = TuiState{};
    state.mode = .pool_form;
    state.pool_form.domain_search_count = 1;
    const domain = "example.local";
    @memcpy(state.pool_form.domain_search[0].buf[0..domain.len], domain);
    state.pool_form.domain_search[0].len = domain.len;

    // Navigate to first domain search entry.
    state.pool_form.active_field = state.pool_form.fieldPosition(.domain_search, .first_entry);

    // Press 'd' to delete.
    handlePoolFormKey(undefined, &state, vaxis.Key{ .codepoint = 'd', .mods = .{} });
    try std.testing.expectEqual(@as(usize, 0), state.pool_form.domain_search_count);
}

test "validatePoolForm: valid with DHCP options and routes" {
    var form = PoolForm{};
    @memcpy(form.subnet_buf[0..14], "192.168.1.0/24");
    form.subnet_len = 14;
    @memcpy(form.router_buf[0..11], "192.168.1.1");
    form.router_len = 11;
    @memcpy(form.lease_time_buf[0..4], "3600");
    form.lease_time_len = 4;
    // Add a route and option with valid data.
    form.route_count = 1;
    form.option_count = 1;
    @memcpy(form.options[0].code_buf[0..2], "66");
    form.options[0].code_len = 2;
    @memcpy(form.options[0].value_buf[0..9], "10.0.0.99");
    form.options[0].value_len = 9;
    try std.testing.expect(validatePoolForm(&form) == null);
}

// ---------------------------------------------------------------------------
// validateReservationForm tests
// ---------------------------------------------------------------------------

test "validateReservationForm: valid minimal IP + MAC" {
    var form = ReservationForm{};
    @memcpy(form.ip_buf[0..11], "192.168.1.5");
    form.ip_len = 11;
    @memcpy(form.mac_buf[0..17], "aa:bb:cc:dd:ee:ff");
    form.mac_len = 17;
    try std.testing.expect(validateReservationForm(&form) == null);
}

test "validateReservationForm: missing IP fails" {
    var form = ReservationForm{};
    @memcpy(form.mac_buf[0..17], "aa:bb:cc:dd:ee:ff");
    form.mac_len = 17;
    try std.testing.expect(validateReservationForm(&form) != null);
}

test "validateReservationForm: missing MAC fails" {
    var form = ReservationForm{};
    @memcpy(form.ip_buf[0..11], "192.168.1.5");
    form.ip_len = 11;
    try std.testing.expect(validateReservationForm(&form) != null);
}

test "validateReservationForm: invalid IP format fails" {
    var form = ReservationForm{};
    @memcpy(form.ip_buf[0..7], "not.a.i");
    form.ip_len = 7;
    @memcpy(form.mac_buf[0..17], "aa:bb:cc:dd:ee:ff");
    form.mac_len = 17;
    try std.testing.expect(validateReservationForm(&form) != null);
}

test "validateReservationForm: MAC with dashes normalizes to colons" {
    var form = ReservationForm{};
    @memcpy(form.ip_buf[0..11], "192.168.1.5");
    form.ip_len = 11;
    @memcpy(form.mac_buf[0..17], "aa-bb-cc-dd-ee-ff");
    form.mac_len = 17;
    try std.testing.expect(validateReservationForm(&form) == null);
    try std.testing.expectEqualStrings("aa:bb:cc:dd:ee:ff", form.mac_buf[0..form.mac_len]);
}

test "validateReservationForm: MAC uppercase normalizes to lowercase" {
    var form = ReservationForm{};
    @memcpy(form.ip_buf[0..11], "192.168.1.5");
    form.ip_len = 11;
    @memcpy(form.mac_buf[0..17], "AA:BB:CC:DD:EE:FF");
    form.mac_len = 17;
    try std.testing.expect(validateReservationForm(&form) == null);
    try std.testing.expectEqualStrings("aa:bb:cc:dd:ee:ff", form.mac_buf[0..form.mac_len]);
}

test "validateReservationForm: invalid MAC length fails" {
    var form = ReservationForm{};
    @memcpy(form.ip_buf[0..11], "192.168.1.5");
    form.ip_len = 11;
    @memcpy(form.mac_buf[0..11], "aa:bb:cc:dd");
    form.mac_len = 11;
    try std.testing.expect(validateReservationForm(&form) != null);
}

test "validateReservationForm: valid hostname passes" {
    var form = ReservationForm{};
    @memcpy(form.ip_buf[0..11], "192.168.1.5");
    form.ip_len = 11;
    @memcpy(form.mac_buf[0..17], "aa:bb:cc:dd:ee:ff");
    form.mac_len = 17;
    @memcpy(form.hostname_buf[0..7], "printer");
    form.hostname_len = 7;
    try std.testing.expect(validateReservationForm(&form) == null);
}

test "validateReservationForm: hostname uppercase auto-lowercases" {
    var form = ReservationForm{};
    @memcpy(form.ip_buf[0..11], "192.168.1.5");
    form.ip_len = 11;
    @memcpy(form.mac_buf[0..17], "aa:bb:cc:dd:ee:ff");
    form.mac_len = 17;
    @memcpy(form.hostname_buf[0..7], "Printer");
    form.hostname_len = 7;
    try std.testing.expect(validateReservationForm(&form) == null);
    try std.testing.expectEqualStrings("printer", form.hostname_buf[0..form.hostname_len]);
}

test "validateReservationForm: hostname starting with dash fails" {
    var form = ReservationForm{};
    @memcpy(form.ip_buf[0..11], "192.168.1.5");
    form.ip_len = 11;
    @memcpy(form.mac_buf[0..17], "aa:bb:cc:dd:ee:ff");
    form.mac_len = 17;
    @memcpy(form.hostname_buf[0..8], "-printer");
    form.hostname_len = 8;
    try std.testing.expect(validateReservationForm(&form) != null);
}

test "validateReservationForm: hostname with invalid chars fails" {
    var form = ReservationForm{};
    @memcpy(form.ip_buf[0..11], "192.168.1.5");
    form.ip_len = 11;
    @memcpy(form.mac_buf[0..17], "aa:bb:cc:dd:ee:ff");
    form.mac_len = 17;
    @memcpy(form.hostname_buf[0..9], "host_name");
    form.hostname_len = 9;
    try std.testing.expect(validateReservationForm(&form) != null);
}

test "validateReservationForm: empty hostname is valid (optional)" {
    var form = ReservationForm{};
    @memcpy(form.ip_buf[0..11], "192.168.1.5");
    form.ip_len = 11;
    @memcpy(form.mac_buf[0..17], "aa:bb:cc:dd:ee:ff");
    form.mac_len = 17;
    // hostname_len stays 0 (default)
    try std.testing.expect(validateReservationForm(&form) == null);
}
