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
    counters: *const dhcp_mod.Counters,
    /// Non-null when the server is part of a sync group.
    sync_mgr: ?*sync_mod.SyncManager,
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
        counters: *const dhcp_mod.Counters,
        sync_mgr: ?*sync_mod.SyncManager,
    ) !*Self {
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
        // Silence libssh's default stderr logging — it writes raw binary
        // protocol data that shows up as "[NNB blob data]" in the journal.
        _ = c.ssh_set_log_level(c.SSH_LOG_NONE);

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

    if (c.ssh_handle_key_exchange(session) < 0) {
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
                        authed = true;
                    } else {
                        log.info("{s}: rejected pubkey for user '{s}' ({s}): key not in authorized_keys", .{ peer, user, key_type });
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

const Tab = enum(u8) { leases = 0, stats = 1, pools = 2 };

const TuiMode = enum { normal, reservation_form, delete_confirm, pool_detail, pool_form, pool_delete_confirm, pool_save_confirm };

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
    /// Index of the field currently receiving input: 0=ip  1=mac  2=hostname.
    active_field: u8 = 0,
    /// Inline error message (empty = no error).
    err_buf: [80]u8 = [_]u8{0} ** 80,
    err_len: usize = 0,
    /// True immediately after a successful save; cleared on the next keypress.
    saved: bool = false,

    fn isNew(self: *const ReservationForm) bool {
        return self.orig_mac_len == 0;
    }
};

const PoolForm = struct {
    editing_index: ?usize = null, // null = new pool
    active_field: u8 = 0,
    scroll_offset: u8 = 0,

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
    domain_search_buf: [256]u8 = [_]u8{0} ** 256,
    domain_search_len: usize = 0,

    // --- DNS ---
    dns_servers_buf: [128]u8 = [_]u8{0} ** 128,
    dns_servers_len: usize = 0,

    // --- Timing ---
    lease_time_buf: [10]u8 = [_]u8{0} ** 10,
    lease_time_len: usize = 0,
    time_offset_buf: [8]u8 = [_]u8{0} ** 8,
    time_offset_len: usize = 0,

    // --- Servers ---
    time_servers_buf: [128]u8 = [_]u8{0} ** 128,
    time_servers_len: usize = 0,
    log_servers_buf: [128]u8 = [_]u8{0} ** 128,
    log_servers_len: usize = 0,
    ntp_servers_buf: [128]u8 = [_]u8{0} ** 128,
    ntp_servers_len: usize = 0,

    // --- Boot ---
    tftp_server_buf: [64]u8 = [_]u8{0} ** 64,
    tftp_server_len: usize = 0,
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

    // --- Status ---
    err_buf: [120]u8 = [_]u8{0} ** 120,
    err_len: usize = 0,

    const FIELD_COUNT: u8 = 20; // 0..19
    const VISIBLE_ROWS: u8 = 12;

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
    // Reservation form (mode == .reservation_form).
    form: ReservationForm = .{},
    // Delete confirm (mode == .delete_confirm): MAC of the reservation to delete.
    del_mac: [18]u8 = [_]u8{0} ** 18,
    del_mac_len: usize = 0,
    del_ip: [16]u8 = [_]u8{0} ** 16,
    del_ip_len: usize = 0,
    // Pool tab state.
    pool_row: u16 = 0,
    pool_start: u16 = 0,
    pool_form: PoolForm = .{},
    pool_confirm: PoolSaveConfirm = .{},
    pool_detail_scroll: u16 = 0,
    pool_del_index: ?usize = null,
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
                        }
                        if (key.matches('1', .{})) state.tab = .leases;
                        if (key.matches('2', .{})) state.tab = .stats;
                        if (key.matches('3', .{})) state.tab = .pools;

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
                                state.mode = .reservation_form;
                            } else if (key.matches('d', .{}) and state.sel_reserved) {
                                // Delete confirmation for a reserved lease.
                                const mac = state.sel_mac[0..state.sel_mac_len];
                                const ip = state.sel_ip[0..state.sel_ip_len];
                                @memcpy(state.del_mac[0..mac.len], mac);
                                state.del_mac_len = mac.len;
                                @memcpy(state.del_ip[0..ip.len], ip);
                                state.del_ip_len = ip.len;
                                state.mode = .delete_confirm;
                            }
                        }
                    }
                },
                .mouse => |mouse| {
                    switch (mouse.button) {
                        .left => if (mouse.type == .press) {
                            const term_row: u16 = if (mouse.row >= 0) @intCast(mouse.row) else 0;
                            const term_col: u16 = if (mouse.col >= 0) @intCast(mouse.col) else 0;
                            if (term_row == 0) {
                                // Header bar: tab switching.
                                // Layout: " Stardust "(10) + " [1] Leases "(12) + " [2] Stats "(11) + " [3] Pools "(11)
                                if (term_col >= 10 and term_col < 22) {
                                    state.tab = .leases;
                                } else if (term_col >= 22 and term_col < 33) {
                                    state.tab = .stats;
                                } else if (term_col >= 33 and term_col < 44) {
                                    state.tab = .pools;
                                }
                            } else if (state.tab == .leases) {
                                if (term_row == 1) {
                                    // Column header row: sort by clicked column.
                                    const n_cols: u16 = 6;
                                    const cw = calcDynColWidth(@intCast(vx.window().width), n_cols);
                                    const clicked_col: SortCol = if (cw > 0)
                                        @enumFromInt(@min(term_col / cw, n_cols - 1))
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
                                    if (clicked <= std.math.maxInt(u16))
                                        table_ctx.row = @intCast(clicked);
                                }
                            }
                        },
                        .wheel_up => switch (state.tab) {
                            .leases => table_ctx.row -|= 1,
                            .stats => state.stats_scroll -|= 3,
                            .pools => state.pool_row -|= 1,
                        },
                        .wheel_down => switch (state.tab) {
                            .leases => table_ctx.row +|= 1,
                            .stats => state.stats_scroll +|= 3,
                            .pools => if (state.pool_row + 1 < server.cfg.pools.len) {
                                state.pool_row += 1;
                            },
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

    const leases_label = " [1] Leases ";
    const stats_label = " [2] Stats ";
    const pools_label = " [3] Pools ";
    _ = win.print(&.{.{ .text = leases_label, .style = if (state.tab == .leases) tab_style_active else tab_style_inactive }}, .{ .col_offset = col, .wrap = .none });
    col += @intCast(leases_label.len);
    _ = win.print(&.{.{ .text = stats_label, .style = if (state.tab == .stats) tab_style_active else tab_style_inactive }}, .{ .col_offset = col, .wrap = .none });
    col += @intCast(stats_label.len);
    _ = win.print(&.{.{ .text = pools_label, .style = if (state.tab == .pools) tab_style_active else tab_style_inactive }}, .{ .col_offset = col, .wrap = .none });
    col += @intCast(pools_label.len);

    const hint: []const u8 = switch (state.tab) {
        .leases => "  j/k:move  /:filter  I/M/H/T/E/P:sort  y:yank  n:new  e:edit  d:del  ^R:reload  q:quit",
        .stats => "  j/k:scroll  ^R:reload  q:quit",
        .pools => if (server.cfg.admin_ssh.read_only) "  j/k:move  v:view  ^R:reload  q:quit" else "  j/k:move  v:view  e:edit  n:new  d:del  ^R:reload  q:quit",
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
    const alt_bg: vaxis.Color = .{ .rgb = .{ 22, 22, 28 } };
    for (0..visible) |ri| {
        const row_idx = ctx.start + @as(u16, @intCast(ri));
        if (row_idx >= rows.len) break;
        const row = rows[row_idx];
        const selected = (row_idx == ctx.row);
        const row_bg: vaxis.Color = if (selected) ctx.active_bg else if (ri % 2 != 0) alt_bg else .default;
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

    // Clamp table cursor to the actual number of rows.
    const n_rows: u16 = if (rows.items.len > 0xFFFF) 0xFFFF else @intCast(rows.items.len);
    if (n_rows > 0 and table_ctx.row >= n_rows) table_ctx.row = n_rows - 1;
    if (n_rows == 0) table_ctx.row = 0;

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
        if ((ip_int & pool.subnet_mask) == subnet_int) return pool;
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
    // Use the caller-supplied frame arena (fa) — same lifetime requirement as
    // renderLeaseTab: grapheme slices must outlive vx.render().
    const a = fa;

    const now = std.time.timestamp();
    const leases = server.store.listLeases() catch return;
    defer server.store.allocator.free(leases);

    const hdr_style: vaxis.Style = .{ .bold = true, .fg = .{ .rgb = .{ 255, 200, 80 } } };
    const val_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 200, 200, 200 } } };
    const bar_full: vaxis.Style = .{ .fg = .{ .rgb = .{ 64, 192, 64 } } };
    const bar_warn: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 180, 0 } } };
    const bar_crit: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 60, 60 } } };

    // Compute total content height:
    //   1 (blank) + 1 (pool header) + 3 * n_pools (label + bar + blank) +
    //   1 (DHCP header) + 8 (DHCP counters) +
    //   1 (blank) + 1 (defense header) + 5 (defense counters) + 1 (trailing blank)
    const n_pools: u16 = @intCast(server.cfg.pools.len);
    const total_rows: u16 = 1 + 1 + 3 * n_pools + 1 + 8 + 1 + 1 + 5 + 1;

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

    for (server.cfg.pools) |pool| {
        const capacity = poolCapacity(&pool);

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
        const used = active + reserved;
        const available: u64 = if (capacity > used) capacity - used else 0;

        // Pool label line: "  subnet/prefix  start – end"
        const start_str = if (pool.pool_start.len > 0) pool.pool_start else "(auto)";
        const end_str = if (pool.pool_end.len > 0) pool.pool_end else "(auto)";
        const pool_label = try std.fmt.allocPrint(a, "  {s}/{d}  {s} \xe2\x80\x93 {s}", .{
            pool.subnet, pool.prefix_len, start_str, end_str,
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
        .{ .label = "DISCOVER", .val = ctr.discover.load(.monotonic) },
        .{ .label = "OFFER   ", .val = ctr.offer.load(.monotonic) },
        .{ .label = "REQUEST ", .val = ctr.request.load(.monotonic) },
        .{ .label = "ACK     ", .val = ctr.ack.load(.monotonic) },
        .{ .label = "NAK     ", .val = ctr.nak.load(.monotonic) },
        .{ .label = "RELEASE ", .val = ctr.release.load(.monotonic) },
        .{ .label = "DECLINE ", .val = ctr.decline.load(.monotonic) },
        .{ .label = "INFORM  ", .val = ctr.inform.load(.monotonic) },
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

    // Top and bottom border strings.
    var top_buf: [256]u8 = undefined;
    var bot_buf: [256]u8 = undefined;
    const inner = w - 2;
    top_buf[0] = '\xe2';
    top_buf[1] = '\x94';
    top_buf[2] = '\x8c'; // ┌
    var i: usize = 3;
    var n: usize = 0;
    while (n < inner) : (n += 1) {
        top_buf[i] = '\xe2';
        top_buf[i + 1] = '\x94';
        top_buf[i + 2] = '\x80'; // ─
        bot_buf[i] = '\xe2';
        bot_buf[i + 1] = '\x94';
        bot_buf[i + 2] = '\x80';
        i += 3;
    }
    top_buf[i] = '\xe2';
    top_buf[i + 1] = '\x94';
    top_buf[i + 2] = '\x90'; // ┐
    bot_buf[0] = '\xe2';
    bot_buf[1] = '\x94';
    bot_buf[2] = '\x94'; // └
    bot_buf[i] = '\xe2';
    bot_buf[i + 1] = '\x94';
    bot_buf[i + 2] = '\x98'; // ┘
    _ = win.print(&.{.{ .text = top_buf[0 .. i + 3], .style = style }}, .{ .col_offset = col, .row_offset = row, .wrap = .none });
    _ = win.print(&.{.{ .text = bot_buf[0 .. i + 3], .style = style }}, .{ .col_offset = col, .row_offset = row + h - 1, .wrap = .none });

    // Side borders.
    var r: u16 = 1;
    while (r < h - 1) : (r += 1) {
        _ = win.print(&.{.{ .text = "\xe2\x94\x82", .style = style }}, .{ .col_offset = col, .row_offset = row + r, .wrap = .none }); // │
        _ = win.print(&.{.{ .text = "\xe2\x94\x82", .style = style }}, .{ .col_offset = col + w - 1, .row_offset = row + r, .wrap = .none });
    }
}

/// Render the reservation add/edit form as a centered overlay.
fn renderReservationForm(state: *TuiState, win: vaxis.Window, fa: std.mem.Allocator) !void {
    const BOX_W: u16 = 54;
    const BOX_H: u16 = 11;
    if (win.width < BOX_W or win.height < BOX_H) return;

    const col: u16 = (win.width - BOX_W) / 2;
    const row: u16 = (win.height -| BOX_H) / 2;

    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 160, 255 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const title_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 200, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    const label_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 180, 180 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const field_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 220, 220, 220 } }, .bg = .{ .rgb = .{ 40, 40, 55 } } };
    const active_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 255, 255 } }, .bg = .{ .rgb = .{ 50, 80, 140 } } };
    const cursor_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 0, 0, 0 } }, .bg = .{ .rgb = .{ 100, 180, 255 } } };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 120, 120, 120 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const err_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 80, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    const ro_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 160, 0 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };

    // Fill box interior background.
    var r: u16 = 0;
    while (r < BOX_H) : (r += 1) {
        const fill = try fa.alloc(u8, BOX_W);
        @memset(fill, ' ');
        _ = win.print(&.{.{ .text = fill, .style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } } }}, .{ .col_offset = col, .row_offset = row + r, .wrap = .none });
    }
    drawBox(win, row, col, BOX_W, BOX_H, border_style);

    const title = if (state.form.isNew()) "  New Reservation" else "  Edit Reservation";
    _ = win.print(&.{.{ .text = title, .style = title_style }}, .{ .col_offset = col + 1, .row_offset = row + 1, .wrap = .none });

    const fields = [3]struct { label: []const u8, buf: []const u8, len: usize }{
        .{ .label = "  IP Address : ", .buf = &state.form.ip_buf, .len = state.form.ip_len },
        .{ .label = "  MAC Address: ", .buf = &state.form.mac_buf, .len = state.form.mac_len },
        .{ .label = "  Hostname   : ", .buf = &state.form.hostname_buf, .len = state.form.hostname_len },
    };
    const FIELD_W: u16 = 22;

    for (fields, 0..) |f, fi| {
        const fr: u16 = row + 3 + @as(u16, @intCast(fi)) * 2;
        _ = win.print(&.{.{ .text = f.label, .style = label_style }}, .{ .col_offset = col + 1, .row_offset = fr, .wrap = .none });
        const is_active = state.form.active_field == @as(u8, @intCast(fi));
        const fs = if (is_active) active_style else field_style;
        const value = f.buf[0..f.len];
        // Pad field to FIELD_W, show cursor at end if active.
        const pad = if (value.len < FIELD_W) FIELD_W - @as(u16, @intCast(value.len)) else 0;
        const padded = try fa.alloc(u8, pad);
        @memset(padded, ' ');
        const lbl_len: u16 = @intCast(f.label.len);
        _ = win.print(&.{.{ .text = value, .style = fs }}, .{ .col_offset = col + 1 + lbl_len, .row_offset = fr, .wrap = .none });
        _ = win.print(&.{.{ .text = padded, .style = fs }}, .{ .col_offset = col + 1 + lbl_len + @as(u16, @intCast(value.len)), .row_offset = fr, .wrap = .none });
        if (is_active) {
            // Draw cursor block at the insert position.
            _ = win.print(&.{.{ .text = " ", .style = cursor_style }}, .{ .col_offset = col + 1 + lbl_len + @as(u16, @intCast(value.len)), .row_offset = fr, .wrap = .none });
        }
    }

    _ = win.print(&.{.{ .text = "  Tab/Shift-Tab: next/prev  Enter: save  Esc: close", .style = hint_style }}, .{ .col_offset = col + 1, .row_offset = row + BOX_H - 3, .wrap = .none });

    if (state.form.err_len > 0) {
        _ = win.print(&.{.{ .text = state.form.err_buf[0..state.form.err_len], .style = err_style }}, .{ .col_offset = col + 1, .row_offset = row + BOX_H - 2, .wrap = .none });
    } else if (state.form.saved) {
        const saved_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 80, 220, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
        _ = win.print(&.{.{ .text = "  Saved!", .style = saved_style }}, .{ .col_offset = col + 1, .row_offset = row + BOX_H - 2, .wrap = .none });
    } else {
        _ = win.print(&.{.{ .text = "  (hostname optional)", .style = ro_style }}, .{ .col_offset = col + 1, .row_offset = row + BOX_H - 2, .wrap = .none });
    }
}

/// Save the form: update StateStore + config.yaml. Returns an error message on failure.
fn saveReservation(server: *AdminServer, form: *const ReservationForm) ?[]const u8 {
    const ip = form.ip_buf[0..form.ip_len];
    const mac = form.mac_buf[0..form.mac_len];
    const hostname_raw = form.hostname_buf[0..form.hostname_len];
    const hostname: ?[]const u8 = if (hostname_raw.len > 0) hostname_raw else null;

    if (ip.len == 0) return "IP address is required";
    if (mac.len == 0) return "MAC address is required";

    // If editing (has orig_mac) and MAC changed, remove old entry first.
    const orig_mac = form.orig_mac[0..form.orig_mac_len];
    if (orig_mac.len > 0 and !std.mem.eql(u8, orig_mac, mac)) {
        server.store.removeLease(orig_mac);
        if (config_write.findPoolForIp(server.cfg, ip)) |pool| {
            _ = config_write.removeReservation(server.allocator, pool, orig_mac);
        }
    }

    // Update StateStore.
    server.store.addReservation(mac, ip, hostname, null) catch |err| {
        return @errorName(err);
    };

    // Update config.yaml.
    if (config_write.findPoolForIp(server.cfg, ip)) |pool| {
        _ = config_write.upsertReservation(server.allocator, pool, mac, ip, hostname, null) catch |err| {
            return @errorName(err);
        };
        config_write.writeConfig(server.allocator, server.cfg, server.cfg_path) catch |err| {
            return @errorName(err);
        };
    } else {
        return "IP not in any configured pool";
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

    if (key.matches(vaxis.Key.enter, .{}) or
        (key.matches(vaxis.Key.tab, .{}) and form.active_field == 2))
    {
        // Save on Enter (any field) or Tab past the last field.
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

    if (key.matches(vaxis.Key.tab, .{})) {
        form.active_field = (form.active_field + 1) % 3;
        return;
    }
    if (key.matches(vaxis.Key.tab, .{ .shift = true })) {
        form.active_field = if (form.active_field == 0) 2 else form.active_field - 1;
        return;
    }

    // Text input for the active field.
    if (key.matches(vaxis.Key.backspace, .{})) {
        switch (form.active_field) {
            0 => if (form.ip_len > 0) {
                form.ip_len -= 1;
            },
            1 => if (form.mac_len > 0) {
                form.mac_len -= 1;
            },
            2 => if (form.hostname_len > 0) {
                form.hostname_len -= 1;
            },
            else => {},
        }
        return;
    }
    if (key.codepoint >= 0x20 and key.codepoint <= 0x7E) {
        const ch: u8 = @intCast(key.codepoint);
        switch (form.active_field) {
            0 => if (form.ip_len < form.ip_buf.len - 1) {
                form.ip_buf[form.ip_len] = ch;
                form.ip_len += 1;
            },
            1 => if (form.mac_len < form.mac_buf.len - 1) {
                form.mac_buf[form.mac_len] = ch;
                form.mac_len += 1;
            },
            2 => if (form.hostname_len < form.hostname_buf.len - 1) {
                form.hostname_buf[form.hostname_len] = ch;
                form.hostname_len += 1;
            },
            else => {},
        }
    }
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

    const ip = state.del_ip[0..state.del_ip_len];
    // Build prompt inline with a fixed-size buffer.
    var prompt_buf: [60]u8 = undefined;
    const prompt = std.fmt.bufPrint(&prompt_buf, "  Delete reservation for {s}? [y/N]", .{ip}) catch "  Delete reservation? [y/N]";
    _ = win.print(&.{.{ .text = prompt, .style = text_style }}, .{ .col_offset = col + 1, .row_offset = row + 1, .wrap = .none });
    _ = win.print(&.{.{ .text = "  y = confirm   Esc / any other key = cancel", .style = hint_style }}, .{ .col_offset = col + 1, .row_offset = row + 3, .wrap = .none });
}

fn handleDeleteConfirmKey(server: *AdminServer, state: *TuiState, key: vaxis.Key) void {
    if (key.matches('y', .{})) {
        const mac = state.del_mac[0..state.del_mac_len];
        const ip = state.del_ip[0..state.del_ip_len];
        server.store.removeLease(mac);
        if (config_write.findPoolForIp(server.cfg, ip)) |pool| {
            _ = config_write.removeReservation(server.allocator, pool, mac);
            config_write.writeConfig(server.allocator, server.cfg, server.cfg_path) catch |err| {
                log.warn("delete reservation: failed to write config: {s}", .{@errorName(err)});
            };
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
    return (ip_int & pool.subnet_mask) == subnet_int;
}

// ---------------------------------------------------------------------------
// Pool config tab: list, detail view, edit form, diff/confirm, save logic
// ---------------------------------------------------------------------------

/// Field metadata for the pool form: label, section header (if first in group).
const PoolFieldMeta = struct {
    label: []const u8,
    section: ?[]const u8 = null, // non-null = render section header before this field
    sensitive: bool = false, // hidden in read_only detail view
};

const pool_field_meta = [_]PoolFieldMeta{
    .{ .label = "Subnet", .section = "Network" },
    .{ .label = "Router" },
    .{ .label = "Pool Start" },
    .{ .label = "Pool End" },
    .{ .label = "Domain Name", .section = "Naming" },
    .{ .label = "Domain Search" },
    .{ .label = "DNS Servers", .section = "DNS" },
    .{ .label = "Lease Time", .section = "Timing" },
    .{ .label = "Time Offset" },
    .{ .label = "Time Servers", .section = "Servers" },
    .{ .label = "Log Servers" },
    .{ .label = "NTP Servers" },
    .{ .label = "TFTP Server", .section = "Boot" },
    .{ .label = "Boot Filename" },
    .{ .label = "HTTP Boot URL" },
    .{ .label = "DNS Upd Enable", .section = "DNS Update" },
    .{ .label = "DNS Upd Server" },
    .{ .label = "DNS Upd Zone" },
    .{ .label = "DNS Upd Key Name", .sensitive = true },
    .{ .label = "DNS Upd Key File", .sensitive = true },
};

/// Return the string value of a pool form field by index.
fn poolFormFieldVal(form: *const PoolForm, idx: u8) []const u8 {
    return switch (idx) {
        0 => form.subnet_buf[0..form.subnet_len],
        1 => form.router_buf[0..form.router_len],
        2 => form.pool_start_buf[0..form.pool_start_len],
        3 => form.pool_end_buf[0..form.pool_end_len],
        4 => form.domain_name_buf[0..form.domain_name_len],
        5 => form.domain_search_buf[0..form.domain_search_len],
        6 => form.dns_servers_buf[0..form.dns_servers_len],
        7 => form.lease_time_buf[0..form.lease_time_len],
        8 => form.time_offset_buf[0..form.time_offset_len],
        9 => form.time_servers_buf[0..form.time_servers_len],
        10 => form.log_servers_buf[0..form.log_servers_len],
        11 => form.ntp_servers_buf[0..form.ntp_servers_len],
        12 => form.tftp_server_buf[0..form.tftp_server_len],
        13 => form.boot_filename_buf[0..form.boot_filename_len],
        14 => form.http_boot_url_buf[0..form.http_boot_url_len],
        15 => if (form.dns_update_enable) "yes" else "no",
        16 => form.dns_update_server_buf[0..form.dns_update_server_len],
        17 => form.dns_update_zone_buf[0..form.dns_update_zone_len],
        18 => form.dns_update_key_name_buf[0..form.dns_update_key_name_len],
        19 => form.dns_update_key_file_buf[0..form.dns_update_key_file_len],
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
        4 => .{ .buf = &form.domain_name_buf, .len = &form.domain_name_len },
        5 => .{ .buf = &form.domain_search_buf, .len = &form.domain_search_len },
        6 => .{ .buf = &form.dns_servers_buf, .len = &form.dns_servers_len },
        7 => .{ .buf = &form.lease_time_buf, .len = &form.lease_time_len },
        8 => .{ .buf = &form.time_offset_buf, .len = &form.time_offset_len },
        9 => .{ .buf = &form.time_servers_buf, .len = &form.time_servers_len },
        10 => .{ .buf = &form.log_servers_buf, .len = &form.log_servers_len },
        11 => .{ .buf = &form.ntp_servers_buf, .len = &form.ntp_servers_len },
        12 => .{ .buf = &form.tftp_server_buf, .len = &form.tftp_server_len },
        13 => .{ .buf = &form.boot_filename_buf, .len = &form.boot_filename_len },
        14 => .{ .buf = &form.http_boot_url_buf, .len = &form.http_boot_url_len },
        // 15 = boolean toggle, not a text buffer
        16 => .{ .buf = &form.dns_update_server_buf, .len = &form.dns_update_server_len },
        17 => .{ .buf = &form.dns_update_zone_buf, .len = &form.dns_update_zone_len },
        18 => .{ .buf = &form.dns_update_key_name_buf, .len = &form.dns_update_key_name_len },
        19 => .{ .buf = &form.dns_update_key_file_buf, .len = &form.dns_update_key_file_len },
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

    form.domain_search_len = joinComma(256, &form.domain_search_buf, pool.domain_search);
    form.dns_servers_len = joinComma(128, &form.dns_servers_buf, pool.dns_servers);

    // lease_time as decimal string
    const lt_str = std.fmt.bufPrint(&form.lease_time_buf, "{d}", .{pool.lease_time}) catch "";
    form.lease_time_len = lt_str.len;

    if (pool.time_offset) |off| {
        const off_str = std.fmt.bufPrint(&form.time_offset_buf, "{d}", .{off}) catch "";
        form.time_offset_len = off_str.len;
    }

    form.time_servers_len = joinComma(128, &form.time_servers_buf, pool.time_servers);
    form.log_servers_len = joinComma(128, &form.log_servers_buf, pool.log_servers);
    form.ntp_servers_len = joinComma(128, &form.ntp_servers_buf, pool.ntp_servers);

    copyField(&form.tftp_server_buf, &form.tftp_server_len, pool.tftp_server_name);
    copyField(&form.boot_filename_buf, &form.boot_filename_len, pool.boot_filename);
    copyField(&form.http_boot_url_buf, &form.http_boot_url_len, pool.http_boot_url);

    form.dns_update_enable = pool.dns_update.enable;
    copyField(&form.dns_update_server_buf, &form.dns_update_server_len, pool.dns_update.server);
    copyField(&form.dns_update_zone_buf, &form.dns_update_zone_len, pool.dns_update.zone);
    copyField(&form.dns_update_key_name_buf, &form.dns_update_key_name_len, pool.dns_update.key_name);
    copyField(&form.dns_update_key_file_buf, &form.dns_update_key_file_len, pool.dns_update.key_file);
}

fn copyField(buf: anytype, len: *usize, src: []const u8) void {
    const n = @min(src.len, buf.len);
    @memcpy(buf[0..n], src[0..n]);
    len.* = n;
}

// ---- Pool list tab ----

fn renderPoolsTab(server: *AdminServer, state: *TuiState, body: vaxis.Window, fa: std.mem.Allocator) !void {
    const pools = server.cfg.pools;
    if (pools.len == 0) {
        _ = body.print(&.{.{ .text = "  No pools configured.", .style = .{ .fg = .{ .rgb = .{ 180, 180, 180 } } } }}, .{ .row_offset = 1, .wrap = .none });
        return;
    }

    const hdr_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 180, 200, 255 } }, .bold = true };
    const sel_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 255, 255 } }, .bg = .{ .rgb = .{ 50, 80, 140 } } };
    const normal_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 200, 200, 200 } } };

    // Clamp selection.
    if (state.pool_row >= pools.len) state.pool_row = @intCast(pools.len - 1);

    const avail_h = body.height;
    const data_h = if (avail_h > 1) avail_h - 1 else 1; // header row

    // Scroll viewport to keep selection visible.
    if (state.pool_row < state.pool_start) state.pool_start = state.pool_row;
    if (state.pool_row >= state.pool_start + data_h) state.pool_start = state.pool_row - data_h + 1;

    // Header.
    const hdr = try std.fmt.allocPrint(fa, "  {s:<20} {s:<30} {s:<16} {s:>7}  {s:>4}  {s:<6}", .{ "Subnet", "Range", "Router", "Lease", "Res", "DNS" });
    _ = body.print(&.{.{ .text = hdr, .style = hdr_style }}, .{ .row_offset = 0, .wrap = .none });

    // Pool rows.
    var row: u16 = 0;
    var i: usize = state.pool_start;
    while (i < pools.len and row < data_h) : ({
        i += 1;
        row += 1;
    }) {
        const p = &pools[i];
        const subnet_label = std.fmt.allocPrint(fa, "{s}/{d}", .{ p.subnet, p.prefix_len }) catch "?";
        const range_label = if (p.pool_start.len > 0 and p.pool_end.len > 0)
            std.fmt.allocPrint(fa, "{s} - {s}", .{ p.pool_start, p.pool_end }) catch "?"
        else
            "auto";
        const dns_label: []const u8 = if (p.dns_update.enable) "yes" else "no";
        const line = try std.fmt.allocPrint(fa, "  {s:<20} {s:<30} {s:<16} {d:>7}  {d:>4}  {s:<6}", .{
            subnet_label,
            range_label,
            p.router,
            p.lease_time,
            p.reservations.len,
            dns_label,
        });
        const style = if (i == state.pool_row) sel_style else normal_style;
        _ = body.print(&.{.{ .text = line, .style = style }}, .{ .row_offset = 1 + row, .wrap = .none });
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
        state.pool_form.editing_index = state.pool_row;
        populatePoolForm(&state.pool_form, &server.cfg.pools[state.pool_row]);
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
    const label_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 140, 160, 200 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const val_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 220, 220, 220 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const section_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 80, 180, 255 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };

    // Title.
    const title = std.fmt.allocPrint(fa, " Pool: {s}/{d} ", .{ pool.subnet, pool.prefix_len }) catch " Pool ";
    _ = box.print(&.{.{ .text = title, .style = border_style }}, .{ .row_offset = 0, .wrap = .none });

    // Build lines.
    var lines: [40]struct { text: []const u8, style: vaxis.Style } = undefined;
    var lcount: usize = 0;

    const fields = pool_field_meta;
    for (fields, 0..) |meta, fi| {
        if (read_only and meta.sensitive) continue;
        if (meta.section) |sec| {
            lines[lcount] = .{ .text = std.fmt.allocPrint(fa, "  -- {s} --", .{sec}) catch "", .style = section_style };
            lcount += 1;
        }
        const val: []const u8 = switch (fi) {
            0 => std.fmt.allocPrint(fa, "{s}/{d}", .{ pool.subnet, pool.prefix_len }) catch "?",
            1 => pool.router,
            2 => if (pool.pool_start.len > 0) pool.pool_start else "\xe2\x80\x94",
            3 => if (pool.pool_end.len > 0) pool.pool_end else "\xe2\x80\x94",
            4 => if (pool.domain_name.len > 0) pool.domain_name else "\xe2\x80\x94",
            5 => if (pool.domain_search.len > 0) blk: {
                break :blk std.fmt.allocPrint(fa, "{s}", .{std.mem.join(fa, ", ", pool.domain_search) catch "\xe2\x80\x94"}) catch "\xe2\x80\x94";
            } else "\xe2\x80\x94",
            6 => if (pool.dns_servers.len > 0) blk: {
                break :blk std.mem.join(fa, ", ", pool.dns_servers) catch "\xe2\x80\x94";
            } else "\xe2\x80\x94",
            7 => std.fmt.allocPrint(fa, "{d}", .{pool.lease_time}) catch "?",
            8 => if (pool.time_offset) |off| std.fmt.allocPrint(fa, "{d}", .{off}) catch "?" else "\xe2\x80\x94",
            9 => if (pool.time_servers.len > 0) (std.mem.join(fa, ", ", pool.time_servers) catch "\xe2\x80\x94") else "\xe2\x80\x94",
            10 => if (pool.log_servers.len > 0) (std.mem.join(fa, ", ", pool.log_servers) catch "\xe2\x80\x94") else "\xe2\x80\x94",
            11 => if (pool.ntp_servers.len > 0) (std.mem.join(fa, ", ", pool.ntp_servers) catch "\xe2\x80\x94") else "\xe2\x80\x94",
            12 => if (pool.tftp_server_name.len > 0) pool.tftp_server_name else "\xe2\x80\x94",
            13 => if (pool.boot_filename.len > 0) pool.boot_filename else "\xe2\x80\x94",
            14 => if (pool.http_boot_url.len > 0) pool.http_boot_url else "\xe2\x80\x94",
            15 => if (pool.dns_update.enable) "yes" else "no",
            16 => if (pool.dns_update.server.len > 0) pool.dns_update.server else "\xe2\x80\x94",
            17 => if (pool.dns_update.zone.len > 0) pool.dns_update.zone else "\xe2\x80\x94",
            18 => if (pool.dns_update.key_name.len > 0) pool.dns_update.key_name else "\xe2\x80\x94",
            19 => if (pool.dns_update.key_file.len > 0) pool.dns_update.key_file else "\xe2\x80\x94",
            else => "\xe2\x80\x94",
        };
        const line = std.fmt.allocPrint(fa, "  {s:<18} {s}", .{ meta.label, val }) catch "";
        lines[lcount] = .{ .text = line, .style = if (meta.section != null) val_style else val_style };
        lcount += 1;
    }
    // Summary lines.
    lines[lcount] = .{ .text = std.fmt.allocPrint(fa, "  Reservations: {d}    Static routes: {d}", .{ pool.reservations.len, pool.static_routes.len }) catch "", .style = label_style };
    lcount += 1;

    // Scrollable content.
    const content_h = BOX_H - 3; // title + hint + bottom padding
    if (state.pool_detail_scroll + content_h > lcount) {
        state.pool_detail_scroll = if (lcount > content_h) @intCast(lcount - content_h) else 0;
    }
    var row: u16 = 1;
    var li: usize = state.pool_detail_scroll;
    while (li < lcount and row < BOX_H - 2) : ({
        li += 1;
        row += 1;
    }) {
        _ = box.print(&.{.{ .text = lines[li].text, .style = lines[li].style }}, .{ .row_offset = row, .wrap = .none });
    }

    // Hint bar.
    const hint_text = if (read_only) "  Esc: close  \xe2\x86\x91/\xe2\x86\x93: scroll" else "  e: edit  Esc: close  \xe2\x86\x91/\xe2\x86\x93: scroll";
    _ = box.print(&.{.{ .text = hint_text, .style = hint_style }}, .{ .row_offset = BOX_H - 1, .wrap = .none });
}

fn handlePoolDetailKey(server: *AdminServer, state: *TuiState, key: vaxis.Key) void {
    if (key.matches(vaxis.Key.escape, .{}) or key.matches('q', .{})) {
        state.mode = .normal;
    } else if (key.matches('e', .{}) and !server.cfg.admin_ssh.read_only) {
        // Transition to edit form for the same pool.
        state.pool_form = .{};
        state.pool_form.editing_index = state.pool_row;
        populatePoolForm(&state.pool_form, &server.cfg.pools[state.pool_row]);
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
    const BOX_W: u16 = 64;
    const BOX_H: u16 = 20;
    if (win.width < BOX_W or win.height < BOX_H) return;
    const x = (win.width - BOX_W) / 2;
    const y = (win.height - BOX_H) / 2;
    const box = win.child(.{ .x_off = x, .y_off = y, .width = BOX_W, .height = BOX_H });
    box.fill(.{ .char = .{ .grapheme = " ", .width = 1 }, .style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } } });

    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 160, 255 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const section_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 80, 180, 255 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    const label_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 160, 160, 190 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const field_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 200, 200, 200 } }, .bg = .{ .rgb = .{ 30, 30, 45 } } };
    const active_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 255, 255 } }, .bg = .{ .rgb = .{ 50, 80, 140 } } };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const err_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 80, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };

    // Title.
    const title = if (form.isNew()) "  New Pool" else std.fmt.allocPrint(fa, "  Edit Pool: {s}", .{form.subnet_buf[0..form.subnet_len]}) catch "  Edit Pool";
    _ = box.print(&.{.{ .text = title, .style = border_style }}, .{ .row_offset = 0, .wrap = .none });

    // Field rendering area: rows 1 .. BOX_H-3.
    const field_h = BOX_H - 3;
    const FIELD_W: u16 = 32;

    // Ensure scroll_offset keeps active_field visible.
    if (form.active_field < form.scroll_offset)
        form.scroll_offset = form.active_field;
    if (form.active_field >= form.scroll_offset + @as(u8, @intCast(field_h)))
        form.scroll_offset = form.active_field - @as(u8, @intCast(field_h)) + 1;

    var row: u16 = 1;
    var fi: u8 = form.scroll_offset;
    while (fi < PoolForm.FIELD_COUNT and row <= field_h) : (fi += 1) {
        const meta = pool_field_meta[fi];
        // Section header (if this is the first field in a group and we have room).
        if (meta.section) |sec| {
            if (row <= field_h) {
                const sec_text = std.fmt.allocPrint(fa, "  -- {s} --", .{sec}) catch "";
                _ = box.print(&.{.{ .text = sec_text, .style = section_style }}, .{ .row_offset = row, .wrap = .none });
                row += 1;
                if (row > field_h) break;
            }
        }

        const is_active = fi == form.active_field;
        const style = if (is_active) active_style else field_style;
        const val = poolFormFieldVal(form, fi);
        const label_text = std.fmt.allocPrint(fa, "  {s:<17}", .{meta.label}) catch "";
        _ = box.print(&.{.{ .text = label_text, .style = label_style }}, .{ .row_offset = row, .wrap = .none });

        // Value field — pad to FIELD_W.
        const val_trunc = val[0..@min(val.len, FIELD_W)];
        const pad_len = FIELD_W - @as(u16, @intCast(val_trunc.len));
        const padded = std.fmt.allocPrint(fa, "{s}{s}", .{ val_trunc, spaces(fa, pad_len) catch "" }) catch val_trunc;
        _ = box.print(&.{.{ .text = padded, .style = style }}, .{ .col_offset = 19, .row_offset = row, .wrap = .none });

        // Cursor for active field.
        if (is_active and fi != 15) { // 15 = boolean toggle, no cursor
            const cursor_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 20, 20, 30 } }, .bg = .{ .rgb = .{ 100, 160, 255 } } };
            const cursor_col: u16 = 19 + @as(u16, @intCast(val_trunc.len));
            if (cursor_col < BOX_W - 1) {
                _ = box.print(&.{.{ .text = " ", .style = cursor_style }}, .{ .col_offset = cursor_col, .row_offset = row, .wrap = .none });
            }
        }
        row += 1;
    }

    // Hint + error.
    _ = box.print(&.{.{ .text = "  Tab: next  Shift-Tab: prev  Enter: review  Esc: cancel", .style = hint_style }}, .{ .row_offset = BOX_H - 2, .wrap = .none });
    if (form.err_len > 0) {
        _ = box.print(&.{.{ .text = form.err_buf[0..form.err_len], .style = err_style }}, .{ .row_offset = BOX_H - 1, .wrap = .none });
    }
}

fn spaces(fa: std.mem.Allocator, n: u16) ![]const u8 {
    if (n == 0) return "";
    const buf = try fa.alloc(u8, n);
    @memset(buf, ' ');
    return buf;
}

fn handlePoolFormKey(server: *AdminServer, state: *TuiState, key: vaxis.Key) void {
    var form = &state.pool_form;
    form.err_len = 0;

    if (key.matches(vaxis.Key.escape, .{})) {
        state.mode = .normal;
        return;
    }
    if (key.matches(vaxis.Key.enter, .{})) {
        // Validate and proceed to confirm screen.
        if (validatePoolForm(form)) |err_msg| {
            form.err_len = @min(err_msg.len, form.err_buf.len);
            @memcpy(form.err_buf[0..form.err_len], err_msg[0..form.err_len]);
            return;
        }
        computePoolDiff(server, state);
        state.mode = .pool_save_confirm;
        return;
    }
    if (key.matches(vaxis.Key.tab, .{ .shift = true })) {
        if (form.active_field > 0) form.active_field -= 1;
        return;
    }
    if (key.matches(vaxis.Key.tab, .{})) {
        if (form.active_field + 1 < PoolForm.FIELD_COUNT) form.active_field += 1;
        return;
    }

    // Field 15 = dns_update_enable: toggle on space or any printable
    if (form.active_field == 15) {
        if (key.codepoint == ' ' or (key.codepoint >= 0x20 and key.codepoint <= 0x7E)) {
            form.dns_update_enable = !form.dns_update_enable;
        }
        return;
    }

    // Text input.
    if (key.matches(vaxis.Key.backspace, .{})) {
        if (poolFormFieldBuf(form, form.active_field)) |fb| {
            if (fb.len.* > 0) fb.len.* -= 1;
        }
    } else if (key.codepoint >= 0x20 and key.codepoint <= 0x7E) {
        if (poolFormFieldBuf(form, form.active_field)) |fb| {
            if (fb.len.* < fb.buf.len) {
                fb.buf[fb.len.*] = @intCast(key.codepoint);
                fb.len.* += 1;
            }
        }
    }
}

fn validatePoolForm(form: *const PoolForm) ?[]const u8 {
    // Subnet: must be x.x.x.x/N
    const subnet = form.subnet_buf[0..form.subnet_len];
    if (subnet.len == 0) return "Subnet is required (e.g. 192.168.1.0/24)";
    if (std.mem.indexOfScalar(u8, subnet, '/') == null) return "Subnet must include /prefix (e.g. 192.168.1.0/24)";
    if (parseSubnet(subnet) == null) return "Invalid subnet format";

    // Router: must be valid IPv4
    const router = form.router_buf[0..form.router_len];
    if (router.len == 0) return "Router is required";
    _ = config_mod.parseIpv4(router) catch return "Invalid router IP";

    // Pool start/end: optional but must be valid IPv4 if set
    if (form.pool_start_len > 0) {
        _ = config_mod.parseIpv4(form.pool_start_buf[0..form.pool_start_len]) catch return "Invalid pool start IP";
    }
    if (form.pool_end_len > 0) {
        _ = config_mod.parseIpv4(form.pool_end_buf[0..form.pool_end_len]) catch return "Invalid pool end IP";
    }

    // Lease time: positive integer
    const lt = form.lease_time_buf[0..form.lease_time_len];
    if (lt.len == 0) return "Lease time is required";
    _ = std.fmt.parseInt(u32, lt, 10) catch return "Lease time must be a positive number";

    // Time offset: optional signed integer
    if (form.time_offset_len > 0) {
        _ = std.fmt.parseInt(i32, form.time_offset_buf[0..form.time_offset_len], 10) catch return "Time offset must be an integer";
    }

    // Comma-separated IP lists: validate each entry
    if (form.dns_servers_len > 0) {
        if (validateIpList(form.dns_servers_buf[0..form.dns_servers_len])) |e| return e;
    }
    if (form.time_servers_len > 0) {
        if (validateIpList(form.time_servers_buf[0..form.time_servers_len])) |e| return e;
    }
    if (form.log_servers_len > 0) {
        if (validateIpList(form.log_servers_buf[0..form.log_servers_len])) |e| return e;
    }
    if (form.ntp_servers_len > 0) {
        if (validateIpList(form.ntp_servers_buf[0..form.ntp_servers_len])) |e| return e;
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

fn parseSubnet(s: []const u8) ?struct { ip: [4]u8, prefix: u8, mask: u32 } {
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
        while (fi < PoolForm.FIELD_COUNT) : (fi += 1) {
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
        return;
    }

    // Editing existing pool.
    const pool = &server.cfg.pools[form.editing_index.?];
    var tmp_form: PoolForm = .{};
    populatePoolForm(&tmp_form, pool);

    // Sync-breaking field indices: subnet(0), pool_start(2), pool_end(3), lease_time(7)
    const sync_fields = [_]u8{ 0, 2, 3, 7 };

    var fi: u8 = 0;
    while (fi < PoolForm.FIELD_COUNT) : (fi += 1) {
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
}

// ---- Confirm screen ----

fn renderPoolSaveConfirm(server: *AdminServer, state: *TuiState, win: vaxis.Window, fa: std.mem.Allocator) !void {
    const confirm = &state.pool_confirm;
    const has_sync = server.sync_mgr != null;

    const BOX_W: u16 = 64;
    const change_lines: u16 = @intCast(@min(confirm.change_count, 10));
    const warn_lines: u16 = if (confirm.has_sync_break and has_sync) 3 else 0;
    const BOX_H: u16 = 5 + change_lines + warn_lines;
    if (win.width < BOX_W or win.height < BOX_H) return;
    const x = (win.width - BOX_W) / 2;
    const y = (win.height - BOX_H) / 2;
    const box = win.child(.{ .x_off = x, .y_off = y, .width = BOX_W, .height = BOX_H });
    box.fill(.{ .char = .{ .grapheme = " ", .width = 1 }, .style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } } });

    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 160, 255 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const sync_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 80, 80 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    const drift_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 220, 180, 60 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const warn_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 100, 100 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };

    const title = if (confirm.is_new_pool) " Confirm New Pool " else if (confirm.is_delete) " Confirm Delete " else " Confirm Changes ";
    _ = box.print(&.{.{ .text = title, .style = border_style }}, .{ .row_offset = 0, .wrap = .none });

    if (confirm.change_count == 0 and !confirm.is_new_pool and !confirm.is_delete) {
        _ = box.print(&.{.{ .text = "  No changes detected.", .style = hint_style }}, .{ .row_offset = 1, .wrap = .none });
        _ = box.print(&.{.{ .text = "  Esc: back", .style = hint_style }}, .{ .row_offset = 2, .wrap = .none });
        return;
    }

    var row: u16 = 1;

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
        _ = box.print(&.{.{ .text = line, .style = style }}, .{ .row_offset = row, .wrap = .none });
        row += 1;
    }

    // Sync warning.
    if (confirm.has_sync_break and has_sync) {
        row += 1;
        _ = box.print(&.{.{ .text = "  !! This will break peer sync. All peers must", .style = warn_style }}, .{ .row_offset = row, .wrap = .none });
        row += 1;
        _ = box.print(&.{.{ .text = "     be updated and restarted with matching config.", .style = warn_style }}, .{ .row_offset = row, .wrap = .none });
        row += 1;
    }

    // Action + hint.
    _ = box.print(&.{.{ .text = "  Config will be saved and reloaded.", .style = hint_style }}, .{ .row_offset = BOX_H - 2, .wrap = .none });
    _ = box.print(&.{.{ .text = "  Y: confirm  N/Esc: cancel", .style = hint_style }}, .{ .row_offset = BOX_H - 1, .wrap = .none });
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

    if (form.isNew()) {
        // Build a new PoolConfig from form fields.
        const pool = buildPoolFromForm(server.allocator, form) orelse return;
        config_write.addPool(server.allocator, server.cfg, pool) catch return;
    } else {
        // Update existing pool in place.
        const idx = form.editing_index.?;
        if (idx >= server.cfg.pools.len) return;
        applyFormToPool(server.allocator, &server.cfg.pools[idx], form);
    }

    // Persist and reload.
    config_write.writeConfig(server.allocator, server.cfg, server.cfg_path) catch return;
    triggerReload(state);
}

fn buildPoolFromForm(allocator: std.mem.Allocator, form: *const PoolForm) ?config_mod.PoolConfig {
    const subnet_info = parseSubnet(form.subnet_buf[0..form.subnet_len]) orelse return null;
    const lease_time = std.fmt.parseInt(u32, form.lease_time_buf[0..form.lease_time_len], 10) catch return null;

    return config_mod.PoolConfig{
        .subnet = allocator.dupe(u8, subnetIpStr(form)) catch return null,
        .subnet_mask = subnet_info.mask,
        .prefix_len = subnet_info.prefix,
        .router = allocator.dupe(u8, form.router_buf[0..form.router_len]) catch return null,
        .pool_start = allocator.dupe(u8, form.pool_start_buf[0..form.pool_start_len]) catch return null,
        .pool_end = allocator.dupe(u8, form.pool_end_buf[0..form.pool_end_len]) catch return null,
        .dns_servers = splitCommaDupe(allocator, form.dns_servers_buf[0..form.dns_servers_len]) catch return null,
        .domain_name = allocator.dupe(u8, form.domain_name_buf[0..form.domain_name_len]) catch return null,
        .domain_search = splitCommaDupe(allocator, form.domain_search_buf[0..form.domain_search_len]) catch return null,
        .lease_time = lease_time,
        .time_offset = if (form.time_offset_len > 0) (std.fmt.parseInt(i32, form.time_offset_buf[0..form.time_offset_len], 10) catch null) else null,
        .time_servers = splitCommaDupe(allocator, form.time_servers_buf[0..form.time_servers_len]) catch return null,
        .log_servers = splitCommaDupe(allocator, form.log_servers_buf[0..form.log_servers_len]) catch return null,
        .ntp_servers = splitCommaDupe(allocator, form.ntp_servers_buf[0..form.ntp_servers_len]) catch return null,
        .tftp_server_name = allocator.dupe(u8, form.tftp_server_buf[0..form.tftp_server_len]) catch return null,
        .boot_filename = allocator.dupe(u8, form.boot_filename_buf[0..form.boot_filename_len]) catch return null,
        .http_boot_url = allocator.dupe(u8, form.http_boot_url_buf[0..form.http_boot_url_len]) catch return null,
        .dns_update = .{
            .enable = form.dns_update_enable,
            .server = allocator.dupe(u8, form.dns_update_server_buf[0..form.dns_update_server_len]) catch return null,
            .zone = allocator.dupe(u8, form.dns_update_zone_buf[0..form.dns_update_zone_len]) catch return null,
            .rev_zone = allocator.dupe(u8, "") catch return null,
            .key_name = allocator.dupe(u8, form.dns_update_key_name_buf[0..form.dns_update_key_name_len]) catch return null,
            .key_file = allocator.dupe(u8, form.dns_update_key_file_buf[0..form.dns_update_key_file_len]) catch return null,
            .lease_time = lease_time,
        },
        .dhcp_options = std.StringHashMap([]const u8).init(allocator),
        .reservations = allocator.alloc(config_mod.Reservation, 0) catch return null,
        .static_routes = allocator.alloc(config_mod.StaticRoute, 0) catch return null,
    };
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

    replaceStrSlice(allocator, &pool.domain_search, form.domain_search_buf[0..form.domain_search_len]);
    replaceStrSlice(allocator, &pool.dns_servers, form.dns_servers_buf[0..form.dns_servers_len]);

    pool.lease_time = lease_time;
    pool.time_offset = if (form.time_offset_len > 0) (std.fmt.parseInt(i32, form.time_offset_buf[0..form.time_offset_len], 10) catch null) else null;

    replaceStrSlice(allocator, &pool.time_servers, form.time_servers_buf[0..form.time_servers_len]);
    replaceStrSlice(allocator, &pool.log_servers, form.log_servers_buf[0..form.log_servers_len]);
    replaceStrSlice(allocator, &pool.ntp_servers, form.ntp_servers_buf[0..form.ntp_servers_len]);

    replaceStr(allocator, &pool.tftp_server_name, form.tftp_server_buf[0..form.tftp_server_len]);
    replaceStr(allocator, &pool.boot_filename, form.boot_filename_buf[0..form.boot_filename_len]);
    replaceStr(allocator, &pool.http_boot_url, form.http_boot_url_buf[0..form.http_boot_url_len]);

    pool.dns_update.enable = form.dns_update_enable;
    replaceStr(allocator, &pool.dns_update.server, form.dns_update_server_buf[0..form.dns_update_server_len]);
    replaceStr(allocator, &pool.dns_update.zone, form.dns_update_zone_buf[0..form.dns_update_zone_len]);
    replaceStr(allocator, &pool.dns_update.key_name, form.dns_update_key_name_buf[0..form.dns_update_key_name_len]);
    replaceStr(allocator, &pool.dns_update.key_file, form.dns_update_key_file_buf[0..form.dns_update_key_file_len]);
    pool.dns_update.lease_time = lease_time;
}

fn replaceStr(allocator: std.mem.Allocator, field: *[]const u8, new_val: []const u8) void {
    allocator.free(field.*);
    field.* = allocator.dupe(u8, new_val) catch "";
}

fn replaceStrSlice(allocator: std.mem.Allocator, field: *[][]const u8, csv: []const u8) void {
    for (field.*) |s| allocator.free(s);
    allocator.free(field.*);
    field.* = splitCommaDupe(allocator, csv) catch allocator.alloc([]const u8, 0) catch &.{};
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
    const leases = server.store.listLeases() catch &.{};
    for (leases) |l| {
        if (isIpInPool(l.ip, pool)) lease_count += 1;
    }

    const BOX_W: u16 = 50;
    const BOX_H: u16 = if (has_sync) 8 else 6;
    if (win.width < BOX_W or win.height < BOX_H) return;
    const x = (win.width - BOX_W) / 2;
    const y = (win.height - BOX_H) / 2;
    const box = win.child(.{ .x_off = x, .y_off = y, .width = BOX_W, .height = BOX_H });
    box.fill(.{ .char = .{ .grapheme = " ", .width = 1 }, .style = .{ .bg = .{ .rgb = .{ 20, 20, 30 } } } });

    const border_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 100, 100 } }, .bg = .{ .rgb = .{ 20, 20, 30 } }, .bold = true };
    const text_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 220, 220, 220 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const warn_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 100, 100 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };
    const hint_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 100, 100, 130 } }, .bg = .{ .rgb = .{ 20, 20, 30 } } };

    _ = box.print(&.{.{ .text = " Delete Pool ", .style = border_style }}, .{ .row_offset = 0, .wrap = .none });

    const label = std.fmt.allocPrint(fa, "  Delete pool {s}/{d}?", .{ pool.subnet, pool.prefix_len }) catch "  Delete pool?";
    _ = box.print(&.{.{ .text = label, .style = text_style }}, .{ .row_offset = 1, .wrap = .none });

    var row: u16 = 2;
    if (lease_count > 0) {
        const lease_msg = std.fmt.allocPrint(fa, "  {d} active lease(s) in this pool.", .{lease_count}) catch "";
        _ = box.print(&.{.{ .text = lease_msg, .style = warn_style }}, .{ .row_offset = row, .wrap = .none });
        row += 1;
    }
    if (has_sync) {
        _ = box.print(&.{.{ .text = "  !! This will break peer sync.", .style = warn_style }}, .{ .row_offset = row, .wrap = .none });
        row += 1;
    }

    _ = box.print(&.{.{ .text = "  y: confirm  any other key: cancel", .style = hint_style }}, .{ .row_offset = BOX_H - 1, .wrap = .none });
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
    try std.testing.expectEqualStrings("very-long-ho…", result);
    try std.testing.expectEqual(@as(usize, 12 - 1 + 3), result.len); // content(11) + "…"(3 bytes)
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
    var ctx: vaxis.widgets.Table.TableContext = .{};

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
    var ctx: vaxis.widgets.Table.TableContext = .{};

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
