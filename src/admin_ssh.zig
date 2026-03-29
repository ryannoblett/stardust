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
            const thread = std.Thread.spawn(.{}, sessionThread, .{ self, session }) catch |err| {
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

const WinCtx = struct {
    pending_cols: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    pending_rows: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
};

fn ptyWindowChangeCb(
    _session: c.ssh_session,
    _channel: c.ssh_channel,
    width: c_int,
    height: c_int,
    _pxw: c_int,
    _pxh: c_int,
    userdata: ?*anyopaque,
) callconv(.c) c_int {
    _ = _session;
    _ = _channel;
    _ = _pxw;
    _ = _pxh;
    const ctx: *WinCtx = @ptrCast(@alignCast(userdata.?));
    if (width > 0) ctx.pending_cols.store(@intCast(width), .release);
    if (height > 0) ctx.pending_rows.store(@intCast(height), .release);
    return 0;
}

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

const Tab = enum(u8) { leases = 0, stats = 1 };

const TuiState = struct {
    tab: Tab = .leases,
    lease_row: u16 = 0,
    lease_start: u16 = 0,
};

fn runTui(
    server: *AdminServer,
    session: c.ssh_session,
    channel: c.ssh_channel,
    init_cols: u32,
    init_rows: u32,
    peer: []const u8,
) !void {
    _ = session;

    const allocator = server.allocator;

    log.debug("{s}: channel open={d} eof={d}", .{
        peer,
        c.ssh_channel_is_open(channel),
        c.ssh_channel_is_eof(channel),
    });

    // Set up SSH channel callbacks so resize events update our WinCtx.
    var winctx: WinCtx = .{};
    var chan_cbs = std.mem.zeroes(c.struct_ssh_channel_callbacks_struct);
    chan_cbs.size = @sizeOf(c.struct_ssh_channel_callbacks_struct);
    chan_cbs.userdata = &winctx;
    chan_cbs.channel_pty_window_change_function = ptyWindowChangeCb;
    _ = c.ssh_set_channel_callbacks(channel, &chan_cbs);

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

    // Read buffer for SSH channel input.
    var read_buf: [1024]u8 = undefined;
    var read_start: usize = 0;

    var running = true;
    while (running) {
        // Check for pending window resize.
        const pr = winctx.pending_rows.swap(0, .acq_rel);
        const pc = winctx.pending_cols.swap(0, .acq_rel);
        if (pr > 0 and pc > 0) {
            try vx.resize(allocator, io, .{
                .rows = @intCast(pr),
                .cols = @intCast(pc),
                .x_pixel = 0,
                .y_pixel = 0,
            });
        }

        // Non-blocking channel read (100 ms timeout).
        // Return values: >=0 bytes read; 0 = timeout/no data; -1 = SSH_ERROR;
        // -2 = SSH_AGAIN (session in non-blocking mode, no data yet — treat as
        // 0 and sleep briefly to avoid spinning).
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
        if (n_raw == -2) { // SSH_AGAIN: returned immediately, throttle the loop
            std.Thread.sleep(50 * std.time.ns_per_ms);
        }

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
                    if (key.matches('c', .{ .ctrl = true }) or
                        key.matches('q', .{}))
                    {
                        running = false;
                        break :parse_loop;
                    }
                    switch (state.tab) {
                        .leases => handleLeaseKey(&state, &table_ctx, key),
                        .stats => {},
                    }
                    if (key.matches('1', .{})) state.tab = .leases;
                    if (key.matches('2', .{})) state.tab = .stats;
                },
                .mouse => |_mouse| {
                    // TODO: click-to-select, scroll wheel
                    _ = _mouse;
                },
                else => {},
            }
        }

        // Render a frame and flush to the SSH channel.
        const win = vx.window();
        win.clear();
        try renderFrame(server, &state, &table_ctx, win, allocator);
        try vx.render(io);
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

// ---------------------------------------------------------------------------
// Frame rendering
// ---------------------------------------------------------------------------

fn renderFrame(
    server: *AdminServer,
    state: *TuiState,
    table_ctx: *vaxis.widgets.Table.TableContext,
    win: vaxis.Window,
    allocator: std.mem.Allocator,
) !void {
    if (win.height < 4 or win.width < 20) return; // terminal too small

    const h = win.height;
    const w = win.width;

    // Header bar (row 0)
    renderHeader(state, win.child(.{ .y_off = 0, .height = 1, .width = w }));

    // Body (rows 1 .. h-2)
    const body = win.child(.{
        .y_off = 1,
        .height = h -| 2,
        .width = w,
    });

    switch (state.tab) {
        .leases => try renderLeaseTab(server, state, table_ctx, body, allocator),
        .stats => try renderStatsTab(server, body, allocator),
    }

    // Status bar (last row)
    renderStatus(server, state, win.child(.{ .y_off = h -| 1, .height = 1, .width = w }));
}

fn renderHeader(state: *TuiState, win: vaxis.Window) void {
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
    _ = win.print(&.{.{ .text = leases_label, .style = if (state.tab == .leases) tab_style_active else tab_style_inactive }}, .{ .col_offset = col, .wrap = .none });
    col += @intCast(leases_label.len);
    _ = win.print(&.{.{ .text = stats_label, .style = if (state.tab == .stats) tab_style_active else tab_style_inactive }}, .{ .col_offset = col, .wrap = .none });
    col += @intCast(stats_label.len);

    const hint = "  j/k:move  q:quit";
    _ = win.print(&.{.{ .text = hint, .style = hint_style }}, .{ .col_offset = col, .wrap = .none });
}

fn renderStatus(server: *AdminServer, state: *TuiState, win: vaxis.Window) void {
    _ = state;
    const now = std.time.timestamp();
    const uptime_s = now - server.start_time;
    const uptime_h = @divTrunc(uptime_s, 3600);
    const uptime_m = @divTrunc(@rem(uptime_s, 3600), 60);

    const style: vaxis.Style = .{
        .fg = .{ .rgb = .{ 150, 150, 150 } },
        .bg = .{ .rgb = .{ 15, 15, 15 } },
    };
    win.fill(.{ .style = .{ .bg = .{ .rgb = .{ 15, 15, 15 } } } });

    var buf: [128]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, " uptime {d}h{d:0>2}m  {s}", .{
        uptime_h,
        uptime_m,
        if (server.cfg.admin_ssh.read_only) "read-only" else "read-write",
    }) catch return;

    _ = win.print(&.{.{ .text = text, .style = style }}, .{ .col_offset = 0, .wrap = .none });
}

// ---------------------------------------------------------------------------
// Lease tab
// ---------------------------------------------------------------------------

fn renderLeaseTab(
    server: *AdminServer,
    _state: *TuiState,
    table_ctx: *vaxis.widgets.Table.TableContext,
    win: vaxis.Window,
    allocator: std.mem.Allocator,
) !void {
    _ = _state;
    // Use an arena for per-frame string allocations.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const now = std.time.timestamp();

    const leases = server.store.listLeases() catch return;
    defer server.store.allocator.free(leases);

    var rows = std.ArrayList(LeaseRow){};
    for (leases) |lease| {
        const pool_label = findPoolLabel(server.cfg, lease.ip) orelse "?";
        const type_str: []const u8 = if (lease.reserved) "reserved" else "dynamic";

        const expires_str = blk: {
            if (lease.reserved) break :blk try a.dupe(u8, "forever");
            const diff = lease.expires - now;
            if (diff <= 0) break :blk try a.dupe(u8, "expired");
            const h = @divTrunc(diff, 3600);
            const m = @divTrunc(@rem(diff, 3600), 60);
            break :blk try std.fmt.allocPrint(a, "{d}h{d:0>2}m", .{ h, m });
        };

        const hostname_str = lease.hostname orelse "";

        try rows.append(a, .{
            .ip = try a.dupe(u8, lease.ip),
            .mac = try a.dupe(u8, lease.mac),
            .hostname = try a.dupe(u8, hostname_str),
            .type = type_str,
            .expires = expires_str,
            .pool = try a.dupe(u8, pool_label),
        });
    }

    // Clamp table cursor to the actual number of rows.
    const n_rows: u16 = if (rows.items.len > 0xFFFF) 0xFFFF else @intCast(rows.items.len);
    if (n_rows > 0 and table_ctx.row >= n_rows) {
        table_ctx.row = n_rows - 1;
    }

    table_ctx.active = true;
    try vaxis.widgets.Table.drawTable(a, win, rows.items, table_ctx);
}

fn findPoolLabel(cfg: *const config_mod.Config, ip_str: []const u8) ?[]const u8 {
    const ip_bytes = config_mod.parseIpv4(ip_str) catch return null;
    const ip_int = std.mem.readInt(u32, &ip_bytes, .big);

    for (cfg.pools) |*pool| {
        const subnet_bytes = config_mod.parseIpv4(pool.subnet) catch continue;
        const subnet_int = std.mem.readInt(u32, &subnet_bytes, .big);
        if ((ip_int & pool.subnet_mask) == subnet_int) {
            return pool.subnet; // static string from config — valid lifetime
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// Stats tab
// ---------------------------------------------------------------------------

fn renderStatsTab(
    server: *AdminServer,
    win: vaxis.Window,
    allocator: std.mem.Allocator,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const now = std.time.timestamp();
    const leases = server.store.listLeases() catch return;
    defer server.store.allocator.free(leases);

    const hdr_style: vaxis.Style = .{ .bold = true, .fg = .{ .rgb = .{ 255, 200, 80 } } };
    const val_style: vaxis.Style = .{ .fg = .{ .rgb = .{ 200, 200, 200 } } };
    const bar_full: vaxis.Style = .{ .fg = .{ .rgb = .{ 64, 192, 64 } } };
    const bar_warn: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 180, 0 } } };
    const bar_crit: vaxis.Style = .{ .fg = .{ .rgb = .{ 255, 60, 60 } } };

    var row: u16 = 0;

    // ---- Pool stats ----
    _ = win.print(&.{.{ .text = "  Pool Utilization", .style = hdr_style }}, .{ .col_offset = 0, .row_offset = row, .wrap = .none });
    row += 1;

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

        // Pool label line
        const pool_label = try std.fmt.allocPrint(a, "  {s}/{d}", .{ pool.subnet, pool.prefix_len });
        _ = win.print(&.{.{ .text = pool_label, .style = val_style }}, .{ .col_offset = 0, .row_offset = row, .wrap = .none });
        row += 1;

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
        _ = win.print(&.{.{ .text = bar_str, .style = bar_style }}, .{ .col_offset = 0, .row_offset = row, .wrap = .none });
        row += 2;

        if (row >= win.height -| 4) break;
    }

    // ---- DHCP counters ----
    _ = win.print(&.{.{ .text = "  DHCP Counters", .style = hdr_style }}, .{ .col_offset = 0, .row_offset = row, .wrap = .none });
    row += 1;

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
        if (row >= win.height) break;
        const line = try std.fmt.allocPrint(a, "    {s}  {d}", .{ cl.label, cl.val });
        _ = win.print(&.{.{ .text = line, .style = val_style }}, .{ .col_offset = 0, .row_offset = row, .wrap = .none });
        row += 1;
    }
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
