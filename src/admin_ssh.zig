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
    log.debug("pty resize callback: {d}x{d}", .{ width, height });
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

// Lease table sort state.  Column index matches LeaseRow field order (0-based).
const SortCol = enum(u8) { none = 255, ip = 0, mac = 1, hostname = 2, type = 3, expires = 4, pool = 5 };
const SortDir = enum { asc, desc };

const TuiState = struct {
    tab: Tab = .leases,
    lease_row: u16 = 0,
    lease_start: u16 = 0,
    sort_col: SortCol = .expires,
    sort_dir: SortDir = .desc,
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

    // ssh_event_dopoll is the only libssh mechanism that reliably dispatches
    // channel request callbacks (including SSH_CHANNEL_REQUEST_WINDOW_CHANGE).
    // ssh_channel_read_timeout does NOT fire them.
    const ssh_ev = c.ssh_event_new() orelse return error.SshEventFailed;
    defer c.ssh_event_free(ssh_ev);
    if (c.ssh_event_add_session(ssh_ev, session) != 0) return error.SshEventFailed;

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
    while (running) {
        // Poll for all SSH events with a 100 ms timeout.
        // ssh_event_dopoll dispatches ALL channel callbacks (including
        // SSH_CHANNEL_REQUEST_WINDOW_CHANGE → ptyWindowChangeCb) which
        // ssh_channel_read_timeout does NOT do.
        // Returns SSH_OK (0) or SSH_ERROR (-1).
        const poll_rc = c.ssh_event_dopoll(ssh_ev, 100);
        if (poll_rc < 0 and c.ssh_channel_is_open(channel) == 0) {
            log.debug("{s}: session error during poll, closing TUI", .{peer});
            break;
        }

        if (c.ssh_channel_is_eof(channel) != 0) {
            log.debug("{s}: channel EOF, closing TUI", .{peer});
            break;
        }

        // Read any channel data buffered by dopoll (non-blocking — returns
        // immediately with 0 if nothing available).
        const n_raw = c.ssh_channel_read_nonblocking(
            channel,
            &read_buf[read_start],
            @intCast(read_buf.len - read_start),
            0,
        );
        if (n_raw < 0) {
            log.debug("{s}: channel read error, closing TUI", .{peer});
            break;
        }

        // Apply any pending resize.  Use cur_cols/cur_rows as fallback for
        // whichever dimension the callback didn't update (some clients send
        // WINDOW_CHANGE with only one non-zero dimension).
        {
            const pr = winctx.pending_rows.swap(0, .acq_rel);
            const pc = winctx.pending_cols.swap(0, .acq_rel);
            const new_cols = if (pc > 0) pc else cur_cols;
            const new_rows = if (pr > 0) pr else cur_rows;
            if (new_cols != cur_cols or new_rows != cur_rows) {
                log.debug("{s}: applying resize {d}x{d} → {d}x{d}", .{
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
                // vx.resize() sends cursor-home + erase-below + flush.
                // Also send an explicit full-screen erase so content left
                // outside the new viewport (e.g. after a narrowing resize) is
                // guaranteed gone before vaxis redraws.
                try io.writeAll("\x1b[2J");
                try io.flush();
            }
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
                            .stats => {},
                        }
                        if (key.matches('1', .{})) state.tab = .leases;
                        if (key.matches('2', .{})) state.tab = .stats;
                    }
                },
                .mouse => |mouse| {
                    switch (mouse.button) {
                        .left => if (mouse.type == .press) {
                            const term_row: u16 = if (mouse.row >= 0) @intCast(mouse.row) else 0;
                            const term_col: u16 = if (mouse.col >= 0) @intCast(mouse.col) else 0;
                            if (term_row == 0) {
                                // Header bar: tab switching.
                                // Layout: " Stardust "(10) + " [1] Leases "(12) + " [2] Stats "(11)
                                if (term_col >= 10 and term_col < 22) {
                                    state.tab = .leases;
                                } else if (term_col >= 22 and term_col < 33) {
                                    state.tab = .stats;
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
                        .wheel_up => if (state.tab == .leases) {
                            table_ctx.row -|= 1;
                        },
                        .wheel_down => if (state.tab == .leases) {
                            table_ctx.row +|= 1;
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
    renderHeader(state, win.child(.{ .y_off = 0, .height = 1, .width = w }));

    // Body (rows 1 .. h-2)
    const body = win.child(.{
        .y_off = 1,
        .height = h -| 2,
        .width = w,
    });

    switch (state.tab) {
        .leases => try renderLeaseTab(server, state, table_ctx, body, fa),
        .stats => try renderStatsTab(server, body, fa),
    }

    // Status bar (last row)
    try renderStatus(server, state, win.child(.{ .y_off = h -| 1, .height = 1, .width = w }), fa);
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

    const hint = "  j/k:move  /:filter  I/M/H/T/E/P:sort  y:yank  q:quit";
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
    const uptime_s = now - server.start_time;
    const uptime_h = @divTrunc(uptime_s, 3600);
    const uptime_m = @divTrunc(@rem(uptime_s, 3600), 60);

    const filter_note: []const u8 = if (state.tab == .leases and state.filter_len > 0)
        try std.fmt.allocPrint(fa, "  filter: {s}  (Esc clears)", .{state.filter_buf[0..state.filter_len]})
    else
        "";
    const text = try std.fmt.allocPrint(fa, " uptime {d}h{d:0>2}m  {s}{s}", .{
        uptime_h,
        uptime_m,
        if (server.cfg.admin_ssh.read_only) "read-only" else "read-write",
        filter_note,
    });
    _ = win.print(&.{.{ .text = text, .style = style }}, .{ .col_offset = 0, .wrap = .none });
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
const LeaseColSpec = struct { ideal: u16, min: u16, left_trunc: bool };
const LEASE_COL_SPECS = [6]LeaseColSpec{
    .{ .ideal = 16, .min = 7, .left_trunc = true }, // ip      ("255.255.255.255" = 15 + 1 padding)
    .{ .ideal = 18, .min = 9, .left_trunc = true }, // mac     ("aa:bb:cc:dd:ee:ff" = 17 + 1 padding)
    .{ .ideal = 60, .min = 6, .left_trunc = false }, // hostname (room for FQDNs)
    .{ .ideal = 8, .min = 4, .left_trunc = false }, // type    ("reserved" = 8)
    .{ .ideal = 9, .min = 7, .left_trunc = false }, // expires ("1234h56m" ~ 9)
    .{ .ideal = 14, .min = 7, .left_trunc = false }, // pool    ("192.168.0.0/24" = 14)
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
                const text = try truncateCell(fa, header_names[ci], widths[ci], false);
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
                const lt = LEASE_COL_SPECS[ci].left_trunc;
                const text = try truncateCell(fa, fields[ci], widths[ci], lt);
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
        const pool_label = findPoolLabel(server.cfg, lease.ip) orelse "?";
        const type_str: []const u8 = if (lease.reserved) "reserved" else "dynamic";
        const hostname_str = lease.hostname orelse "";

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
                containsIgnoreCase(pool_label, filter);
            if (!match) continue;
        }

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
    if (n_rows > 0 and table_ctx.row >= n_rows) table_ctx.row = n_rows - 1;
    if (n_rows == 0) table_ctx.row = 0;

    // Update selected-row state (used by yank mode to copy fields to clipboard).
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
            return .{ .mac = "aa:bb:cc:dd:ee:ff", .ip = ip, .hostname = null, .expires = exp, .reserved = res };
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
