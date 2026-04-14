# Changelog

## v0.4-alpha1 (2026-04-13)

### DHCP Relay Agent (stardust-relay)

New lightweight relay binary (`stardust-relay`, 12MB vs 42MB server) for forwarding DHCP between subnets:

- **Auto-detect downstream interfaces**: excludes the upstream route interface automatically
- **Per-interface sockets**: SO_BINDTODEVICE with correct giaddr per downstream interface
- **Option 82 (Relay Agent Information)**: configurable policy — replace, append, drop, or keep
- **SIGHUP config reload**: upstream servers, option82, max_hops, log level
- **Shared packet parsing**: new `dhcp_common.zig` module shared between server and relay (no libssh/libvaxis dependencies)
- **YAML config**: `relay.yaml` with upstream servers, interface list, option82 settings

### Option 82 Server Support (RFC 3046)

- **Echo Option 82**: OFFER, ACK, NAK, and INFORM responses echo relay agent information per RFC 3046 §2.2
- **Lease storage**: `relay_agent` (hex-encoded Option 82) and `relay_ip` (giaddr) stored on leases and synced to peers

### TUI Improvements

- **Relay columns**: new relay IP and relay port columns in lease table (right-aligned, shrink-first priority)
- **Compact type column**: dynamic→dyn, reserved→resv, conflict→block
- **Improved expiry format**: `13d+19h` for >1 day, `11h+04m` for <1 day, `none` for reserved
- **Hostname sizing**: capped at 24 chars initially, fills remaining terminal width

### Bug Fixes

- Memory leak: relay_agent/relay_ip not freed in remove/forceRemove lease paths
- Expiry format: i64 remainder cast to u64 to avoid sign display in format string

---

## v0.3-alpha3 (2026-04-12)

### TUI Improvements

- **Human-friendly uptime**: status bar scales from minutes through years (e.g. `2w3d5h02m`, `1y2m15d0h30m`) instead of raw hours
- **Help screen reorganized**: better grouping, consistent key ordering, arrow key symbols, compact layout
- **Pool tab key hints**: consistent ordering (`n:new e:edit d:delete`)

### Prometheus Metrics

- **`stardust_defense_events_total`**: new counter family for defense/security events (probe_conflict, decline_ip_quarantined, decline_mac_blocked, decline_global_limited, decline_refused)
- **`stardust_ssh_events_total`**: new counter family for SSH server events (attempts, logins, failures)
- Updated metric endpoint documentation comments

### Documentation

- README: updated screenshots, improved project description, fixed outdated examples, added missing feature docs

---

## v0.3-alpha2 (2026-04-06)

### Config Sync

Per-pool configuration synchronization between peers:

- **Reservation sync**: `RESERVATION_UPDATE` / `RESERVATION_DELETE` messages with per-item `config_modified` timestamps and last-write-wins conflict resolution
- **Pool config sync**: `POOL_CONFIG_UPDATE` with full pool YAML propagation and per-pool `config_version` timestamps
- **Anti-entropy**: HELLO exchanges `config_version`; higher version automatically pushes to peers with stale config on reconnect
- **Two-gate capability**: global `config_writable` (top-level) + `sync.config_sync` (sync-specific) — both must be true for a peer to accept config pushes
- **TUI integration**: reservation save/delete and pool save trigger immediate sync notifications to capable peers
- **Settings TUI**: layout-driven click handler (fixes AUDIT.md fragility concern), Config Writable shown read-only, Config Sync toggle editable

### Security Profiles

- **AppArmor** profile for Debian/Ubuntu/SUSE: confines binary to `/etc/stardust` + `/var/lib/stardust`, explicit rules for atomic write patterns (`.tmp`, `.writetest`)
- **SELinux** policy for RHEL/Fedora: 4 types (`stardust_exec_t`, `stardust_conf_t`, `stardust_key_t`, `stardust_state_t`), file contexts for all default paths
- Both profiles included in .deb, .rpm, and .tar.gz packages

### TUI Improvements

- **Natural sort** for hostname column: `client-2` sorts before `client-10` (overflow-safe, no u64 arithmetic)
- **Sync status** on stats tab: peer counts, config capability, 4 config sync counters (CONFIG PUSH/RECV, RESV PUSH/RECV)
- **Config Writable** displayed as read-only in settings (must be set via config.yaml for safety)

### Infrastructure

- **MIT license** with LGPL-2.1 libssh notice
- **Auto-detect local IP** for sync voting when listen_address is 0.0.0.0 (falls back to random 255.255.x.x to lose all ties)
- **Suppress zig-yaml debug logs** on config reload (comptime scope filter)
- **Config writability startup check**: fatal error if `config_writable=true` but config path isn't writable
- **Subnet mask consistency**: all 5 remaining single-sided comparisons fixed to mask both sides

### Bug Fixes (rounds 6-7, 7 total)

- `naturalLessThan` used `b[ai]` instead of `b[bi]` — hostname sort was broken
- `naturalLessThan` u64 overflow on 20+ digit runs — replaced with run-extraction
- `parsePoolFromYaml` leaked zig-yaml parse_errors on load failure
- `processPoolConfigUpdate` logged parse failure as `err` instead of `warn`
- Prometheus output missing `forcerenew` counter
- `saveUnlocked` temp file not cleaned up on rename failure
- 9 previously-silent behaviors now log warnings or info messages

### Test Coverage

~440 tests across 10 modules. New tests for malformed JSON/YAML handling, MAC class time_offset override, /30 subnet capacity, natural sort edge cases.

---

## v0.3-alpha1 (2026-04-03)

### Per-Pool Sync Protocol (v2)

Major rewrite of the lease synchronization protocol:

- **Per-pool hashes**: Each pool is independently hashed and compared across peers, replacing the single global hash
- **Majority-voting conflict resolution**: When pool configs differ, the majority hash wins; ties broken by lowest IP. Losing pools are atomically disabled (stop serving DHCP)
- **Decoupled authentication**: Peers authenticate on group name + shared secret only; pool hashes determine which pools sync, not whether peers talk
- **Startup sync wait**: Waits up to 5 seconds for peer responses before serving, preventing split-brain on startup
- **HELLO v2 wire format**: Carries per-pool subnet/prefix/hash entries; v1 peers rejected with version_mismatch NAK
- **TUI indicator**: Disabled pools show "CONFIG MISMATCH, DISABLED" in bold red on the Pools tab

### Per-Pool Structured MAC Classes

MAC classes moved from global config to per-pool, with expanded structured field overrides:

- **First-class field overrides**: router, domain_name, domain_search, dns_servers, ntp_servers, log_servers, wins_servers, time_offset, tftp_servers, boot_filename, http_boot_url, static_routes
- **Priority**: pool defaults → MAC class (specificity ordered) → reservation
- **TUI editor**: Scrollable sub-modal with inline [+] Add entries for multi-value fields, 3-level modal stack (pool → MAC class → server/route/option editor)
- **`collectOverrides` returns `OverrideResult`**: Typed first-class fields with proper encoding (binary i32 for time_offset, DNS wire format for domain_search, etc.)
- **Duplicate option prevention**: `isFirstClassOverrideActive` filter prevents MAC class dhcp_options from conflicting with first-class field overrides

### Server List Rework

Converted DNS, NTP, Log, WINS, and TFTP server fields to inline [+] Add entries:

- **DNS Servers**: max 8, order matters, +/- reorder keys, auto-populates DNS Update Server
- **NTP Servers**: max 4, randomized per-client (xid-seeded Fisher-Yates shuffle)
- **Log Servers**: max 4, randomized per-client
- **WINS Servers**: max 2, randomized per-client
- **TFTP Servers**: max 4, order matters (merged from tftp_server_name + cisco_tftp_servers)
- **Domain name resolution**: All server fields accept domain names; resolved to IPv4 at DHCP response time via getaddrinfo with 32-entry LRU cache (60s TTL)

### DHCPFORCERENEW (RFC 3203 + RFC 6704)

- **FORCERENEW**: Sent to clients when pool config changes, reservations are modified, or leases are force-released
- **Nonce authentication (RFC 6704)**: DHCPACK includes option 145 (16-byte crypto-random nonce); FORCERENEW includes option 90 (HMAC-MD5 authentication)
- **Graceful fallback**: Pre-existing leases without nonces receive unauthenticated FORCERENEW

### DHCP Leasequery (RFC 4388 + RFC 6148)

- **Query types**: by IP address, MAC address, client identifier, or relay agent information
- **Response types**: DHCPLEASEACTIVE (with lease time, CLTT, subnet mask, router), DHCPLEASEUNASSIGNED, DHCPLEASEUNKNOWN

### Pool Form Rework

- **Unified layout system**: `pool_layout` array drives rendering, scroll, click handling, and navigation in visual order — sections and inline entries interleave naturally
- **Comprehensive validation**: All fields validated on save with per-character input filtering
- **Config validation on load**: `validatePoolFields` mirrors TUI validation for config.yaml

### Backend Counters

New stats tab section: SSH Attempts/Logins/Failures, Sync Full/Lease events, FORCERENEW, LEASEQUERY

### Pool Hash Coverage

`computePoolHash` now covers ALL pool fields: server lists, domain settings, DNS update config, DHCP options, per-reservation options, MAC classes with all structured fields

### Bug Fixes (30 total across 5 audit rounds)

Critical fixes:
- Use-after-free in DHCP RELEASE handling
- Buffer overflow in leasequery response builder
- DNS resolve cache hash collision (wrong IP returned)
- `addLeaseUnlocked` data loss on OOM (old lease freed before new allocation)
- `signTsig` buffer overflow with long key names
- String literal free in 7 array field parsing paths
- `last_modified` not restored from persisted JSON (broke sync conflict resolution after restart)

See AUDIT.md for the complete list of all 30 fixes with severity ratings.

### Other

- Migrated to driftlevel GitHub organization
- /31 subnet capacity fixed (RFC 3021)
- DNS label length validated (≤63 per RFC 1035)
- Router at subnet/broadcast address rejected
- ~400 unit tests across all modules

---

## v0.2-alpha2 (2026-04-01)

### New DHCP Options

- **Option 26 — Interface MTU**: first-class `mtu` pool config field (68-65535)
- **Option 28 — Broadcast Address**: auto-derived from subnet, no config needed
- **Option 44 — WINS/NetBIOS Name Servers**: first-class `wins_servers` pool config field
- **Option 150 — Cisco TFTP**: first-class `cisco_tftp_servers` pool config field

All four options respect the override system (pool → MAC class → reservation).

### TUI Improvements

- **Inline editing for pool routes, DHCP options, and domain search**: replaced "(Enter to edit)" sub-list modals with inline [+] Add buttons and editable rows directly in the pool form
- **Static route edit modal**: two-field modal (Network / Gateway) with CIDR and subnet validation
- **Domain search edit modal**: single-field modal with domain name validation
- **DHCP option edit modal**: two-field modal (Option # / Value) with lookup
- **Comprehensive pool form validation**: subnet (CIDR), router/start/end (valid IPs in subnet, start <= end), domain name (auto-lowercase, valid chars), DNS servers (valid IPs), lease time (max 2 weeks), MTU (68-65535), HTTP Boot URL (scheme + domain + path), all IP lists validated
- **Reservation form validation**: IP (valid IPv4), MAC (auto-normalize dashes to colons, lowercase, xx:xx:xx:xx:xx:xx format), hostname (auto-lowercase, alphanumeric + dashes)
- **Settings tab**: reordered (Metrics before Admin SSH), fixed click handler, sequential navigation, HTTP port (1-65535) and bind (valid IP) validation
- **Double-click [+] Add buttons** opens add modals in both pool and reservation forms
- **Config parse errors**: YAML syntax errors now show exact line, column, and underline

### Bug Fixes

- **Pool detail view crash**: field indices and buffer size not updated after adding new DHCP option fields
- **Pool form scroll clamp**: rewrote scroll as row-based offset instead of field-index approximation
- **Pool diff missed routes/options**: computePoolDiff now detects changes to static routes, DHCP options, and domain search entries
- **Settings tab broken input**: click handler had wrong line positions after Metrics/SSH section swap; edit indices didn't match visual order
- **applyFormToPool missing fields**: mtu, wins_servers, cisco_tftp_servers silently lost when editing existing pools
- **splitCommaDupe leak**: partial string allocations leaked on error
- **parseSyncConfig peers uninitialized**: errdefer freed garbage pointers on partial allocation failure
- **parseMacClasses top-level errdefer**: previously-built MacClass entries leaked when a later entry failed
- **Test discovery**: added comptime import block in main.zig; fixed 26 compilation errors and 6 test failures in previously-undiscovered tests across admin_ssh, metrics, dns, sync modules

### Other

- Migrated repository to driftlevel GitHub organization
- Updated all org references in README, Dockerfile, git remotes

---

## v0.2-alpha1 (2026-04-01)

### SSH Admin TUI

Full-featured interactive terminal interface accessible over SSH (`ssh -p 2267 admin@dhcp-server`).

- **Leases tab** -- live lease table with column sorting (click headers or keyboard shortcuts), text filter, row selection, yank-to-clipboard (OSC 52), and force-release
- **Stats tab** -- per-pool capacity bars, DHCP message counters (DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE, DECLINE, INFORM), defense counters (decline rate-limit, quarantine), and uptime
- **Pools tab** -- view, edit, add, and remove pool configurations; scrollable form with all pool fields; sub-modals for static routes and DHCP options; diff/confirm screen showing which fields changed and whether sync peers will be affected
- **Settings tab** -- editable global settings (log level, random allocation, metrics collect/enable/port/bind) with deferred save and dirty-field indicators
- **Reservation management** -- add/edit/delete reservations with inline DHCP option editing, option code lookup modal, and per-reservation option overrides
- **Help screen** -- press `?` for all keyboard shortcuts; adaptive layout, scrollable
- **Full mouse support** -- click tabs, sort columns, select rows, click form fields, scroll, close modals via [X] button
- **Keyboard navigation** -- j/k, arrows, Tab/Shift-Tab, Home/End, Ctrl+R to reload config
- **Read-only mode** -- `read_only: true` blocks all writes and hides sensitive key paths
- **Config write-back** -- changes saved atomically (temp file + rename) and reloaded via SIGHUP
- **Graceful shutdown** -- Ctrl+C / `q` cleanly disconnects SSH sessions

### DHCP Option Overrides

Layered override system for DHCP options with three priority levels:

1. **Pool defaults** -- `dhcp_options` map on the pool configuration
2. **MAC class rules** -- match clients by MAC prefix (vendor OUI); applied in specificity order (shortest prefix first, most specific wins)
3. **Per-reservation overrides** -- `dhcp_options` map on individual reservations (highest priority)

### UEFI HTTP Boot

When a client sends option 60 = `"HTTPClient"`, the server echoes option 60 and provides the configured HTTP URL as option 67. Non-HTTP clients receive standard TFTP options (66/67).

### Prometheus Metrics

In-process counters for all DHCP message types, pool utilization, and defense events. Optionally exposed via HTTP (`GET /metrics`) for Prometheus scraping.

### CI / Build

- Nix-based cross-compilation for libssh (replaces apt packages)
- Static musl binaries for x86_64, aarch64, and riscv64
- Nix flake with libssh bundle outputs for all targets

### Bug Fixes

- **Use-after-free in DHCP RELEASE handling** -- `handleRelease` used lease string pointers after `removeLease` freed them (manifested as `[59B blob data]` in journald)
- **Use-after-free on config reload** -- `store.dir` dangled after old config was freed; now updated after replacement
- **Thread-unsafe logging** -- multiple threads writing to stderr caused journald blob detection; fixed with single-syscall writes
- **Sync peer authentication** -- unauthenticated peers could send lease updates; now rejected before processing
- **Memory leaks** -- fixed incomplete errdefer chains in `parseMacClasses`, `parseReservations`, `buildPoolFromFormInner`, `upsertReservation`, and `dupeOptionsMap`
- **Config parse errors** -- YAML syntax errors now show exact line, column, and underline instead of bare `ParseFailure`
- **TUI resize handling** -- drain SSH message queue for `WINDOW_CHANGE` events; handle `SSH_AGAIN` return codes

### Packaging

- systemd: added `ConfigurationDirectory=stardust` for `DynamicUser=yes`
- Documented `ConfigurationDirectoryMode=0775` and group ownership for TUI write-back
- OpenRC init script for Alpine/Gentoo
- Docker: multi-arch scratch images (x86_64, aarch64, riscv64)

---

## v0.1-alpha1 (2026-03-28)

Initial feature-complete release of Stardust DHCP server.

### Core DHCP

- Full DISCOVER / OFFER / REQUEST / ACK / NAK flow (RFC 2131)
- DHCPRELEASE, DHCPDECLINE, and DHCPINFORM handling
- Relay agent support -- routes responses via `giaddr` (RFC 2131 S4.1)
- Multiple pools -- serve several subnets from one daemon; relay agent `giaddr` or `ciaddr` selects the correct pool
- Configurable lease range (`pool_start` / `pool_end`); defaults to full usable subnet
- Lease state persisted to JSON and restored at startup
- SIGHUP config reload without dropping the socket
- Client identifier (option 61) support for lease tracking across MAC changes

### DHCP Options

Subnet mask (1), time offset (2), router (3), time servers (4), DNS servers (6), log servers (7), hostname (12), domain name (15), static routes (33), NTP servers (42), lease time (51), TFTP server (66), boot filename (67), domain search list (119, RFC 3397), classless static routes (121, RFC 3442), and arbitrary custom options via `dhcp_options` map.

### Static Reservations

Pin MAC address or client identifier (option 61) to a fixed IP and optional hostname. Reservations survive lease expiry and DHCPRELEASE.

### Pre-Offer Conflict Detection

- ARP probe (RFC 5227 style) for local clients; ICMP echo for relayed clients
- Conflicting addresses quarantined for `max(lease_time / 10, 300)` seconds

### DHCPDECLINE Protection

- Per-MAC cooldown after 3 declines within 60 seconds
- Global rate limit: 20 declines per 5-minute window

### Dynamic DNS Updates (RFC 2136)

- A and PTR record updates on lease grant/release
- TSIG authentication (HMAC-SHA256 / HMAC-MD5) with BIND key files
- Anonymous updates when `key_file` is empty
- Reverse zone auto-derived from subnet prefix length

### Lease Synchronisation (Active-Active)

- UDP lease sync with AES-256-GCM encryption (HKDF-SHA-256 key derivation)
- HELLO handshake with SHA-256 pool hash verification
- Last-write-wins conflict resolution; periodic lease-hash anti-entropy
- Multicast or unicast peer discovery
- DNS failover: lowest-IP server takes over when primary is offline

### Packaging

- systemd unit with `DynamicUser=yes`
- Multi-arch container images (x86_64, aarch64, riscv64) on GHCR
- CI and tag-triggered release builds (.deb, .rpm, .tar.gz)

### Bug Fixes (since v0.1-alpha)

- TSIG MAC: added CLASS and TTL to `tsig_vars` per RFC 2845 S4.3.2
