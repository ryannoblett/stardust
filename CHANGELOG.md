# Changelog

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
