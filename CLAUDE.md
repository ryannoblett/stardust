# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Stardust is a DHCP server (RFC 2131/2132) written in Zig. It handles IP lease management, DNS update integration, and configuration via YAML.

## Commands

```bash
zig build                                    # Release build
zig build -Doptimize=Debug                  # Debug build
zig build run                               # Build and run
zig build dev                               # Debug executable (stardust-dev)
zig build test                              # Run all tests
zig build test -Dtest_filter="test_name"   # Run a single test
zig build check                             # Style check
zig fmt .                                   # Format all Zig files
```

## Architecture

```
main.zig → config.zig + state.zig + dns.zig + dhcp.zig + admin_ssh.zig + sync.zig
```

- **main.zig** — Entry point. Initializes `GeneralPurposeAllocator`, loads config, creates `StateStore`, `DNSUpdater`, `SyncManager`, `DHCPServer`, `AdminServer`, and `MetricsServer`, then runs the server loop. Also contains `logFn` (custom log function with binary data guard and single-syscall stderr writes).
- **src/config.zig** — Loads `config.yaml` via `zig-yaml`. Uses a two-struct pattern: `RawConfig` (YAML-parsed strings) → `Config` (typed, with parsed IPs/masks). Key structs: `Config`, `PoolConfig`, `Reservation`, `MacClass`, `SyncConfig`, `AdminSSHConfig`, `MetricsConfig`, `StaticRoute`. Has `parseIpv4()`, `parseMask()`, and `computePoolHash()`.
- **src/dhcp.zig** — Core server. Binds UDP port 67, parses DHCP packets into `DHCPHeader` (extern struct matching RFC wire format), handles DISCOVER/OFFER/REQUEST/ACK/RELEASE/DECLINE/INFORM flows. DHCP option override system: `collectOverrides` merges pool → MAC class → reservation options; `matchMacClass` does prefix matching with specificity ordering. Response routing follows RFC 2131 §4.1.
- **src/state.zig** — Lease store (MAC, IP, hostname, expiry, client ID, reserved flag, local flag). Thread-safe via `RwLock`. Persists leases to `leases.json` atomically (temp file + rename).
- **src/dns.zig** — RFC 2136 dynamic DNS updates with TSIG authentication (HMAC-SHA256 / HMAC-MD5). Sends A and PTR record updates on lease grant/release. Parses BIND-format key files.
- **src/probe.zig** — Pre-offer conflict detection. ARP probe (RFC 5227 style, SPA=0.0.0.0) for local networks; ICMP echo for relayed networks.
- **src/sync.zig** — Active-active lease synchronisation over UDP with AES-256-GCM encryption. HELLO handshake with pool hash verification. Last-write-wins conflict resolution. Periodic lease hash anti-entropy.
- **src/admin_ssh.zig** — SSH admin TUI server (via libssh + libvaxis). Four tabs (Leases, Stats, Pools, Settings). Pool form with scrollable fields, sub-modals for static routes and DHCP options. Reservation form with inline DHCP option editing and option lookup modal. Settings tab with editable fields (log level, metrics, allocation mode) and deferred save. All modals have [X] close buttons, borders, and mouse support.
- **src/config_write.zig** — YAML serializer for Config. Atomic write (temp file + rename). Helpers for pool/reservation mutations used by TUI and sync.

## Dependencies

- **zig-yaml** v0.2.0 — YAML parser (declared in `build.zig.zon`)
- **libvaxis** — Terminal UI library for the SSH admin TUI (pure Zig, no C deps)
- **libssh** — SSH server library (C, statically linked). Cross-compilation uses Nix bundles via `-Dlibssh_dir`

## Releases

Releases are triggered by pushing a `v*` tag (e.g. `v0.3-alpha1`). The release workflow requires a matching entry in `CHANGELOG.md` — the build **will fail** if one is missing.

Before tagging a release:

1. Add a `## v{version} (YYYY-MM-DD)` section to `CHANGELOG.md` with a feature summary
2. Commit the changelog update
3. Tag the commit and push both the branch and the tag

The release workflow extracts the changelog section and uses it as the GitHub release body. DHCP option keys in YAML examples must be unquoted integers (e.g. `66:` not `"66":`) — zig-yaml does not support quoted map keys.

## Naming Conventions

- Types (structs, enums, error sets): `PascalCase`
- Functions and variables: `camelCase`
- Constants: `snake_case` or `ALL_CAPS` for truly global constants
- Documentation comments: `///` for public APIs; `//` for implementation notes
