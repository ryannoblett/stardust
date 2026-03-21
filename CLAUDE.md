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
main.zig → config.zig + state.zig + dns.zig + dhcp.zig
```

- **main.zig** — Entry point. Initializes `GeneralPurposeAllocator`, loads config, creates `StateStore`, `DNSUpdater`, and `DHCPServer`, then runs the server loop.
- **src/config.zig** — Loads `config.yaml` via `zig-yaml`. Uses a two-struct pattern: `RawConfig` (YAML-parsed strings) → `Config` (typed, with parsed IPs/masks). Has `parseIpv4()` and `parseMask()` helpers, tested in-file.
- **src/dhcp.zig** — Core server. Binds UDP port 67, parses DHCP packets into `DHCPHeader` (extern struct matching RFC wire format), handles DISCOVER/OFFER/REQUEST/ACK/RELEASE flows. Broadcasts responses to 255.255.255.255:68.
- **src/state.zig** — Lease store (MAC, IP, hostname, expiry, client ID). **Currently stub** — in-memory only, disk persistence not yet implemented.
- **src/dns.zig** — DNS update integration. **Currently stub** — configuration parsing done, BIND TSIG update logic not yet implemented.

## Dependencies

Single external dependency: `zig-yaml` v0.2.0 (declared in `build.zig.zon`, fetched from GitHub). The YAML module is imported in `build.zig` and passed to the main module — if adding new modules that need YAML, follow the same pattern in `build.zig`.

## Naming Conventions

- Types (structs, enums, error sets): `PascalCase`
- Functions and variables: `camelCase`
- Constants: `snake_case` or `ALL_CAPS` for truly global constants
- Documentation comments: `///` for public APIs; `//` for implementation notes
