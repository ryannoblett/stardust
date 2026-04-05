# Security & Code Audit Log

This document tracks all bugs found and fixed during code audits, plus known
remaining findings that are low-severity or by-design.

## Audit Rounds

- **Round 1** (2026-04-01): Initial memory safety scan
- **Round 2** (2026-04-01): Post-fix verification + test coverage gaps
- **Round 3** (2026-04-01): Full codebase audit after major TUI refactor
- **Round 4** (2026-04-02): Post-feature audit (sync protocol, MAC classes, FORCERENEW)
- **Round 5** (2026-04-02): Exhaustive line-by-line final sweep
- **Round 6** (2026-04-05): Config sync feature audit + natural sort bug
- **Round 7** (2026-04-05): Exhaustive re-verification after config sync

---

## All Fixed Bugs (by round)

### Round 1

| # | File | Severity | Description |
|---|------|----------|-------------|
| 1 | config.zig | Critical | `parseMacClasses` incomplete errdefer — if `.match` alloc fails, `.name` and opts map leak |
| 2 | admin_ssh.zig | Critical | `saveReservation` didn't pass form DHCP options to `upsertReservation` — options silently discarded |
| 3 | config_write.zig | Critical | `removeReservation` didn't free `dhcp_options` on the removed reservation |
| 4 | config_write.zig | Critical | `upsertReservation` didn't accept or store `dhcp_options` parameter |

### Round 2

| # | File | Severity | Description |
|---|------|----------|-------------|
| 5 | config.zig | Critical | `parseReservations` `res_opts` StringHashMap leaked on error (missing errdefer) |
| 6 | config_write.zig | Medium | `dupeOptionsMap` leaked value string if `put()` failed (missing errdefer for `v`) |
| 7 | config_write.zig | Medium | `upsertReservation` leaked all `new_res` fields if `realloc` failed (no errdefer chain) |
| 8 | admin_ssh.zig | Medium | `buildPoolFromFormInner` dns_update struct fields lacked errdefer chain |

### Round 3

| # | File | Severity | Description |
|---|------|----------|-------------|
| 9 | config.zig | Critical | Array fields (7 types) initialized to `""` string literal — `deinit` tried to `free()` literal on partial alloc failure. Fixed with `allocator.alloc(u8, 0)` |
| 10 | admin_ssh.zig | Critical | `computePoolDiff` sync_fields used wrong index (MTU instead of Lease Time). Later corrected: MTU IS sync-breaking, lease time is not |
| 11 | admin_ssh.zig | Medium | `buildPoolFromFormInner` and helpers had same string-literal-free bug as #9 |
| 12 | dns.zig | Critical | `signTsig` had no bounds check before appending TSIG record — potential heap overflow with long key names. Added `BufferTooSmall` error |
| 13 | state.zig | Critical | `addLeaseUnlocked` freed old lease BEFORE new allocations — data loss on OOM. Reordered: allocate first, remove second |
| 14 | admin_ssh.zig | Medium | `applyFormToPool` missing mtu, wins_servers, cisco_tftp_servers updates |
| 15 | config.zig | Medium | `parseSyncConfig` peers array had uninitialized elements — errdefer freed garbage pointers |
| 16 | admin_ssh.zig | Medium | `splitCommaDupe` leaked partial string allocations on error |

### Round 4

| # | File | Severity | Description |
|---|------|----------|-------------|
| 17 | dhcp.zig | Critical | `buildLeaseQueryResponse` 576-byte buffer could overflow with long hostname + client_id (up to 784 bytes). Increased to 1024 with bounds checks |
| 18 | dhcp.zig | Critical | `buildLeaseQueryResponse` returned sub-slice of larger allocation — callers couldn't free correctly. Fixed with realloc to actual size |
| 19 | dhcp.zig | Critical | DNS resolve cache only checked hash, not actual hostname — wrong IP on hash collision. Added hostname comparison |
| 20 | config.zig | Medium | `parseMacClassStringList` returned comptime `&.{}` — errdefer tried to free non-allocator-owned slice |
| 21 | admin_ssh.zig | Medium | `buildMacClassesFromForm` had no errdefer — leaked on partial allocation failure |
| 22 | dhcp.zig | Medium | `forceRenewPool` and `selectPool` only masked one side of subnet comparison |

### Round 5

| # | File | Severity | Description |
|---|------|----------|-------------|
| 23 | dns.zig | Medium | `encodeDnsName` accepted labels >63 bytes — violated RFC 1035 s3.1. Added NameTooLong error |
| 24 | sync.zig | Medium | `decrypt` payload_len from untrusted input could overflow arithmetic. Added cap at 8192 |
| 25 | state.zig | Medium | `load()` didn't restore `last_modified` from persisted JSON — broke sync conflict resolution after restart |
| 26 | dhcp.zig | Medium | DNS resolve cache cold-start: uninitialized slot (name_len=0) could false-positive match on hash=0. Added name_len>0 check |
| 27 | config.zig | Medium | `validatePoolFields` didn't reject router at subnet/broadcast address |
| 28 | metrics.zig | Medium | /31 subnets reported 0 capacity (should be 2 per RFC 3021). /32 also fixed (returns 1) |
| 29 | dhcp.zig | Medium | Duplicate DHCP options when MAC class has both first-class field AND dhcp_options for same code. Added `isFirstClassOverrideActive` filter |
| 30 | sync.zig | Low | No warning when self_ip=0 (listen 0.0.0.0) causes server to win all voting ties |

### Round 6

| # | File | Severity | Description |
|---|------|----------|-------------|
| 31 | admin_ssh.zig | Critical | `naturalLessThan` used `b[ai]` instead of `b[bi]` for digit detection — hostname natural sort produced wrong results |
| 32 | config.zig | Medium | `parsePoolFromYaml` leaked zig-yaml parse_errors on load failure — `defer doc.deinit` placed after `doc.load` instead of before |
| 33 | sync.zig | Low | `processPoolConfigUpdate` logged parse failure as `err` instead of `warn` — malformed peer data is external input, not internal error |

### Round 7

| # | File | Severity | Description |
|---|------|----------|-------------|
| 34 | admin_ssh.zig | Medium | `naturalLessThan` digit accumulation could overflow u64 on 20+ digit runs — replaced with run-extraction approach that avoids arithmetic entirely |
| 35 | metrics.zig | Medium | Prometheus output missing `forcerenew` counter — added `stardust_dhcp_packets_total{type="forcerenew"}` |
| 36 | state.zig | Medium | `saveUnlocked` temp file not deleted if `rename` fails — added explicit cleanup in catch block |
| 37 | sync.zig | Low | `processPoolConfigUpdate` error log didn't clarify that in-memory update succeeded — improved message to note anti-entropy retry |

---

## Remaining Findings (not fixed — low severity or by-design)

### Performance / Design

| File | Description | Status |
|------|-------------|--------|
| state.zig | `getLeaseByIp` and `getLeaseByClientId` are O(n) linear scans | Acceptable for typical deployment sizes (<1000 leases). Secondary index would add complexity |
| state.zig | `save()` atomic rename not guaranteed cross-filesystem | Standard limitation; state_dir should be on same filesystem |
| state.zig | Duplicate MAC in leases.json overwrites earlier entry | **Logs warning** — last entry wins is acceptable |
| sync.zig | `notifyLeaseUpdate` JSON may exceed UDP MTU for leases with very long fields | **Logs warning** when >1400 bytes |
| sync.zig | processHello truncates if pool_count * 37 > payload length | **Logs warning** with advertised vs actual count |
| dhcp.zig | `collectOverrides` HashMap put errors on OOM | **Logs warning** — partial overrides better than crash |
| dhcp.zig | `handleDecline` decline_records put error on OOM | **Logs warning** with MAC address |
| dhcp.zig | LEASEQUERY realloc failure returns original larger allocation | **Logs info** — wastes memory but safe |
| config.zig | `parseIpv4` accepts leading zeros (e.g., "192.168.01.001") | Functional but could be ambiguous (octal interpretation). Not fixing to avoid breaking configs |

### Style / Documentation

| File | Description | Status |
|------|-------------|--------|
| config_write.zig | No YAML escaping for special characters in string values | Mitigated by input validation — config parser and TUI reject special chars. Documented in module header |
| dhcp.zig | Nonce hex encoding format (`{x:0>2}`) implicitly lowercase — no explicit documentation | Zig format is stable; added comment |
| admin_ssh.zig | `handleSettingsClick` field_map has hardcoded line indices | **Fixed**: click handler now uses `settings_line_to_edit` mapping populated by renderSettingsTab |
| admin_ssh.zig | `activeFieldInfo` returns field_idx=0 as fallback for invalid af values | Safe in practice — callers validate against totalFields() |
| dhcp.zig | `appendRawStringOpt` truncates values >255 bytes | **Logs warning** — per DHCP spec, option length is u8 |
| dhcp.zig | `encodeOptionValue` falls back to raw string on mixed IP/non-IP parse | **Logs warning** when partial IP parse detected (likely misconfiguration) |
| dhcp.zig | `encodeDnsSearchList` skips domains that overflow buffer | **Logs info** with domain name |
| config.zig | `isValidDomainName` allows single-character TLDs | RFC-compliant; single-char TLDs exist (.x, .z proposed) |

### Edge Cases (correct but worth noting)

| File | Description |
|------|-------------|
| dhcp.zig | `allocateIp` with pool_end=255.255.255.255 would allocate broadcast address — configuration error, not code bug |
| dhcp.zig | Option 119 (domain search) encoding silently skips domains that overflow the buffer — defensive, per RFC |
| dhcp.zig | `forceRenewPool` subnet mask logic differs from `metrics.zig:isIpInPool` (both correct, just different code paths) |
| sync.zig | Peer timeout uses wall clock — system clock set backwards could cause premature timeout |
| config.zig | /31 and /32 subnets parse correctly but pool_start/pool_end auto-computation may produce degenerate ranges |

---

## Test Coverage Summary

**Total tests: ~440 across 10 files**

| File | Tests | Coverage |
|------|-------|----------|
| dhcp.zig | 119 | Core DHCP protocol, all message types, option encoding, MAC class overrides (incl. time_offset), leasequery, FORCERENEW |
| admin_ssh.zig | 120 | TUI forms, validation, field navigation, inline entries, pool layout, natural sort (overflow-safe) |
| sync.zig | 68 | Per-pool protocol, voting algorithm, HELLO v2 format, encryption, config sync, reservation sync, malformed input handling |
| config.zig | 63 | YAML parsing, validation, per-pool hash, MAC class parsing |
| state.zig | 32 | Lease CRUD, persistence, nonce lifecycle, pruning |
| config_write.zig | 17 | YAML serialization, MAC class fields, pool round-trip, config_version |
| dns.zig | 15 | DNS name encoding, TSIG signing, key parsing, label limits |
| util.zig | 4 | String escaping utilities |
| probe.zig | 2 | ARP/ICMP probe helpers |
| metrics.zig | 3 | Pool capacity computation (/24, /30, /31, /32) |

### Notable test coverage

- DHCP option encoding verified for options 1, 2, 3, 4, 6, 15, 26, 28, 33, 42, 44, 51, 53, 54, 58, 59, 66, 67, 90, 119, 121, 145, 150
- MAC class first-class field overrides tested for router, dns_servers, static_routes, domain_name, http_boot_url
- Sync voting: all-match, local minority, local majority, tie-break by IP, local-only pool
- Lease lifecycle: create, update, replace (nonce freed), remove, prune, save/load round-trip
- Validation: pool form fields, reservation form, MAC patterns, domain names, IP addresses, file paths, URLs

### Remaining test gaps (MEDIUM priority)

| Gap | Why not tested |
|-----|---------------|
| Config reload (SIGHUP → reloadConfig) | Requires signal handling; integration test territory |
| DNS resolve cache hit/miss/TTL | Requires network access for getaddrinfo |
| Prometheus metrics HTTP response format | Requires HTTP client or socket testing |
| SSH authorized_keys file parsing | Requires filesystem mocking |
| Per-MAC decline threshold window expiry | Requires time manipulation |
