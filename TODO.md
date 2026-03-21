# Stardust TODO

All lower-priority features have been implemented.

## Completed

**DNS update integration** ✓
Implemented RFC 2136 dynamic DNS updates in `src/dns.zig` with TSIG key
authentication (HMAC-SHA256 and HMAC-MD5). Sends A/PTR record updates to the
configured DNS server when a lease is granted or released. Key file format is
BIND-compatible (`key "name" { algorithm ...; secret "..."; };`).

**`dhcp_options` passthrough** ✓
`Config.dhcp_options` is now populated from `config.yaml` via an untyped YAML
walk (since `yaml.parse` doesn't support StringHashMap). Options are injected
into OFFER and ACK packets. Values can be comma-separated IPv4 addresses
(encoded as 4 bytes each) or raw strings. Keys are DHCP option codes as
decimal strings (e.g. `42: "192.168.1.1"` for NTP server).

**Logging improvements** ✓
All output now goes through `std.log` with a custom `logFn` in `main.zig`.
Each line is written to stderr in the format:
```
<N>YYYY-MM-DDTHH:MM:SSZ [LEVEL] message
```
where `<N>` is the sd-daemon priority prefix (journald-compatible). Log level
is configurable via `log_level: debug|info|warn|error` in `config.yaml`.
