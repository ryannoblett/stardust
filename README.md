# Stardust

[![CI](https://github.com/ryannoblett/stardust/actions/workflows/ci.yml/badge.svg)](https://github.com/ryannoblett/stardust/actions/workflows/ci.yml)

A lightweight DHCP server (RFC 2131/2132) written in Zig. Designed for
small-to-medium networks where you want a fast, single-binary daemon with
no runtime dependencies, optional RFC 2136 dynamic DNS integration, and
active-active redundancy via encrypted lease synchronisation.

## Quick start

```bash
# 1. Copy and edit the example config
cp config.yaml /etc/stardust/config.yaml
$EDITOR /etc/stardust/config.yaml   # set subnet, router, dns_servers at minimum

# 2. Run (needs CAP_NET_BIND_SERVICE and CAP_NET_RAW, or root)
sudo stardust -c /etc/stardust/config.yaml
```

Minimal config:

```yaml
state_dir: "/var/lib/stardust"

pools:
  - subnet:      "192.168.1.0/24"
    router:      "192.168.1.1"
    dns_servers:
      - "1.1.1.1"
    lease_time:  3600
```

Stardust listens on `0.0.0.0:67` by default. `state_dir` must be writable;
leases are persisted there as `leases.json` and survive restarts.

Reload config without restarting:

```bash
kill -HUP $(pidof stardust)
```

## Features

### Core DHCP

- Full DISCOVER → OFFER → REQUEST → ACK/NAK flow (RFC 2131)
- DHCPRELEASE, DHCPDECLINE, and DHCPINFORM handling
- Relay agent support — routes responses via `giaddr` (RFC 2131 §4.1)
- Multiple pools — serve several subnets from one daemon; relay agent
  `giaddr` selects the correct pool automatically
- Configurable lease range (`pool_start` / `pool_end`); defaults to the full
  usable subnet
- Lease state persisted to JSON and restored at startup (expired leases skipped)
- SIGHUP config reload — updates all settings without dropping the socket

### DHCP options

| Option | Description |
|--------|-------------|
| 1 | Subnet mask |
| 2 | Time offset (seconds east of UTC) |
| 3 | Router (default gateway) |
| 4 | RFC 868 time servers |
| 6 | DNS servers |
| 7 | Log servers |
| 12 | Hostname (from reservation config or client request) |
| 15 | Domain name |
| 33 | Static routes |
| 42 | NTP servers |
| 51 | Lease time |
| 53 | Message type |
| 54 | Server identifier |
| 55 | Parameter Request List filtering — only requested options are sent |
| 61 | Client identifier — used for lease tracking across MAC changes |
| 66 | TFTP server name (PXE boot) |
| 67 | Boot filename (PXE boot) |
| 82 | Relay agent information — parsed and logged at VERBOSE level |
| 119 | Domain search list (RFC 3397) |
| 121 | Classless static routes (RFC 3442) |

Arbitrary additional options can be injected via `dhcp_options` in config
(numeric keys, IPv4 or raw string values).

### Static reservations

Pin a MAC address (or DHCP client identifier, option 61) to a fixed IP and
optional hostname. Reservations survive lease expiry and DHCPRELEASE.

```yaml
pools:
  - subnet: "192.168.1.0/24"
    # ...
    reservations:
      - mac: "aa:bb:cc:dd:ee:ff"
        ip:  "192.168.1.50"
        hostname: "printer"
      - client_id: "01aabbccddeeff"   # option 61 hex string
        ip: "192.168.1.51"
```

### Pre-offer conflict detection

Before offering an address, Stardust probes for existing occupants:

- **ARP probe** (RFC 5227 style, SPA=0.0.0.0) for clients on the local segment
- **ICMP echo** for clients behind a relay agent

The probing client's own MAC address and its existing lease IP are excluded
from conflict detection, so renewals are not falsely blocked. Addresses that
genuinely conflict are quarantined for `max(lease_time / 10, 300)` seconds,
the same cooldown used for DHCPDECLINE.

### DHCPDECLINE protection

- Per-MAC cooldown after 3 declines within 60 seconds
- Global rate limit: 20 declines per 5-minute window (blocks MAC-rotation attacks)

### Dynamic DNS updates (RFC 2136)

Stardust can update a BIND-compatible DNS server with A and PTR records when
leases are granted or released. Each update sends two separate DNS UPDATE
messages — one for the forward zone (A record) and one for the reverse zone
(PTR record) — as required by RFC 2136 §3.1.

Authentication uses TSIG (HMAC-SHA256 or HMAC-MD5) with a standard BIND key
file. Leave `key_file` empty for anonymous (unauthenticated) updates.

DNS update is configured per-pool:

```yaml
pools:
  - subnet: "192.168.1.0/24"
    # ...
    dns_update:
      enable:   true
      server:   "127.0.0.1"
      zone:     "home.lan"
      key_name: "dhcp-update"
      key_file: "/etc/bind/dhcp-update.key"  # leave empty for anonymous updates
```

The reverse zone (`x.y.z.in-addr.arpa`) is derived automatically from the
pool's subnet prefix length using classful octet boundaries (≤8 bit → /8,
≤16 bit → /16, >16 bit → /24). Sub-/24 reverse delegations (RFC 2317) are
not currently supported.

### Lease synchronisation (active-active redundancy)

Two or more Stardust instances serving the same subnet can share lease state
over UDP. Each datagram is encrypted with AES-256-GCM (key derived from a
shared TSIG secret via HKDF-SHA-256). Peers authenticate each other by
comparing a SHA-256 hash of the pool configuration — servers with different
subnet/pool/reservation settings are rejected.

Conflict resolution is last-write-wins on the `last_modified` timestamp.
Anti-entropy: peers exchange a lease-set hash periodically and only transmit
the full lease list when hashes differ.

```yaml
sync:
  enable:     true
  group_name: "dhcp-ha"
  key_file:   "/etc/stardust/sync.key"   # BIND TSIG key file

  # Option A — link-local multicast (same L2 segment)
  multicast: "239.255.0.67"

  # Option B — unicast (peers across routers)
  # peers:
  #   - "10.0.0.2"
  #   - "10.0.0.3"
```

Enable `pool_allocation_random: true` on all group members to reduce the
chance of two servers assigning the same address during a network partition.

**DNS behaviour in a sync group**

DNS updates are sent only by the server that issued the DHCPACK (the
"originating" server). If that server goes offline, the remaining server with
the lowest IP address in the active group takes over as DNS delegate —
sending deletes on lease expiry or DHCPRELEASE, and resuming normal operation
until the originator returns. When the originator reconnects it automatically
reclaims its DNS role. This election works correctly for groups of any size.

**DHCPREQUEST handling in a sync group**

For the normal DISCOVER → OFFER → REQUEST flow the server identifier (option
54) ensures only the chosen server replies. For broadcast DHCPREQUEST without
a server identifier (REBINDING state), the same lowest-IP election applies: a
standby server defers to the originator if it is reachable, and takes over if
it is not.

### Logging

Structured log lines on stderr, journald-compatible when `JOURNAL_STREAM` is
set. When running under systemd, timestamps are omitted from log lines (journald
records them independently):

```
# standalone / non-journald
2025-04-01T12:00:00Z [INFO] DHCPACK 192.168.1.42 to aa:bb:cc:dd:ee:ff host=printer lease=3600s

# under systemd / journald
<6>[INFO] DHCPACK 192.168.1.42 to aa:bb:cc:dd:ee:ff host=printer lease=3600s
```

Log level is configurable in `config.yaml`:

| Level | Description |
|-------|-------------|
| `error` | Errors only |
| `warn` | Errors and warnings |
| `info` | Normal operation: lease grants, server startup, peer auth (default) |
| `verbose` | Per-event summaries: every OFFER, ACK, NAK, RELEASE, DNS send, sync send/receive |
| `debug` | Full packet-level detail |

## Configuration reference

See the annotated [`config.yaml`](config.yaml) for all options. Key top-level
fields:

| Field | Default | Description |
|-------|---------|-------------|
| `listen_address` | `"0.0.0.0"` | Address to bind UDP port 67 |
| `state_dir` | — | Directory for `leases.json` (required) |
| `log_level` | `"info"` | `error` / `warn` / `info` / `verbose` / `debug` |
| `pool_allocation_random` | `false` | Random vs sequential IP allocation |

Each entry in `pools:` is one subnet. Required pool fields: `subnet` (CIDR),
`router`, `dns_servers`, `lease_time`. Optional: `pool_start`, `pool_end`,
`domain_name`, `domain_search`, `reservations`, `static_routes`,
`dhcp_options`, `dns_update`, and all time/NTP/PXE options.

## Compilation

Requires **Zig 0.15.2**. No other build dependencies.

```bash
git clone https://github.com/ryannoblett/stardust
cd stardust
zig build                        # release build → zig-out/bin/stardust
zig build -Doptimize=ReleaseSafe # optimised, safety checks kept
zig build test                   # run all unit tests
```

Cross-compilation (fully static musl binaries):

```bash
zig build -Doptimize=ReleaseSafe -Dtarget=aarch64-linux-musl
zig build -Doptimize=ReleaseSafe -Dtarget=x86_64-linux-musl
```

Pre-built binaries for x86\_64, aarch64, and riscv64 are available on the
[Releases](../../releases) page. Each archive contains the binary and an
example `config.yaml`.

## Container image

Multi-arch images (x86\_64, aarch64, riscv64) are published to the GitHub
Container Registry on every release:

```bash
docker pull ghcr.io/ryannoblett/stardust:latest
```

The image is built on `scratch` — it contains only the statically-linked
binary. Mount your config file and a volume for lease state:

```bash
docker run -d --name stardust \
  --network host \
  --cap-add NET_BIND_SERVICE \
  --cap-add NET_RAW \
  --restart unless-stopped \
  -v /etc/stardust/config.yaml:/etc/stardust/config.yaml:ro \
  -v stardust-state:/var/lib/stardust \
  ghcr.io/ryannoblett/stardust:latest
```

`--network host` is required — DHCP uses 255.255.255.255 broadcasts that
cannot cross Docker's default bridge NAT. Set `state_dir: "/var/lib/stardust"`
in your config to use the named volume.

Config reload works the same way inside a container:

```bash
docker kill -s HUP stardust
```

## systemd unit

The unit file is included in the `.deb` and `.rpm` packages and in the release
tarballs as `stardust.service`. To install manually:

```bash
sudo install -m 644 stardust.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now stardust
```

```ini
[Unit]
Description=Stardust DHCP Server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/stardust -c /etc/stardust/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
DynamicUser=yes
StateDirectory=stardust
RuntimeDirectory=stardust

[Install]
WantedBy=multi-user.target
```

## OpenRC init script

For Devuan, Alpine Linux, Gentoo, and other OpenRC-based systems. The script
is included in the release tarballs as `stardust.openrc`.

```bash
sudo install -m 755 stardust.openrc /etc/init.d/stardust
sudo rc-update add stardust default
sudo rc-service stardust start
```

```sh
#!/sbin/openrc-run

description="Stardust DHCP Server"

command="/usr/local/bin/stardust"
command_args="-c /etc/stardust/config.yaml"
command_user="root"
pidfile="/run/${RC_SVCNAME}.pid"
command_background="yes"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath --directory --owner root:root --mode 0755 /var/lib/stardust
}
```
