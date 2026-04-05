# Stardust

[![CI](https://github.com/driftlevel/stardust/actions/workflows/ci.yml/badge.svg)](https://github.com/driftlevel/stardust/actions/workflows/ci.yml)

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

- Full DISCOVER / OFFER / REQUEST / ACK / NAK flow (RFC 2131)
- DHCPRELEASE, DHCPDECLINE, and DHCPINFORM handling
- Relay agent support — routes responses via `giaddr` (RFC 2131 S4.1)
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
| 4 | Time servers (mirrors NTP servers; override with `time_servers` in pool config) |
| 6 | DNS servers |
| 7 | Log servers |
| 12 | Hostname (from reservation config or client request) |
| 15 | Domain name |
| 26 | Interface MTU |
| 28 | Broadcast address (auto-derived from subnet) |
| 33 | Static routes |
| 42 | NTP servers |
| 44 | NetBIOS/WINS name servers |
| 51 | Lease time |
| 53 | Message type |
| 54 | Server identifier |
| 55 | Parameter Request List filtering — only requested options are sent |
| 58 | Renewal (T1) time — half of lease time |
| 59 | Rebinding (T2) time — 87.5% of lease time |
| 60 | Vendor class identifier (UEFI HTTP boot echo) |
| 61 | Client identifier — used for lease tracking across MAC changes |
| 66 | TFTP server name (PXE boot) |
| 67 | Boot filename (PXE / UEFI HTTP boot URL) |
| 82 | Relay agent information — parsed and logged at VERBOSE level |
| 119 | Domain search list (RFC 3397) |
| 121 | Classless static routes (RFC 3442) |
| 150 | Cisco TFTP server address |

Arbitrary additional options can be injected via `dhcp_options` in config
(numeric keys, IPv4 or raw string values).

### DHCP option overrides

Options can be overridden at three levels, with higher levels taking priority:

1. **Pool defaults** — `dhcp_options` map on the pool
2. **MAC class rules** — match clients by MAC prefix (vendor OUI); applied in
   specificity order (shortest prefix first, most specific wins)
3. **Per-reservation** — `dhcp_options` map on individual reservations

```yaml
mac_classes:
  - name: "IP Phones"
    match: "64:16:7f"            # Polycom OUI
    dhcp_options:
      66: "tftp.phones.local"
      150: "10.0.0.5"

pools:
  - subnet: "192.168.1.0/24"
    reservations:
      - mac: "64:16:7f:aa:bb:cc"
        ip: "192.168.1.50"
        dhcp_options:              # overrides the MAC class
          66: "tftp.lobby.local"
```

MAC class patterns support prefix matching (`"64:16:7f"` matches any MAC
starting with that OUI) and trailing wildcards (`"64:16:7f:*"`). Matching
is case-insensitive and validated at octet boundaries.

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

### UEFI HTTP boot

When a client sends option 60 = `"HTTPClient"` (UEFI Specification S24.4),
the server echoes option 60 and provides the configured HTTP URL as option 67.
Non-HTTP clients receive standard TFTP options (66/67) instead.

```yaml
pools:
  - subnet: "192.168.1.0/24"
    http_boot_url: "http://boot.example.com/uefi/bootx64.efi"
    tftp_server_name: "192.168.1.1"  # fallback for non-UEFI clients
    boot_filename: "pxelinux.0"
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
(PTR record) — as required by RFC 2136 S3.1.

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
pool's subnet prefix length using classful octet boundaries.

### SSH admin TUI

An interactive full-screen terminal interface accessible over SSH. Provides
real-time visibility and management without touching config files.

```bash
ssh -p 2267 admin@dhcp-server
```

**Tabs:**

| Tab | Description |
|-----|-------------|
| 1 Leases | Live lease table with sort, filter, yank (copy to clipboard) |
| 2 Stats | Per-pool capacity bars, DHCP message counters, uptime |
| 3 Pools | View/edit/add/remove pool configurations with diff preview |
| 4 Settings | Global config (log level, metrics, allocation mode); editable fields with deferred save |

**Capabilities:**
- Full mouse support — click tabs, sort columns, select rows, scroll
- Keyboard navigation — j/k, arrows, Tab/Shift-Tab, Home/End
- Pool editing — scrollable form with all fields; static routes and DHCP
  options edited via sub-modals; diff/confirm screen shows sync impact
- Reservation management — add/edit/delete with inline DHCP option editing and option lookup
- Force-release — evict any lease (dynamic or reserved) from the TUI
- Config write-back — changes saved atomically and reloaded via SIGHUP
- `read_only` mode — blocks all writes; hides sensitive key paths
- Help screen — press `?` for all keyboard shortcuts

```yaml
admin_ssh:
  enable: true
  port: 2267
  host_key: "/etc/stardust/ssh_host_key"
  authorized_keys: "/etc/stardust/authorized_keys"
```

Generate a host key: `ssh-keygen -t ed25519 -f /etc/stardust/ssh_host_key -N ""`

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

**DNS behaviour in a sync group:**
DNS updates are sent only by the server that issued the DHCPACK. If that server
goes offline, the server with the lowest IP takes over DNS until it returns.

**Pool config changes with sync:**
Changing pool settings that affect the pool hash (subnet, range, lease time,
reservations, static routes) disconnects all sync peers. All peers must be
updated with matching config and restarted together.

### Prometheus metrics

```yaml
metrics:
  collect: true        # in-process counters (default true; used by SSH stats tab)
  http_enable: true    # expose GET /metrics endpoint
  http_port: 9167
  http_bind: "127.0.0.1"
```

### Logging

Structured log lines on stderr, journald-compatible when `JOURNAL_STREAM` is
set:

```
2025-04-01T12:00:00Z [INFO] DHCPACK 192.168.1.42 to aa:bb:cc:dd:ee:ff host=printer lease=3600s
```

| Level | Description |
|-------|-------------|
| `err` | Errors only |
| `warn` | Errors and warnings |
| `info` | Normal operation: lease grants, server startup, peer auth (default) |
| `verbose` | Per-event summaries: every OFFER, ACK, NAK, RELEASE, DNS, sync |
| `debug` | Full packet-level detail |

## Configuration reference

See the annotated [`config.yaml`](config.yaml) for all options. Key top-level
fields:

| Field | Default | Description |
|-------|---------|-------------|
| `listen_address` | `"0.0.0.0"` | Address to bind UDP port 67 |
| `state_dir` | -- | Directory for `leases.json` (required) |
| `log_level` | `"info"` | `err` / `warn` / `info` / `verbose` / `debug` |
| `pool_allocation_random` | `false` | Random vs sequential IP allocation |
| `mac_classes` | `[]` | MAC prefix rules with DHCP option overrides |

Each entry in `pools:` is one subnet. Required pool fields: `subnet` (CIDR),
`router`, `dns_servers`, `lease_time`. Optional: `pool_start`, `pool_end`,
`domain_name`, `domain_search`, `reservations`, `static_routes`,
`dhcp_options`, `dns_update`, `http_boot_url`, `mtu`, `wins_servers`,
`cisco_tftp_servers`, and all time/NTP/PXE options.

## Compilation

Requires **Zig 0.15.2** and **libssh** (for the SSH admin TUI).

```bash
git clone https://github.com/driftlevel/stardust
cd stardust
zig build                        # release build
zig build -Doptimize=ReleaseSafe # optimised, safety checks kept
zig build -Doptimize=Debug       # debug build (GPA memory safety)
zig build test                   # run all unit tests
zig build dev                    # debug executable (stardust-dev)
```

Cross-compilation (fully static musl binaries via Nix):

```bash
# Install Nix, then:
BUNDLE=$(nix build .#libssh-aarch64-musl --no-link --print-out-paths)
zig build -Doptimize=ReleaseSafe -Dtarget=aarch64-linux-musl -Dlibssh_dir=$BUNDLE
```

Pre-built binaries for x86\_64, aarch64, and riscv64 are available on the
[Releases](../../releases) page.

## Container image

Multi-arch images (x86\_64, aarch64, riscv64) are published to the GitHub
Container Registry on every release:

```bash
docker pull ghcr.io/driftlevel/stardust:latest
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
  ghcr.io/driftlevel/stardust:latest
```

`--network host` is required — DHCP uses 255.255.255.255 broadcasts that
cannot cross Docker's default bridge NAT.

## systemd unit

Included in `.deb` / `.rpm` packages and release tarballs as `stardust.service`:

```bash
sudo install -m 644 packaging/stardust.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now stardust
```

The unit uses `DynamicUser=yes` with `ConfigurationDirectory=stardust`,
`StateDirectory=stardust`, and `RuntimeDirectory=stardust` for filesystem
isolation.

**TUI write-back:** The SSH admin TUI saves pool and reservation changes
back to `config.yaml`. For this to work with `DynamicUser=yes`, the
configuration directory must be writable:

```ini
# In the [Service] section:
ConfigurationDirectoryMode=0775
```

Then make the config file group-writable by a shared group (e.g.
`stardust-secrets`) so the dynamic user can write to it:

```bash
sudo groupadd stardust-secrets
sudo chgrp stardust-secrets /etc/stardust/config.yaml
sudo chmod g+w /etc/stardust/config.yaml
```

## OpenRC init script

For Alpine Linux, Gentoo, and other OpenRC-based systems. Included in
release tarballs as `stardust.openrc`:

```bash
sudo install -m 755 packaging/stardust.openrc /etc/init.d/stardust
sudo rc-update add stardust default
sudo rc-service stardust start
```

## Security profiles

### AppArmor (Debian, Ubuntu, SUSE)

```bash
sudo cp packaging/apparmor/usr.local.bin.stardust /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.stardust
```

The profile confines stardust to:
- Read `/etc/stardust/` (config, keys); write `config.yaml` + `.tmp` only
- Read-write `/var/lib/stardust/` (leases)
- Network: UDP (DHCP, sync), TCP (SSH admin, metrics)
- DNS resolution via system resolver
- Denies access to `/home`, `/root`, `/tmp`, `/srv`

### SELinux (RHEL, Fedora, CentOS, Rocky)

```bash
cd packaging/selinux
checkmodule -M -m -o stardust.mod stardust.te
semodule_package -o stardust.pp -m stardust.mod -f stardust.fc
sudo semodule -i stardust.pp
sudo restorecon -Rv /usr/local/bin/stardust /etc/stardust /var/lib/stardust
```

Types:
- `stardust_exec_t` — binary (`/usr/local/bin/stardust`)
- `stardust_conf_t` — config directory (`/etc/stardust/`)
- `stardust_key_t` — SSH and TSIG keys (read-only subset)
- `stardust_state_t` — state directory (`/var/lib/stardust/`)
