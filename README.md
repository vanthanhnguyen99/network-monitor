# OpenWRT Netmon Lite

OpenWRT Netmon Lite is a lightweight realtime network observer for a home or lab OpenWRT router. The router only forwards syslog-style telemetry; the LAN server keeps short-lived state in RAM and serves a dashboard plus JSON APIs.

The default mode is a single C++20 process with no database and bounded in-memory buffers. Extended deployments can enable bounded SQLite persistence, a Prometheus `/metrics` endpoint, and the checked-in Grafana dashboard.

## What It Runs

- UDP syslog receiver on `1514` by default.
- Optional TCP syslog receiver on `1514`.
- HTTP dashboard and JSON API on `8080`.
- WebSocket endpoint at `/ws` for realtime refresh signals.
- In-memory device, traffic, event, and WAN attack state.
- Optional SQLite mode with strict retention.
- Optional Prometheus exporter endpoint, disabled by default.
- Optional Grafana dashboard JSON under `deployments/grafana/`.

## Quick Start With Docker

Build and start the service:

```sh
scripts/start-docker-service.sh
```

Open the dashboard:

```text
http://localhost:8080
```

Install as a host systemd service that starts the Docker Compose stack on boot:

```sh
sudo scripts/install-docker-service.sh
```

The installer checks whether `/etc/systemd/system/openwrt-netmon-lite.service` already exists before adding it. Use `--force` only when you intentionally want to overwrite the service file.

Send a mock UDP log from the host:

```sh
printf '%s\n' '<13>NETDEV: ts=1767000000 mac=00:e0:4c:68:02:89 ip=192.168.10.157 host=test-device neigh=REACHABLE' \
  | nc -u -w1 127.0.0.1 1514
```

Send mock traffic snapshots:

```sh
printf '%s\n' '<13>NETTRAFFIC: ts=1767000000 mac=00:e0:4c:68:02:89 ip=192.168.10.157 rx_bytes=100000 tx_bytes=40000' \
  | nc -u -w1 127.0.0.1 1514

printf '%s\n' '<13>NETTRAFFIC: ts=1767000060 mac=00:e0:4c:68:02:89 ip=192.168.10.157 rx_bytes=220000 tx_bytes=70000' \
  | nc -u -w1 127.0.0.1 1514
```

Send mock WAN interface snapshots for near-realtime total traffic:

```sh
printf '%s\n' '<13>NETIFACE: ts=1767000000 if=pppoe-wan rx_bytes=1000000 tx_bytes=300000' \
  | nc -u -w1 127.0.0.1 1514

printf '%s\n' '<13>NETIFACE: ts=1767000001 if=pppoe-wan rx_bytes=3000000 tx_bytes=800000' \
  | nc -u -w1 127.0.0.1 1514
```

Send a mock WAN drop:

```sh
printf '%s\n' '<13>kernel: WAN_ATTACK: IN=pppoe-wan OUT= MAC= SRC=207.66.160.140 DST=42.114.141.42 LEN=68 PROTO=TCP DPT=443' \
  | nc -u -w1 127.0.0.1 1514
```

## Configuration

The default Docker Compose file mounts `config.example.yaml` as `/app/config.yaml`, then enables SQLite and Prometheus with environment overrides so the dashboard can switch between live memory and SQLite data.

Important settings:

```yaml
server:
  http_addr: "0.0.0.0:8080"
  syslog_udp_addr: "0.0.0.0:1514"
  enable_udp: true
  enable_tcp: false

state:
  device_online_ttl_seconds: 180
  device_idle_ttl_seconds: 600
  max_events: 2000
  max_attack_events: 1000
  traffic_rate_hold_seconds: 75

storage:
  mode: "sqlite"
  sqlite:
    path: "/data/openwrt-netmon-lite.db"
    retention_days: 7
    max_db_mb: 128
    max_events: 50000
    max_traffic_points_per_device: 2016

metrics:
  prometheus_enabled: true
  prometheus_path: "/metrics"
  include_device_labels: false

security:
  dashboard_token: ""
  trusted_router_ips:
    # - "192.168.10.1"
```

Environment overrides supported by the container:

- `NETMON_HTTP_ADDR`
- `NETMON_SYSLOG_UDP_ADDR`
- `NETMON_SYSLOG_TCP_ADDR`
- `NETMON_ENABLE_UDP`
- `NETMON_ENABLE_TCP`
- `NETMON_DASHBOARD_TOKEN`
- `NETMON_STORAGE_MODE`
- `NETMON_SQLITE_PATH`
- `NETMON_SQLITE_RETENTION_DAYS`
- `NETMON_SQLITE_MAX_DB_MB`
- `NETMON_SQLITE_MAX_EVENTS`
- `NETMON_SQLITE_MAX_TRAFFIC_POINTS_PER_DEVICE`
- `NETMON_SQLITE_VACUUM_ON_START`
- `NETMON_PROMETHEUS_ENABLED`
- `NETMON_PROMETHEUS_PATH`
- `NETMON_PROMETHEUS_INCLUDE_DEVICE_LABELS`
- `NETMON_PROMETHEUS_DEVICE_LABEL_MODE`
- `NETMON_TRUSTED_ROUTER_IPS`, comma-separated
- `NETMON_WEB_ROOT`

When `security.dashboard_token` is set, API, WebSocket, and Prometheus requests require either `X-Netmon-Token` or `?token=<value>`.

## OpenWRT Setup

Assume the Docker host is `192.168.10.10`.

Configure remote syslog on the router. This also writes `/etc/netmon-collector.conf`, so Netmon telemetry can bypass OpenWRT log buffering and send directly to the Docker host over UDP:

```sh
LAN_SERVER_IP=192.168.10.10 SYSLOG_PORT=1514 SYSLOG_PROTO=udp sh ./openwrt/setup-remote-syslog.sh
```

Install the collector scripts on the router. The collector runs lightweight `NETIFACE` WAN counters every 1 second, `NETTRAFFIC` every 1 second, and `NETDEV` every 5 seconds through OpenWRT `procd`:

```sh
ssh root@192.168.10.1 'mkdir -p /usr/lib/netmon'
scp openwrt/netmon-lib.sh root@192.168.10.1:/usr/lib/netmon/netmon-lib.sh
scp openwrt/netmon-iface.sh root@192.168.10.1:/usr/bin/netmon-iface.sh
scp openwrt/netmon-devices.sh root@192.168.10.1:/usr/bin/netmon-devices.sh
scp openwrt/netmon-traffic.sh root@192.168.10.1:/usr/bin/netmon-traffic.sh
scp openwrt/netmon-collector-loop.sh root@192.168.10.1:/usr/bin/netmon-collector-loop.sh
scp openwrt/netmon-collector.init root@192.168.10.1:/etc/init.d/netmon-collector
ssh root@192.168.10.1 'chmod +x /usr/lib/netmon/netmon-lib.sh /usr/bin/netmon-iface.sh /usr/bin/netmon-devices.sh /usr/bin/netmon-traffic.sh /usr/bin/netmon-collector-loop.sh /etc/init.d/netmon-collector && /etc/init.d/netmon-collector enable && /etc/init.d/netmon-collector restart'
```

The top Download/Upload summary prefers `NETIFACE` WAN counters when they are fresh. On a WAN interface, `rx_bytes` is internet download into the router and `tx_bytes` is internet upload out of the router. Per-device rows still use `nlbwmon`; the first `NETTRAFFIC` sample sets totals, and rates appear after the second changed sample for the same MAC. To avoid flicker with sampled collection, the dashboard holds the latest non-zero per-device rate for `state.traffic_rate_hold_seconds`.

```sh
ssh root@192.168.10.1 'opkg update && opkg install nlbwmon && /etc/init.d/nlbwmon enable && /etc/init.d/nlbwmon start'
```

To change intervals later, edit `/etc/netmon-collector.conf` and set `NETMON_IFACE_INTERVAL_SECONDS` for WAN counters, `NETMON_DEVICES_INTERVAL_SECONDS` for device discovery, and `NETMON_TRAFFIC_INTERVAL_SECONDS` for `nlbwmon` traffic. If your WAN device is not detected correctly, set `NETMON_WAN_IFACE`, for example `pppoe-wan`, `wan`, or `eth0.2`. Set `NETMON_SEND_MODE="syslog"` only when you intentionally want telemetry to go through OpenWRT logd again.

## APIs

```text
GET /api/health
GET /api/summary
GET /api/devices
GET /api/events?limit=100
GET /api/wan-attacks?limit=100
GET /api/devices?source=sqlite&limit=100
GET /api/events?source=sqlite&limit=100
GET /api/wan-attacks?source=sqlite&limit=100
GET /api/traffic-history?source=sqlite&limit=180
GET /api/device-traffic-24h?limit=50
GET /metrics
GET /ws
```

The data-source endpoints return `{ "source": "live|sqlite", "items": [...] }`; omit `source` or use `source=live` for the realtime in-memory view, and use `source=sqlite` for persisted history when SQLite is enabled. `/api/device-traffic-24h` is SQLite-backed and returns per-device download, upload, total bytes, sample count, and first/last sample timestamps for the last 24 hours.

The dashboard polls `/api/summary`, `/api/integrations`, and the selected-source `/api/devices` every 1 second. WebSocket events trigger the same fast refresh so traffic and online-device state stay realtime. Heavier event, WAN attack, and 24h SQLite device-traffic panels refresh every 8 seconds to avoid unnecessary LAN traffic.

## Native Build For Development

Docker is the intended runtime, but native builds are useful for tests:

```sh
scripts/build-source.sh
```

Run locally:

```sh
./build/openwrt-netmon-lite --config ./config.example.yaml
```

Sanitizer build:

```sh
scripts/build-source.sh --debug --sanitizers
```

## Storage Model

The native default storage mode is `memory`. The Docker Compose service overrides it to `sqlite` and writes the database to the named volume mounted at `/data`.

To enable SQLite history on a writable path:

```yaml
storage:
  mode: "sqlite"
  sqlite:
    path: "/data/openwrt-netmon-lite.db"
    retention_days: 7
    max_db_mb: 128
    max_events: 50000
    max_traffic_points_per_device: 2016
```

SQLite mode stores normalized device, traffic, event, and WAN attack telemetry only. Logs are parsed and cleaned before insert: control characters are stripped, MAC fields are normalized, raw/csv payloads are saved only as bounded previews, and unsupported fields are dropped. Retention runs on startup and during the cleanup loop. If SQLite cannot be opened when `storage.mode: "sqlite"` is set, the service fails startup instead of silently falling back to memory.

## Prometheus And Grafana

Enable the exporter:

```yaml
metrics:
  prometheus_enabled: true
  prometheus_path: "/metrics"
```

The exporter includes service health, uptime, message counters, parse errors, device counts by status, aggregate traffic rates, WAN attack counters, and event buffer size. Per-device labels are disabled by default to avoid high-cardinality metrics.

Import the Grafana dashboard from:

```text
deployments/grafana/openwrt-netmon-lite-dashboard.json
```

See `deployments/grafana/README.md` for the Prometheus scrape example and dashboard notes.
