# OpenWRT Netmon Lite

OpenWRT Netmon Lite is a lightweight realtime network observer for a home or lab OpenWRT router. The router only forwards syslog-style telemetry; the LAN server keeps short-lived state in RAM and serves a dashboard plus JSON APIs.

The MVP is implemented as a single C++20 process and is intended to run in Docker. It does not use a database, does not write long-term logs, and keeps bounded ring buffers for events, WAN drops, and per-device traffic points.

## What It Runs

- UDP syslog receiver on `1514` by default.
- Optional TCP syslog receiver on `1514`.
- HTTP dashboard and JSON API on `8080`.
- WebSocket endpoint at `/ws` for realtime refresh signals.
- In-memory device, traffic, event, and WAN attack state.

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

The default Docker Compose file mounts `config.example.yaml` as `/app/config.yaml`.

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
- `NETMON_TRUSTED_ROUTER_IPS`, comma-separated
- `NETMON_WEB_ROOT`

When `security.dashboard_token` is set, API and WebSocket requests require either `X-Netmon-Token` or `?token=<value>`.

## OpenWRT Setup

Assume the Docker host is `192.168.10.10`.

Configure remote syslog on the router. This also writes `/etc/netmon-collector.conf`, so Netmon telemetry can bypass OpenWRT log buffering and send directly to the Docker host over UDP:

```sh
LAN_SERVER_IP=192.168.10.10 SYSLOG_PORT=1514 SYSLOG_PROTO=udp sh ./openwrt/setup-remote-syslog.sh
```

Install the collector scripts on the router. The collector runs lightweight `NETIFACE` WAN counters every 1 second, `NETTRAFFIC` every 3 seconds, and `NETDEV` every 5 seconds through OpenWRT `procd`:

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
GET /ws
```

The dashboard polls `/api/summary` every 1 second and `/api/devices` every 3 seconds. When `NETIFACE` messages arrive over WebSocket, it also refreshes `/api/summary` immediately, without pulling the full device list each time. Heavier event panels use smaller limits and refresh less often to avoid unnecessary LAN traffic.

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

The default storage mode is `memory`. The service logs to stdout/stderr, keeps bounded in-memory buffers, and does not create a database. The Docker Compose configuration runs the container as read-only with a small tmpfs at `/tmp`.
