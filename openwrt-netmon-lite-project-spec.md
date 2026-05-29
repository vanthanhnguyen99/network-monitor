# OpenWRT Realtime Network Observer

## 1. Project Summary

Build a lightweight realtime network monitoring system for a home/lab OpenWRT network.

The key design decision is:

> OpenWRT only collects and forwards lightweight telemetry.  
> The LAN server receives, parses, keeps short-lived state in RAM, and exposes a web dashboard.  
> No long-term database is required in the MVP.

This project should be suitable as a portfolio project for embedded/Linux networking work.

The server implementation should use **C++** instead of Go.

---

## 2. Goals

### Primary goals

1. Centralize OpenWRT network logs on one LAN server.
2. Visualize the current network state through a web dashboard.
3. Show active devices in the network:
   - MAC address
   - IP address
   - hostname
   - last seen
   - online/idle/offline status
   - current or recent upload/download rate if available
4. Show lightweight traffic summary per device.
5. Show important realtime events:
   - new DHCP lease
   - device seen/idle/offline
   - WAN attack/firewall drop logs
   - WAN reconnect events
6. Minimize storage usage on the server.
7. Keep OpenWRT load low.
8. Keep the server implementation suitable for a C++/Linux networking portfolio.

### Non-goals for MVP

Do not implement these in the first version:

1. Long-term history storage.
2. Prometheus, Loki, Elasticsearch, InfluxDB, TimescaleDB, or any heavy database.
3. Full packet capture.
4. Deep packet inspection.
5. Cloud upload.
6. Automatic firewall blocking.
7. Complex authentication system.
8. Mobile app.

---

## 3. Important Constraints

### OpenWRT constraints

OpenWRT must only do simple collection and forwarding:

- Use built-in remote syslog when possible.
- Use small shell scripts only for snapshots.
- Do not run a database on the router.
- Do not run Grafana/Prometheus/Loki on the router.
- Do not write large logs to router flash.
- Avoid logging every packet.

### Server constraints

The LAN server should avoid growing storage usage over time.

Default mode:

- No persistent database.
- No long-term log files.
- Keep state in RAM.
- Keep only rolling buffers.
- Log application output to stdout/stderr.
- Optional debug file logging must be disabled by default.

Target storage usage:

- Stable over time.
- Ideally less than 50 MB excluding the compiled binary and frontend static assets.
- If optional file logging is enabled, it must have rotation and size limits.

---

## 4. Recommended Architecture

```text
OpenWRT Router
  ├─ logd / logread
  ├─ remote syslog -> LAN server
  ├─ NETDEV snapshot via logger
  ├─ NETTRAFFIC summary via nlbwmon + logger
  └─ firewall/WAN logs

LAN Server
  ├─ C++ syslog receiver
  ├─ parser
  ├─ in-memory state store
  ├─ rolling event buffers
  ├─ HTTP API
  ├─ WebSocket realtime updates
  └─ web dashboard
```

---

## 5. Technology Recommendation

Preferred implementation:

```text
Language: C++20 or C++23
Build system: CMake
Network I/O: Boost.Asio or standalone Asio
HTTP/WebSocket: Crow, Boost.Beast, or another lightweight C++ web layer
JSON: nlohmann/json or equivalent
Config: yaml-cpp, toml++, or a simple custom config parser
Storage: RAM only
Transport from OpenWRT: syslog UDP or TCP
Dashboard: served by the C++ backend
Packaging: single binary + config file + systemd service
```

Recommended MVP stack:

```text
C++20
CMake
Boost.Asio for UDP/TCP syslog receiver
Crow for HTTP API and WebSocket dashboard
nlohmann/json for JSON responses
Plain HTML/CSS/JavaScript for frontend
```

Why C++ is preferred for this project:

- It matches the target embedded/Linux networking skill set.
- It demonstrates low-level networking, parsing, memory ownership, and event-driven server design.
- It keeps runtime overhead low.
- It can be packaged as one native Linux service.
- It is suitable for later extension into nftables, netlink, eBPF, or other Linux networking integrations.

Acceptable alternatives:

- C++ with standalone Asio instead of Boost.Asio.
- C++ with Boost.Beast instead of Crow.
- Rust backend with Tokio if C++ is explicitly dropped later.
- Python only for a temporary parser prototype, not the preferred final version.

---

## 6. Data Sources

### 6.1 Built-in OpenWRT logs

OpenWRT can forward system logs to a remote syslog server.

Expected logs:

```text
dnsmasq-dhcp  -> DHCP lease events
netifd/pppd   -> WAN up/down and PPPoE reconnect events
kernel/fw4    -> firewall drop/WAN attack logs
hostapd       -> WiFi association/disassociation events
```

Example firewall log:

```text
Fri May 29 11:40:06 2026 kern.warn kernel: WAN_ATTACK: IN=pppoe-wan OUT= MAC= SRC=207.66.160.140 DST=42.114.141.42 LEN=68
```

Example DHCP log:

```text
Fri May 29 11:40:31 2026 daemon.info dnsmasq-dhcp[1]: DHCPREQUEST(eth2.vlan10) 192.168.10.157 00:e0:4c:68:02:89
Fri May 29 11:40:31 2026 daemon.info dnsmasq-dhcp[1]: DHCPACK(eth2.vlan10) 192.168.10.157 00:e0:4c:68:02:89 thanhvn-MacBookAir7-2
```

### 6.2 Active device snapshot

DHCP lease logs alone are not enough to determine active devices.

OpenWRT should periodically emit a lightweight snapshot using:

- `/tmp/dhcp.leases`
- `ip neigh`
- optional `ubus`/`hostapd` data for WiFi clients

Use a custom syslog tag:

```text
NETDEV
```

Example emitted log format:

```text
NETDEV ts=1767000000 mac=00:e0:4c:68:02:89 ip=192.168.10.157 host=thanhvn-MacBookAir7-2 lease_expiry=1767003600 neigh=REACHABLE
```

### 6.3 Traffic summary

Do not log every packet.

For per-device traffic summary, use `nlbwmon` if available.

Use a custom syslog tag:

```text
NETTRAFFIC
```

Example emitted log format:

```text
NETTRAFFIC ts=1767000000 mac=00:e0:4c:68:02:89 ip=192.168.10.157 rx_bytes=123456789 tx_bytes=9876543
```

If using raw `nlbw -c csv`, the server must parse the CSV format defensively.

### 6.4 Optional WiFi clients

If the OpenWRT device is also the access point, the collector can use `ubus` or hostapd-related data to detect associated WiFi clients.

This is optional for MVP.

---

## 7. OpenWRT Setup

Assume the LAN server IP is:

```text
192.168.10.10
```

Use port `1514` so the server process does not need root privileges.

### 7.1 Configure remote syslog

UDP mode:

```sh
uci set system.@system[0].log_ip='192.168.10.10'
uci set system.@system[0].log_port='1514'
uci set system.@system[0].log_proto='udp'
uci set system.@system[0].log_hostname='openwrt-main'
uci commit system
/etc/init.d/log restart
```

TCP mode:

```sh
uci set system.@system[0].log_ip='192.168.10.10'
uci set system.@system[0].log_port='1514'
uci set system.@system[0].log_proto='tcp'
uci set system.@system[0].log_hostname='openwrt-main'
uci commit system
/etc/init.d/log restart
```

Test:

```sh
logger -t NETMON_TEST "hello from OpenWRT"
```

### 7.2 Active device snapshot script

Create:

```sh
cat > /usr/bin/netmon-devices.sh <<'EOF'
#!/bin/sh

TS="$(date +%s)"

[ -f /tmp/dhcp.leases ] || exit 0

cat /tmp/dhcp.leases | while read expiry mac ip host clientid; do
    state="$(ip neigh show "$ip" 2>/dev/null | awk '{print $NF; exit}')"

    [ -z "$host" ] && host="unknown"
    [ -z "$state" ] && state="unknown"

    logger -t NETDEV "ts=$TS mac=$mac ip=$ip host=$host lease_expiry=$expiry neigh=$state"
done
EOF

chmod +x /usr/bin/netmon-devices.sh
```

Run every minute:

```sh
echo '* * * * * /usr/bin/netmon-devices.sh' >> /etc/crontabs/root
/etc/init.d/cron restart
```

### 7.3 Optional traffic snapshot script

Install `nlbwmon`:

```sh
opkg update
opkg install nlbwmon
/etc/init.d/nlbwmon enable
/etc/init.d/nlbwmon start
```

Create:

```sh
cat > /usr/bin/netmon-traffic.sh <<'EOF'
#!/bin/sh

TS="$(date +%s)"

# Prefer JSON if available and easy to parse server-side.
# Fall back to CSV if JSON output is unavailable on this OpenWRT build.
nlbw -c csv 2>/dev/null | while IFS= read -r line; do
    logger -t NETTRAFFIC "ts=$TS csv=$line"
done
EOF

chmod +x /usr/bin/netmon-traffic.sh
```

Run every 5 minutes:

```sh
echo '*/5 * * * * /usr/bin/netmon-traffic.sh' >> /etc/crontabs/root
/etc/init.d/cron restart
```

---

## 8. Server Application Requirements

Project name:

```text
openwrt-netmon-lite
```

### 8.1 Required features

The C++ server must:

1. Listen for syslog messages on UDP and/or TCP.
2. Parse messages from OpenWRT.
3. Recognize at least these tags/patterns:
   - `NETDEV`
   - `NETTRAFFIC`
   - `dnsmasq-dhcp`
   - `WAN_ATTACK`
   - `netifd`
   - `pppd`
   - `hostapd`
4. Keep device state in RAM.
5. Keep traffic state in RAM.
6. Keep recent events in bounded ring buffers.
7. Expose a web dashboard.
8. Expose JSON APIs.
9. Push realtime updates through WebSocket.
10. Avoid unbounded memory growth.
11. Use RAII and avoid raw owning pointers.
12. Compile cleanly with warnings enabled.

### 8.2 Configuration

Support a config file:

```yaml
server:
  http_addr: "0.0.0.0:8080"
  syslog_udp_addr: "0.0.0.0:1514"
  syslog_tcp_addr: "0.0.0.0:1514"
  enable_udp: true
  enable_tcp: false

state:
  device_online_ttl_seconds: 180
  device_keep_ttl_seconds: 3600
  max_events: 2000
  max_attack_events: 1000
  max_traffic_points_per_device: 60

storage:
  mode: "memory"
  enable_debug_file_log: false
  debug_log_path: "./netmon-debug.log"
  debug_log_max_mb: 10

security:
  bind_lan_only: true
  dashboard_token: ""
  trusted_router_ips:
    - "192.168.10.1"
```

Also support environment variable overrides:

```text
NETMON_HTTP_ADDR
NETMON_SYSLOG_UDP_ADDR
NETMON_SYSLOG_TCP_ADDR
NETMON_ENABLE_UDP
NETMON_ENABLE_TCP
NETMON_DASHBOARD_TOKEN
```

---

## 9. In-Memory Data Model

Use C++ value types where possible. Prefer `std::string`, `std::chrono`, `std::vector`, `std::deque`, `std::unordered_map`, `std::optional`, and `std::shared_mutex` or equivalent synchronization primitives where needed.

### 9.1 Device state

```cpp
enum class DeviceStatus {
    Online,
    Idle,
    Offline,
    Unknown
};

struct DeviceState {
    std::string mac;
    std::string ip;
    std::string hostname;
    std::string interface_name;
    std::string source;      // dhcp, netdev, wifi, arp, traffic
    std::string neigh_state;

    DeviceStatus status = DeviceStatus::Unknown;

    std::chrono::system_clock::time_point first_seen{};
    std::chrono::system_clock::time_point last_seen{};
    std::chrono::system_clock::time_point last_dhcp{};

    std::uint64_t rx_bytes_total = 0;
    std::uint64_t tx_bytes_total = 0;
    double rx_rate_bps = 0.0;
    double tx_rate_bps = 0.0;

    std::vector<std::string> tags;
};
```

### 9.2 Traffic snapshot

```cpp
struct TrafficSnapshot {
    std::string mac;
    std::string ip;
    std::chrono::system_clock::time_point ts{};
    std::uint64_t rx_bytes = 0;
    std::uint64_t tx_bytes = 0;
};
```

### 9.3 Event

```cpp
enum class EventSeverity {
    Info,
    Warning,
    Critical
};

struct Event {
    std::string id;
    std::chrono::system_clock::time_point ts{};
    std::string type;       // device, traffic, wan_attack, dhcp, wan, system
    EventSeverity severity = EventSeverity::Info;
    std::string source;
    std::string message;
    std::unordered_map<std::string, std::string> fields;
};
```

### 9.4 WAN attack event

```cpp
struct WANAttackEvent {
    std::chrono::system_clock::time_point ts{};
    std::string in_if;
    std::string src_ip;
    std::string dst_ip;
    std::string src_port;
    std::string dst_port;
    std::string proto;
    std::string length;
    std::string raw;
};
```

### 9.5 State store

Suggested shape:

```cpp
class StateStore {
public:
    void updateDevice(const DeviceState& device);
    void updateTraffic(const TrafficSnapshot& snapshot);
    void addEvent(const Event& event);
    void addWANAttack(const WANAttackEvent& event);

    std::vector<DeviceState> devices() const;
    std::vector<Event> recentEvents(std::size_t limit) const;
    std::vector<WANAttackEvent> recentWANAttacks(std::size_t limit) const;

    void cleanup(std::chrono::system_clock::time_point now);

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, DeviceState> devices_by_mac_;
    RingBuffer<Event> events_;
    RingBuffer<WANAttackEvent> wan_attacks_;
};
```

---

## 10. Device Status Logic

Recommended status calculation:

```text
ONLINE:
  LastSeen <= 3 minutes ago and neigh is REACHABLE/STALE/DELAY/PROBE
  OR WiFi associated client is seen

IDLE:
  DHCP lease exists but no strong activity recently
  OR neigh is STALE/unknown but LastSeen <= 10 minutes ago

OFFLINE:
  LastSeen > 10 minutes ago

UNKNOWN:
  MAC/IP exists but status cannot be inferred
```

The exact thresholds must be configurable.

---

## 11. Traffic Logic

For each traffic snapshot:

1. Find previous snapshot for same MAC or same IP.
2. Compute delta:
   - `delta_rx = current_rx - previous_rx`
   - `delta_tx = current_tx - previous_tx`
   - `delta_time = current_ts - previous_ts`
3. Compute rates:
   - `rx_rate_bps = delta_rx * 8 / delta_time`
   - `tx_rate_bps = delta_tx * 8 / delta_time`
4. If counters reset or delta is negative, discard that interval.
5. Keep only last N points per device.

Dashboard should display:

```text
Device | IP | Hostname | Download | Upload | Total RX | Total TX | Last seen
```

---

## 12. Syslog Parser Requirements

The parser must be tolerant.

It should handle:

1. Traditional syslog prefixes.
2. OpenWRT `logread` style messages.
3. Missing hostname.
4. Extra spaces.
5. Logs with partial fields.
6. Unknown tags.

Recommended C++ parser design:

```cpp
struct ParseResult {
    bool matched = false;
    std::string type;
    std::unordered_map<std::string, std::string> fields;
    std::string raw;
};

class LogParser {
public:
    ParseResult parse(std::string_view line) const;

private:
    ParseResult parseWANAttack(std::string_view line) const;
    ParseResult parseDHCP(std::string_view line) const;
    ParseResult parseNetDev(std::string_view line) const;
    ParseResult parseNetTraffic(std::string_view line) const;
};
```

Use `std::string_view` for parsing where practical, but make sure stored values are copied into owned `std::string` fields.

### 12.1 WAN_ATTACK parser

Input example:

```text
kern.warn kernel: WAN_ATTACK: IN=pppoe-wan OUT= MAC= SRC=207.66.160.140 DST=42.114.141.42 LEN=68 TOS=0x00
```

Extract:

```text
type=wan_attack
in_if=pppoe-wan
src_ip=207.66.160.140
dst_ip=42.114.141.42
len=68
raw=<original line>
```

Fields to support if present:

```text
IN
OUT
SRC
DST
SPT
DPT
PROTO
LEN
MAC
TOS
TTL
```

### 12.2 DHCP parser

Input example:

```text
dnsmasq-dhcp[1]: DHCPACK(eth2.vlan10) 192.168.10.157 00:e0:4c:68:02:89 thanhvn-MacBookAir7-2
```

Extract:

```text
event=dhcp_ack
interface=eth2.vlan10
ip=192.168.10.157
mac=00:e0:4c:68:02:89
hostname=thanhvn-MacBookAir7-2
```

Support at least:

```text
DHCPREQUEST
DHCPACK
DHCPDISCOVER
DHCPOFFER
```

### 12.3 NETDEV parser

Input example:

```text
NETDEV: ts=1767000000 mac=00:e0:4c:68:02:89 ip=192.168.10.157 host=thanhvn-MacBookAir7-2 lease_expiry=1767003600 neigh=REACHABLE
```

Extract key-value pairs.

### 12.4 NETTRAFFIC parser

Support two possible formats.

Preferred parsed format:

```text
NETTRAFFIC: ts=1767000000 mac=00:e0:4c:68:02:89 ip=192.168.10.157 rx_bytes=123456789 tx_bytes=9876543
```

Fallback CSV wrapper:

```text
NETTRAFFIC: ts=1767000000 csv=<raw nlbw csv line>
```

For the first MVP, it is acceptable to store raw CSV lines as events and implement exact CSV parsing in a later iteration.

---

## 13. HTTP API

### 13.1 Health

```http
GET /api/health
```

Response:

```json
{
  "ok": true,
  "uptime_seconds": 1234,
  "version": "0.1.0"
}
```

### 13.2 Current summary

```http
GET /api/summary
```

Response:

```json
{
  "active_devices": 12,
  "idle_devices": 4,
  "offline_devices": 3,
  "wan_attack_5m": 28,
  "rx_rate_bps": 1234567,
  "tx_rate_bps": 234567,
  "last_log_ts": "2026-05-29T11:40:00Z"
}
```

### 13.3 Devices

```http
GET /api/devices
```

Response:

```json
[
  {
    "mac": "00:e0:4c:68:02:89",
    "ip": "192.168.10.157",
    "hostname": "thanhvn-MacBookAir7-2",
    "status": "online",
    "last_seen": "2026-05-29T11:40:00Z",
    "rx_rate_bps": 1200000,
    "tx_rate_bps": 250000
  }
]
```

### 13.4 Recent events

```http
GET /api/events?limit=100
```

### 13.5 WAN attacks

```http
GET /api/wan-attacks?limit=100
```

### 13.6 WebSocket

```http
GET /ws
```

Events pushed to clients:

```json
{
  "type": "device_update",
  "payload": {}
}
```

```json
{
  "type": "wan_attack",
  "payload": {}
}
```

```json
{
  "type": "summary_update",
  "payload": {}
}
```

---

## 14. Web Dashboard Requirements

The dashboard should be simple and fast.

### Required panels

1. Status cards:
   - Active devices
   - Idle devices
   - Offline devices
   - WAN attacks in last 5 minutes
   - Current total download/upload rate

2. Active devices table:
   - Status
   - Hostname
   - IP
   - MAC
   - Download
   - Upload
   - Last seen

3. Top talkers:
   - Top 10 devices by current download rate
   - Top 10 devices by current upload rate

4. WAN attack panel:
   - latest source IP
   - destination IP
   - protocol/port if present
   - count per source IP in rolling window

5. Event stream:
   - new DHCP device
   - device offline
   - WAN reconnect
   - WAN attack

### UI constraints

- No heavy frontend framework required.
- Must work on desktop browser.
- Mobile-friendly is nice but not required for MVP.
- Should update without page refresh using WebSocket or polling.
- Frontend static files should be served by the C++ backend.

---

## 15. Memory Safety and Storage Rules

The application must use bounded memory.

Use ring buffers:

```text
recent_events: max 2000
wan_attack_events: max 1000
traffic_points_per_device: max 60
```

Cleanup loop every 60 seconds:

1. Mark devices offline if not seen recently.
2. Remove devices older than `device_keep_ttl_seconds` if offline.
3. Trim event buffers.
4. Trim traffic points.
5. Recompute summary.

No unbounded maps keyed by attacker IP forever.

For attacker counters, keep rolling window buckets:

```text
key: src_ip
window: 5 minutes
cleanup: remove src_ip if no event in 10 minutes
```

C++ implementation rules:

1. Prefer RAII for resource management.
2. Avoid raw owning pointers.
3. Use `std::unique_ptr` or `std::shared_ptr` only when ownership semantics require them.
4. Keep parser code allocation-light but do not sacrifice correctness.
5. Protect shared state accessed by network threads and web handlers.
6. Build with warnings enabled:
   - `-Wall`
   - `-Wextra`
   - `-Wpedantic`
7. Consider sanitizers during development:
   - AddressSanitizer
   - UndefinedBehaviorSanitizer
   - ThreadSanitizer for concurrency debugging

---

## 16. Suggested Repository Structure

```text
openwrt-netmon-lite/
  README.md
  PROJECT_SPEC.md
  CMakeLists.txt
  cmake/
  config.example.yaml
  src/
    main.cpp
    app.cpp
    config.cpp
    syslog_server.cpp
    log_parser.cpp
    state_store.cpp
    traffic.cpp
    web_server.cpp
    ring_buffer.cpp
  include/
    netmon/
      app.hpp
      config.hpp
      syslog_server.hpp
      log_parser.hpp
      state_store.hpp
      traffic.hpp
      web_server.hpp
      ring_buffer.hpp
      types.hpp
  web/
    static/
      index.html
      app.js
      style.css
  openwrt/
    setup-remote-syslog.sh
    netmon-devices.sh
    netmon-traffic.sh
  deployments/
    systemd/
      openwrt-netmon-lite.service
    docker/
      Dockerfile
      docker-compose.yml
  tests/
    parser_tests.cpp
    state_store_tests.cpp
    ring_buffer_tests.cpp
    traffic_tests.cpp
  testdata/
    sample-openwrt.log
    sample-netdev.log
    sample-wan-attack.log
```

---

## 17. Build and Run Requirements

### Dependencies

For Ubuntu/Debian development:

```sh
sudo apt update
sudo apt install -y build-essential cmake pkg-config libboost-system-dev libssl-dev
```

If using Crow from the system package repository or vendored source, document the selected installation method clearly.

If using additional libraries, document them clearly:

```text
nlohmann/json
yaml-cpp or toml++
Crow or Boost.Beast
GoogleTest or Catch2 for tests
```

### Configure and build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

Expected binary:

```text
build/openwrt-netmon-lite
```

### Run

```sh
./build/openwrt-netmon-lite --config ./config.example.yaml
```

### Development build with sanitizers

```sh
cmake -S . -B build-debug \
  -DCMAKE_BUILD_TYPE=Debug \
  -DNETMON_ENABLE_SANITIZERS=ON

cmake --build build-debug -j"$(nproc)"
```

### Test

```sh
ctest --test-dir build --output-on-failure
```

### Send mock syslog message

UDP:

```sh
echo '<13>NETDEV: ts=1767000000 mac=00:e0:4c:68:02:89 ip=192.168.10.157 host=test-device neigh=REACHABLE' | nc -u -w1 127.0.0.1 1514
```

TCP:

```sh
echo '<13>NETDEV: ts=1767000000 mac=00:e0:4c:68:02:89 ip=192.168.10.157 host=test-device neigh=REACHABLE' | nc 127.0.0.1 1514
```

---

## 18. Systemd Service

Create:

```ini
[Unit]
Description=OpenWRT Netmon Lite
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=netmon
Group=netmon
ExecStart=/usr/local/bin/openwrt-netmon-lite --config /etc/openwrt-netmon-lite/config.yaml
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

---

## 19. Security Requirements

1. Bind dashboard to LAN interface only by default.
2. Do not expose dashboard to WAN.
3. Support optional dashboard token.
4. Accept syslog only from trusted router IPs if configured.
5. Do not execute shell commands based on log content.
6. Sanitize all values displayed in the web UI.
7. Avoid storing sensitive long-term browsing/traffic history.
8. Avoid logging raw payload content.
9. Treat every syslog line as untrusted input.
10. Enforce maximum line length for incoming syslog messages.

---

## 20. MVP Milestones

### Milestone 1: C++ syslog receiver

Deliverables:

- UDP syslog listener using Boost.Asio or standalone Asio
- TCP syslog listener optional
- raw log event display in web UI
- `/api/health`

Acceptance:

- `logger -t NETMON_TEST` from OpenWRT appears on dashboard.

### Milestone 2: Device state

Deliverables:

- `NETDEV` parser
- DHCP parser
- in-memory device map
- `/api/devices`
- active device table

Acceptance:

- Devices from `/tmp/dhcp.leases` snapshots appear in dashboard within 60 seconds.

### Milestone 3: WAN attack events

Deliverables:

- `WAN_ATTACK` parser
- recent attack ring buffer
- top attacker source IPs
- `/api/wan-attacks`

Acceptance:

- WAN attack log lines appear in dashboard and counts update.

### Milestone 4: Traffic summary

Deliverables:

- `NETTRAFFIC` parser
- traffic delta calculation
- top talkers panel

Acceptance:

- Per-device upload/download rate appears when traffic snapshots are received.

### Milestone 5: Packaging

Deliverables:

- CMake build
- systemd service
- example config
- OpenWRT scripts
- README setup guide

Acceptance:

- Fresh LAN server can run the app with one compiled binary and one config file.

---

## 21. Testing Requirements

### Unit tests

Write tests for:

1. Key-value parser.
2. DHCP parser.
3. WAN_ATTACK parser.
4. NETDEV parser.
5. Traffic delta calculation.
6. Ring buffer capacity.
7. Device status timeout logic.
8. Trusted router IP filter.
9. Syslog max-line-length handling.
10. Unknown log handling.

### Integration tests

Use sample logs in `testdata/`.

Test scenario:

1. Start server.
2. Send sample syslog lines.
3. Query `/api/devices`.
4. Query `/api/events`.
5. Query `/api/wan-attacks`.
6. Verify expected JSON.

Suggested C++ test frameworks:

```text
GoogleTest
Catch2
doctest
```

---

## 22. Example Test Logs

```text
<13>May 29 11:40:31 openwrt-main dnsmasq-dhcp[1]: DHCPACK(eth2.vlan10) 192.168.10.157 00:e0:4c:68:02:89 thanhvn-MacBookAir7-2
<13>May 29 11:40:35 openwrt-main NETDEV: ts=1767000000 mac=00:e0:4c:68:02:89 ip=192.168.10.157 host=thanhvn-MacBookAir7-2 lease_expiry=1767003600 neigh=REACHABLE
<13>May 29 11:41:03 openwrt-main kernel: WAN_ATTACK: IN=pppoe-wan OUT= MAC= SRC=172.217.194.139 DST=42.114.141.42 LEN=97 TOS=0x00
<13>May 29 11:45:00 openwrt-main NETTRAFFIC: ts=1767000300 mac=00:e0:4c:68:02:89 ip=192.168.10.157 rx_bytes=123456789 tx_bytes=9876543
```

---

## 23. Implementation Notes for Coding Agent

Follow these rules:

1. Implement the MVP in small commits or small steps.
2. Prefer simple C++ code over complex abstractions.
3. Keep dependencies minimal.
4. Do not introduce persistent databases unless explicitly requested.
5. Do not add Prometheus/Loki/ELK in the MVP.
6. Do not require root for the server by default.
7. Use port `1514` for syslog by default.
8. Use port `8080` for the dashboard by default.
9. Provide clear setup instructions.
10. Provide mock data so the dashboard can be tested without a real router.
11. Add comments around parser edge cases.
12. Treat all incoming log data as untrusted input.
13. Avoid global mutable state unless it is wrapped inside a clear application/state object.
14. Keep business logic independent from the web framework.
15. Keep parser and state-store code easy to unit test.
16. Prefer `std::chrono` for time logic.
17. Prefer `std::string_view` for parsing input, but copy data before storing it.
18. Do not over-optimize before the MVP works.

---

## 24. Future Enhancements

Possible later additions:

1. Optional SQLite mode with strict retention.
2. Optional Prometheus exporter endpoint.
3. Optional Grafana dashboard.
4. Optional Telegram alerts.
5. Optional nftables auto-block integration.
6. OUI vendor lookup from local database.
7. Device alias mapping.
8. Import/export known devices.
9. Multi-router support.
10. WiFi signal strength if OpenWRT is AP.
11. Flow export support using softflowd.
12. Anomaly detection based on rolling baseline.
13. Linux netlink integration.
14. nftables counter reader.
15. eBPF-based local sensor for non-OpenWRT Linux gateways.

---

## 25. References

These references are included for the coding agent to verify assumptions and implementation details:

1. OpenWRT logging and remote syslog options:  
   https://openwrt.org/docs/guide-user/base-system/log.essentials

2. OpenWRT system configuration:  
   https://openwrt.org/docs/guide-user/base-system/system_configuration

3. OpenWRT bandwidth monitoring guide:  
   https://openwrt.org/docs/guide-user/services/network_monitoring/bwmon

4. nlbwmon project:  
   https://github.com/jow-/nlbwmon

5. OpenWRT ubus documentation:  
   https://openwrt.org/docs/techref/ubus

6. Home Assistant OpenWRT ubus presence detection notes:  
   https://www.home-assistant.io/integrations/ubus/

7. Boost.Asio documentation:  
   https://www.boost.org/doc/libs/release/doc/html/boost_asio.html

8. Standalone Asio documentation:  
   https://think-async.com/

9. Crow C++ web framework:  
   https://crowcpp.org/master/

10. Prometheus storage retention reference, useful only if optional Prometheus mode is added later:  
   https://prometheus.io/docs/prometheus/latest/storage/

---

## 26. Final MVP Definition

The first working version is complete when:

1. OpenWRT sends syslog to the LAN server.
2. The C++ server dashboard opens at:

```text
http://<server-ip>:8080
```

3. The dashboard shows:
   - active devices
   - recent DHCP events
   - WAN attack events
   - basic traffic summary if `NETTRAFFIC` is available

4. The server does not grow disk usage over time.
5. All state is kept in RAM by default.
6. The project has clear README instructions for both OpenWRT and server setup.
7. The project builds with CMake.
8. Core parser/state logic is covered by C++ unit tests.
