#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unistd.h>

#include "netmon/config.hpp"
#include "netmon/log_parser.hpp"
#include "netmon/net_utils.hpp"
#include "netmon/prometheus_exporter.hpp"
#include "netmon/ring_buffer.hpp"
#include "netmon/runtime_stats.hpp"
#include "netmon/sqlite_store.hpp"
#include "netmon/state_store.hpp"
#include "netmon/utils.hpp"
#include "netmon/web_server.hpp"

namespace {

int failures = 0;

#define CHECK(expr)                                                                 \
  do {                                                                              \
    if (!(expr)) {                                                                  \
      std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " #expr \
                << '\n';                                                           \
      ++failures;                                                                   \
    }                                                                               \
  } while (false)

netmon::Config testConfig() {
  netmon::Config config;
  config.device_online_ttl_seconds = 180;
  config.device_idle_ttl_seconds = 600;
  config.device_keep_ttl_seconds = 3600;
  config.max_events = 4;
  config.max_attack_events = 4;
  config.max_traffic_points_per_device = 2;
  config.traffic_rate_hold_seconds = 30;
  return config;
}

void testKeyValueParser() {
  const auto fields = netmon::LogParser::parseKeyValues("ts=1767000000 mac=AA:BB:CC:DD:EE:FF host=desk neigh=REACHABLE");
  CHECK(fields.at("ts") == "1767000000");
  CHECK(fields.at("mac") == "AA:BB:CC:DD:EE:FF");
  CHECK(fields.at("host") == "desk");
  CHECK(fields.at("neigh") == "REACHABLE");
}

void testDHCPParser() {
  netmon::LogParser parser;
  const auto result = parser.parse("<13>May 29 11:40:31 openwrt-main dnsmasq-dhcp[1]: DHCPACK(eth2.vlan10) 192.168.10.157 00:e0:4c:68:02:89 thanhvn-MacBookAir7-2");
  CHECK(result.matched);
  CHECK(result.type == "dhcp");
  CHECK(result.fields.at("event") == "dhcp_ack");
  CHECK(result.fields.at("interface") == "eth2.vlan10");
  CHECK(result.fields.at("ip") == "192.168.10.157");
  CHECK(result.fields.at("mac") == "00:e0:4c:68:02:89");
  CHECK(result.fields.at("hostname") == "thanhvn-MacBookAir7-2");
}

void testWANAttackParser() {
  netmon::LogParser parser;
  const auto result = parser.parse("kern.warn kernel: WAN_ATTACK: IN=pppoe-wan OUT= MAC= SRC=207.66.160.140 DST=42.114.141.42 LEN=68 TOS=0x00 PROTO=TCP DPT=443");
  CHECK(result.matched);
  CHECK(result.type == "wan_attack");
  CHECK(result.fields.at("in_if") == "pppoe-wan");
  CHECK(result.fields.at("src_ip") == "207.66.160.140");
  CHECK(result.fields.at("dst_ip") == "42.114.141.42");
  CHECK(result.fields.at("len") == "68");
  CHECK(result.fields.at("proto") == "TCP");
  CHECK(result.fields.at("dst_port") == "443");
}

void testNetDevParser() {
  netmon::LogParser parser;
  const auto result = parser.parse("NETDEV: ts=1767000000 mac=00:E0:4C:68:02:89 ip=192.168.10.157 host=test-device lease_expiry=1767003600 neigh=REACHABLE");
  CHECK(result.matched);
  CHECK(result.type == "netdev");
  CHECK(result.fields.at("mac") == "00:e0:4c:68:02:89");
  CHECK(result.fields.at("ip") == "192.168.10.157");
  CHECK(result.fields.at("hostname") == "test-device");
  CHECK(result.fields.at("neigh") == "REACHABLE");
}

void testNetTrafficCsvParser() {
  netmon::LogParser parser;
  const auto grouped = parser.parse("NETTRAFFIC: ts=1767000000 csv=00:e0:4c:68:02:89 12 100000 80 40000 50");
  CHECK(grouped.matched);
  CHECK(grouped.type == "nettraffic");
  CHECK(grouped.fields.at("mac") == "00:e0:4c:68:02:89");
  CHECK(grouped.fields.at("rx_bytes") == "100000");
  CHECK(grouped.fields.at("tx_bytes") == "40000");

  const auto raw = parser.parse("NETTRAFFIC: ts=1767000000 csv=IPv4 192.168.10.157 00:e0:4c:68:02:89 HTTPS 7 250000 120 99000 70");
  CHECK(raw.matched);
  CHECK(raw.fields.at("ip") == "192.168.10.157");
  CHECK(raw.fields.at("mac") == "00:e0:4c:68:02:89");
  CHECK(raw.fields.at("rx_bytes") == "250000");
  CHECK(raw.fields.at("tx_bytes") == "99000");
}

void testNetIfaceParser() {
  netmon::LogParser parser;
  const auto result = parser.parse("NETIFACE: ts=1767000000 if=pppoe-wan rx_bytes=120000 tx_bytes=45000");
  CHECK(result.matched);
  CHECK(result.type == "netiface");
  CHECK(result.fields.at("interface") == "pppoe-wan");
  CHECK(result.fields.at("rx_bytes") == "120000");
  CHECK(result.fields.at("tx_bytes") == "45000");
}

void testTrafficDelta() {
  netmon::StateStore store(testConfig());
  netmon::TrafficSnapshot first;
  first.mac = "00:e0:4c:68:02:89";
  first.ip = "192.168.10.157";
  first.ts = netmon::fromUnixSeconds(100);
  first.rx_bytes = 1000;
  first.tx_bytes = 2000;
  store.updateTraffic(first);

  netmon::TrafficSnapshot second = first;
  second.ts = netmon::fromUnixSeconds(160);
  second.rx_bytes = 1600;
  second.tx_bytes = 2600;
  store.updateTraffic(second);

  const auto devices = store.devices();
  CHECK(devices.size() == 1);
  CHECK(std::fabs(devices[0].rx_rate_bps - 80.0) < 0.001);
  CHECK(std::fabs(devices[0].tx_rate_bps - 80.0) < 0.001);
}

void testTrafficDuplicateSamplesHoldRate() {
  netmon::StateStore store(testConfig());
  netmon::TrafficSnapshot first;
  first.mac = "00:e0:4c:68:02:89";
  first.ts = netmon::fromUnixSeconds(100);
  first.rx_bytes = 1000;
  first.tx_bytes = 2000;
  store.updateTraffic(first);

  netmon::TrafficSnapshot second = first;
  second.ts = netmon::fromUnixSeconds(160);
  second.rx_bytes = 1600;
  second.tx_bytes = 2600;
  store.updateTraffic(second);

  netmon::TrafficSnapshot duplicate = second;
  duplicate.ts = netmon::fromUnixSeconds(165);
  store.updateTraffic(duplicate);
  auto devices = store.devices();
  CHECK(std::fabs(devices[0].rx_rate_bps - 80.0) < 0.001);
  CHECK(std::fabs(devices[0].tx_rate_bps - 80.0) < 0.001);

  netmon::TrafficSnapshot expired = second;
  expired.ts = netmon::fromUnixSeconds(200);
  store.updateTraffic(expired);
  devices = store.devices();
  CHECK(devices[0].rx_rate_bps == 0.0);
  CHECK(devices[0].tx_rate_bps == 0.0);

  netmon::TrafficSnapshot third = second;
  third.ts = netmon::fromUnixSeconds(220);
  third.rx_bytes = 2200;
  third.tx_bytes = 3200;
  store.updateTraffic(third);
  devices = store.devices();
  CHECK(std::fabs(devices[0].rx_rate_bps - 80.0) < 0.001);
  CHECK(std::fabs(devices[0].tx_rate_bps - 80.0) < 0.001);
}

void testInterfaceRatePreferredForSummary() {
  netmon::StateStore store(testConfig());
  const auto now = netmon::nowSystem();

  netmon::TrafficSnapshot first_device;
  first_device.mac = "00:e0:4c:68:02:89";
  first_device.ts = now - std::chrono::seconds(2);
  first_device.rx_bytes = 1000;
  first_device.tx_bytes = 1000;
  store.updateTraffic(first_device);

  netmon::TrafficSnapshot second_device = first_device;
  second_device.ts = now - std::chrono::seconds(1);
  second_device.rx_bytes = 1100;
  second_device.tx_bytes = 1100;
  store.updateTraffic(second_device);

  netmon::InterfaceSnapshot first_iface;
  first_iface.interface_name = "pppoe-wan";
  first_iface.ts = now - std::chrono::seconds(1);
  first_iface.rx_bytes = 5000;
  first_iface.tx_bytes = 10000;
  store.updateInterface(first_iface);

  netmon::InterfaceSnapshot second_iface = first_iface;
  second_iface.ts = now;
  second_iface.rx_bytes = 7000;
  second_iface.tx_bytes = 13000;
  store.updateInterface(second_iface);

  const auto summary = store.summary();
  CHECK(summary.rate_source == "interface");
  CHECK(summary.rate_interface == "pppoe-wan");
  CHECK(std::fabs(summary.rx_rate_bps - 16000.0) < 0.001);
  CHECK(std::fabs(summary.tx_rate_bps - 24000.0) < 0.001);
}

void testRingBufferCapacity() {
  netmon::RingBuffer<int> buffer(3);
  buffer.push(1);
  buffer.push(2);
  buffer.push(3);
  buffer.push(4);
  const auto items = buffer.items();
  CHECK(items.size() == 3);
  CHECK(items[0] == 2);
  CHECK(items[2] == 4);
}

void testDeviceTimeout() {
  netmon::StateStore store(testConfig());
  const auto now = netmon::nowSystem();
  netmon::DeviceState device;
  device.mac = "00:e0:4c:68:02:89";
  device.ip = "192.168.10.157";
  device.last_seen = now - std::chrono::seconds(700);
  store.updateDevice(device);
  store.cleanup(now);
  const auto devices = store.devices();
  CHECK(devices.size() == 1);
  CHECK(devices[0].status == netmon::DeviceStatus::Offline);
}

void testTrustedRouterFilter() {
  CHECK(netmon::isTrustedPeer({}, "10.0.0.1"));
  CHECK(netmon::isTrustedPeer({"192.168.10.1"}, "192.168.10.1"));
  CHECK(!netmon::isTrustedPeer({"192.168.10.1"}, "192.168.10.2"));
}

void testMaxLineLength() {
  CHECK(netmon::boundedLine("abc", 3).has_value());
  CHECK(!netmon::boundedLine("abcd", 3).has_value());
}

void testUnknownLog() {
  netmon::LogParser parser;
  const auto result = parser.parse("totally custom log line");
  CHECK(!result.matched);
  CHECK(result.type == "unknown");
}

void testWebSocketAccept() {
  CHECK(netmon::websocketAcceptKey("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

void testNestedConfigOptions() {
  const std::string path = "/tmp/openwrt-netmon-lite-config-test-" + std::to_string(getpid()) + ".yaml";
  {
    std::ofstream out(path);
    out << "storage:\n"
        << "  mode: \"sqlite\"\n"
        << "  sqlite:\n"
        << "    path: \"/tmp/netmon.db\"\n"
        << "    retention_days: 3\n"
        << "    max_db_mb: 9\n"
        << "    max_events: 12\n"
        << "    max_traffic_points_per_device: 13\n"
        << "    vacuum_on_start: true\n"
        << "metrics:\n"
        << "  prometheus_enabled: true\n"
        << "  prometheus_path: \"metrics\"\n"
        << "  include_device_labels: true\n"
        << "  device_label_mode: \"raw_mac\"\n";
  }

  const netmon::Config config = netmon::loadConfig(path);
  CHECK(config.storage_mode == "sqlite");
  CHECK(config.sqlite_path == "/tmp/netmon.db");
  CHECK(config.sqlite_retention_days == 3);
  CHECK(config.sqlite_max_db_mb == 9);
  CHECK(config.sqlite_max_events == 12);
  CHECK(config.sqlite_max_traffic_points_per_device == 13);
  CHECK(config.sqlite_vacuum_on_start);
  CHECK(config.prometheus_enabled);
  CHECK(config.prometheus_path == "/metrics");
  CHECK(config.prometheus_include_device_labels);
  CHECK(config.prometheus_device_label_mode == "raw_mac");
  std::remove(path.c_str());
}

void testPrometheusExporter() {
  netmon::Config config = testConfig();
  netmon::StateStore store(config);
  netmon::RuntimeStats stats;

  netmon::DeviceState device;
  device.mac = "00:e0:4c:68:02:89";
  device.ip = "192.168.10.157";
  device.last_seen = netmon::nowSystem();
  device.source = "netdev";
  store.updateDevice(device);

  stats.recordSyslogMessage("dhcp");
  stats.recordParseError();
  stats.recordWANAttack();

  const std::string body = netmon::renderPrometheusMetrics(config, store, stats, std::chrono::steady_clock::now() - std::chrono::seconds(10));
  CHECK(body.find("openwrt_netmon_up 1") != std::string::npos);
  CHECK(body.find("openwrt_netmon_syslog_messages_total{type=\"dhcp\"} 1") != std::string::npos);
  CHECK(body.find("openwrt_netmon_parse_errors_total 1") != std::string::npos);
  CHECK(body.find("openwrt_netmon_devices{status=\"online\"} 1") != std::string::npos);
  CHECK(body.find("openwrt_netmon_wan_attacks_total 1") != std::string::npos);
}

void testSqliteStorePersistenceAndRetention() {
  const std::string base = "/tmp/openwrt-netmon-lite-sqlite-test-" + std::to_string(getpid()) + ".db";
  std::remove(base.c_str());
  std::remove((base + "-wal").c_str());
  std::remove((base + "-shm").c_str());

  netmon::Config config = testConfig();
  config.storage_mode = "sqlite";
  config.sqlite_path = base;
  config.sqlite_retention_days = 1;
  config.sqlite_max_db_mb = 16;
  config.sqlite_max_events = 1;
  config.sqlite_max_traffic_points_per_device = 8;

  try {
    netmon::SqliteStore sqlite(config);
    netmon::StateStore state(config);

    netmon::DeviceState device;
    device.mac = "00:e0:4c:68:02:89";
    device.ip = "192.168.10.157";
    device.hostname = "test-device";
    device.last_seen = netmon::nowSystem();
    device.last_traffic = device.last_seen;
    device.last_rate = device.last_seen;
    device.source = "netdev";
    device.rx_bytes_total = 1200;
    device.tx_bytes_total = 800;
    device.rx_rate_bps = 320.0;
    device.tx_rate_bps = 160.0;
    state.updateDevice(device);
    sqlite.upsertDevices(state.devices());

    netmon::TrafficSnapshot old_traffic;
    old_traffic.mac = device.mac;
    old_traffic.ip = device.ip;
    old_traffic.ts = netmon::nowSystem() - std::chrono::hours(30);
    old_traffic.rx_bytes = 9000;
    old_traffic.tx_bytes = 9000;
    sqlite.insertTraffic(old_traffic);

    netmon::TrafficSnapshot first_traffic = old_traffic;
    first_traffic.ts = netmon::nowSystem() - std::chrono::hours(3);
    first_traffic.rx_bytes = 100;
    first_traffic.tx_bytes = 50;
    sqlite.insertTraffic(first_traffic);

    netmon::TrafficSnapshot second_traffic = first_traffic;
    second_traffic.ts = netmon::nowSystem() - std::chrono::hours(2);
    second_traffic.rx_bytes = 500;
    second_traffic.tx_bytes = 150;
    sqlite.insertTraffic(second_traffic);

    netmon::TrafficSnapshot reset_traffic = second_traffic;
    reset_traffic.ts = netmon::nowSystem() - std::chrono::hours(1);
    reset_traffic.rx_bytes = 50;
    reset_traffic.tx_bytes = 20;
    sqlite.insertTraffic(reset_traffic);

    netmon::TrafficSnapshot latest_traffic = reset_traffic;
    latest_traffic.ts = netmon::nowSystem();
    latest_traffic.rx_bytes = 90;
    latest_traffic.tx_bytes = 30;
    sqlite.insertTraffic(latest_traffic);

    netmon::Event old_event;
    old_event.id = "old";
    old_event.ts = netmon::nowSystem() - std::chrono::hours(48);
    old_event.type = "device";
    old_event.message = "old";
    sqlite.insertEvent(old_event);

    netmon::Event new_event;
    new_event.id = "new";
    new_event.ts = netmon::nowSystem();
    new_event.type = "device";
    new_event.message = "new";
    sqlite.insertEvent(new_event);
    sqlite.applyRetention();

    netmon::StateStore restored(config);
    sqlite.loadInto(restored);
    CHECK(restored.devices().size() == 1);
    CHECK(restored.devices()[0].hostname == "test-device");
    CHECK(restored.devices()[0].last_traffic.time_since_epoch().count() != 0);
    CHECK(restored.devices()[0].last_rate.time_since_epoch().count() != 0);
    CHECK(std::fabs(restored.devices()[0].rx_rate_bps - 320.0) < 0.001);
    const auto events = restored.recentEvents(10);
    CHECK(events.size() == 1);
    CHECK(events[0].id == "new");
    const auto totals = sqlite.deviceTrafficTotals(std::chrono::hours(24), 10);
    CHECK(totals.size() == 1);
    CHECK(totals[0].rx_bytes == 490);
    CHECK(totals[0].tx_bytes == 130);
    CHECK(totals[0].samples == 4);
  } catch (const std::runtime_error& ex) {
    const std::string message = ex.what();
    if (message.find("requires libsqlite3") == std::string::npos) {
      std::cerr << "unexpected sqlite error: " << message << '\n';
      ++failures;
    } else {
      std::cerr << "sqlite test skipped: " << message << '\n';
    }
  }

  std::remove(base.c_str());
  std::remove((base + "-wal").c_str());
  std::remove((base + "-shm").c_str());
}

}  // namespace

int main() {
  testKeyValueParser();
  testDHCPParser();
  testWANAttackParser();
  testNetDevParser();
  testNetTrafficCsvParser();
  testNetIfaceParser();
  testTrafficDelta();
  testTrafficDuplicateSamplesHoldRate();
  testInterfaceRatePreferredForSummary();
  testRingBufferCapacity();
  testDeviceTimeout();
  testTrustedRouterFilter();
  testMaxLineLength();
  testUnknownLog();
  testWebSocketAccept();
  testNestedConfigOptions();
  testPrometheusExporter();
  testSqliteStorePersistenceAndRetention();

  if (failures != 0) {
    std::cerr << failures << " test failure(s)\n";
    return EXIT_FAILURE;
  }
  std::cout << "all tests passed\n";
  return EXIT_SUCCESS;
}
