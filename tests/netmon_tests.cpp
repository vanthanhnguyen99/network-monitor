#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "netmon/config.hpp"
#include "netmon/log_parser.hpp"
#include "netmon/net_utils.hpp"
#include "netmon/ring_buffer.hpp"
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

}  // namespace

int main() {
  testKeyValueParser();
  testDHCPParser();
  testWANAttackParser();
  testNetDevParser();
  testNetTrafficCsvParser();
  testTrafficDelta();
  testTrafficDuplicateSamplesHoldRate();
  testRingBufferCapacity();
  testDeviceTimeout();
  testTrustedRouterFilter();
  testMaxLineLength();
  testUnknownLog();
  testWebSocketAccept();

  if (failures != 0) {
    std::cerr << failures << " test failure(s)\n";
    return EXIT_FAILURE;
  }
  std::cout << "all tests passed\n";
  return EXIT_SUCCESS;
}
