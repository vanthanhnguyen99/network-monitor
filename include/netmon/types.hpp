#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace netmon {

enum class DeviceStatus {
  Online,
  Idle,
  Offline,
  Unknown,
};

enum class EventSeverity {
  Info,
  Warning,
  Critical,
};

struct DeviceState {
  std::string mac;
  std::string ip;
  std::string hostname;
  std::string interface_name;
  std::string source;
  std::string neigh_state;

  DeviceStatus status = DeviceStatus::Unknown;

  std::chrono::system_clock::time_point first_seen{};
  std::chrono::system_clock::time_point last_seen{};
  std::chrono::system_clock::time_point last_dhcp{};
  std::chrono::system_clock::time_point last_traffic{};
  std::chrono::system_clock::time_point last_rate{};

  std::uint64_t rx_bytes_total = 0;
  std::uint64_t tx_bytes_total = 0;
  double rx_rate_bps = 0.0;
  double tx_rate_bps = 0.0;

  std::vector<std::string> tags;
};

struct TrafficSnapshot {
  std::string mac;
  std::string ip;
  std::chrono::system_clock::time_point ts{};
  std::uint64_t rx_bytes = 0;
  std::uint64_t tx_bytes = 0;
};

struct InterfaceSnapshot {
  std::string interface_name;
  std::chrono::system_clock::time_point ts{};
  std::uint64_t rx_bytes = 0;
  std::uint64_t tx_bytes = 0;
};

struct InterfaceState {
  std::string interface_name;
  std::chrono::system_clock::time_point last_seen{};
  std::chrono::system_clock::time_point last_rate{};
  std::uint64_t rx_bytes_total = 0;
  std::uint64_t tx_bytes_total = 0;
  double rx_rate_bps = 0.0;
  double tx_rate_bps = 0.0;
};

struct Event {
  std::string id;
  std::chrono::system_clock::time_point ts{};
  std::string type;
  EventSeverity severity = EventSeverity::Info;
  std::string source;
  std::string message;
  std::unordered_map<std::string, std::string> fields;
};

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

struct Summary {
  std::size_t active_devices = 0;
  std::size_t idle_devices = 0;
  std::size_t offline_devices = 0;
  std::size_t unknown_devices = 0;
  std::size_t wan_attack_5m = 0;
  double rx_rate_bps = 0.0;
  double tx_rate_bps = 0.0;
  std::string rate_source = "devices";
  std::string rate_interface;
  std::chrono::system_clock::time_point last_interface_ts{};
  std::chrono::system_clock::time_point last_log_ts{};
};

std::string toString(DeviceStatus status);
std::string toString(EventSeverity severity);

}  // namespace netmon
