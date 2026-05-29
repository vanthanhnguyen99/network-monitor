#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace netmon {

struct Config {
  std::string http_addr = "0.0.0.0:8080";
  std::string syslog_udp_addr = "0.0.0.0:1514";
  std::string syslog_tcp_addr = "0.0.0.0:1514";
  bool enable_udp = true;
  bool enable_tcp = false;

  int device_online_ttl_seconds = 180;
  int device_idle_ttl_seconds = 600;
  int device_keep_ttl_seconds = 3600;
  std::size_t max_events = 2000;
  std::size_t max_attack_events = 1000;
  std::size_t max_traffic_points_per_device = 60;
  int traffic_rate_hold_seconds = 75;

  std::string storage_mode = "memory";
  bool enable_debug_file_log = false;
  std::string debug_log_path = "./netmon-debug.log";
  int debug_log_max_mb = 10;

  bool bind_lan_only = true;
  std::string dashboard_token;
  std::vector<std::string> trusted_router_ips;
  std::size_t max_syslog_line_length = 4096;

  std::string web_root = "./web/static";
};

Config loadConfig(const std::string& path);
void applyEnvironmentOverrides(Config& config);

}  // namespace netmon
