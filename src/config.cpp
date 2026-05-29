#include "netmon/config.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>

#include "netmon/utils.hpp"

namespace netmon {
namespace {

void setIfEnv(const char* name, std::string& value) {
  if (const char* env = std::getenv(name); env != nullptr) {
    value = env;
  }
}

void setBoolIfEnv(const char* name, bool& value) {
  if (const char* env = std::getenv(name); env != nullptr) {
    value = parseBool(env, value);
  }
}

void applyValue(Config& config, const std::string& section, const std::string& key, const std::string& raw_value) {
  const std::string value = stripQuotes(stripInlineComment(raw_value));
  if (section == "server") {
    if (key == "http_addr") {
      config.http_addr = value;
    } else if (key == "syslog_udp_addr") {
      config.syslog_udp_addr = value;
    } else if (key == "syslog_tcp_addr") {
      config.syslog_tcp_addr = value;
    } else if (key == "enable_udp") {
      config.enable_udp = parseBool(value, config.enable_udp);
    } else if (key == "enable_tcp") {
      config.enable_tcp = parseBool(value, config.enable_tcp);
    }
  } else if (section == "state") {
    if (key == "device_online_ttl_seconds") {
      config.device_online_ttl_seconds = parseInt(value, config.device_online_ttl_seconds);
    } else if (key == "device_idle_ttl_seconds") {
      config.device_idle_ttl_seconds = parseInt(value, config.device_idle_ttl_seconds);
    } else if (key == "device_keep_ttl_seconds") {
      config.device_keep_ttl_seconds = parseInt(value, config.device_keep_ttl_seconds);
    } else if (key == "max_events") {
      config.max_events = static_cast<std::size_t>(parseUint64(value, config.max_events));
    } else if (key == "max_attack_events") {
      config.max_attack_events = static_cast<std::size_t>(parseUint64(value, config.max_attack_events));
    } else if (key == "max_traffic_points_per_device") {
      config.max_traffic_points_per_device = static_cast<std::size_t>(parseUint64(value, config.max_traffic_points_per_device));
    } else if (key == "traffic_rate_hold_seconds") {
      config.traffic_rate_hold_seconds = parseInt(value, config.traffic_rate_hold_seconds);
    }
  } else if (section == "storage") {
    if (key == "mode") {
      config.storage_mode = value;
    } else if (key == "enable_debug_file_log") {
      config.enable_debug_file_log = parseBool(value, config.enable_debug_file_log);
    } else if (key == "debug_log_path") {
      config.debug_log_path = value;
    } else if (key == "debug_log_max_mb") {
      config.debug_log_max_mb = parseInt(value, config.debug_log_max_mb);
    }
  } else if (section == "security") {
    if (key == "bind_lan_only") {
      config.bind_lan_only = parseBool(value, config.bind_lan_only);
    } else if (key == "dashboard_token") {
      config.dashboard_token = value;
    } else if (key == "max_syslog_line_length") {
      config.max_syslog_line_length = static_cast<std::size_t>(parseUint64(value, config.max_syslog_line_length));
    }
  } else if (section == "web") {
    if (key == "root") {
      config.web_root = value;
    }
  }
}

}  // namespace

Config loadConfig(const std::string& path) {
  Config config;
  if (!path.empty()) {
    std::ifstream input(path);
    if (!input) {
      std::cerr << "config: could not open " << path << ", using defaults\n";
    } else {
      std::string section;
      std::string list_key;
      std::string line;
      while (std::getline(input, line)) {
        std::string text = stripInlineComment(line);
        if (text.empty()) {
          continue;
        }

        if (text.rfind("-", 0) == 0) {
          if (section == "security" && list_key == "trusted_router_ips") {
            std::string item = trim(text.substr(1));
            item = stripQuotes(stripInlineComment(item));
            if (!item.empty()) {
              config.trusted_router_ips.push_back(item);
            }
          }
          continue;
        }

        const std::size_t colon = text.find(':');
        if (colon == std::string::npos) {
          continue;
        }

        std::string key = trim(text.substr(0, colon));
        std::string value = trim(text.substr(colon + 1));
        if (section == "security" && key == "trusted_router_ips") {
          config.trusted_router_ips.clear();
          list_key = key;
          continue;
        }
        if (value.empty()) {
          section = key;
          list_key.clear();
          continue;
        }

        list_key.clear();
        applyValue(config, section, key, value);
      }
    }
  }

  applyEnvironmentOverrides(config);
  return config;
}

void applyEnvironmentOverrides(Config& config) {
  setIfEnv("NETMON_HTTP_ADDR", config.http_addr);
  setIfEnv("NETMON_SYSLOG_UDP_ADDR", config.syslog_udp_addr);
  setIfEnv("NETMON_SYSLOG_TCP_ADDR", config.syslog_tcp_addr);
  setBoolIfEnv("NETMON_ENABLE_UDP", config.enable_udp);
  setBoolIfEnv("NETMON_ENABLE_TCP", config.enable_tcp);
  setIfEnv("NETMON_DASHBOARD_TOKEN", config.dashboard_token);
  setIfEnv("NETMON_WEB_ROOT", config.web_root);

  if (const char* env = std::getenv("NETMON_TRUSTED_ROUTER_IPS"); env != nullptr) {
    config.trusted_router_ips.clear();
    for (const std::string& item : split(env, ',')) {
      const std::string ip = trim(item);
      if (!ip.empty()) {
        config.trusted_router_ips.push_back(ip);
      }
    }
  }
}

}  // namespace netmon
