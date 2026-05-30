#include "netmon/config.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>

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

void setIntIfEnv(const char* name, int& value) {
  if (const char* env = std::getenv(name); env != nullptr) {
    value = parseInt(env, value);
  }
}

void setSizeIfEnv(const char* name, std::size_t& value) {
  if (const char* env = std::getenv(name); env != nullptr) {
    value = static_cast<std::size_t>(parseUint64(env, value));
  }
}

std::string sectionPath(const std::vector<std::pair<int, std::string>>& stack) {
  std::ostringstream out;
  for (std::size_t i = 0; i < stack.size(); ++i) {
    if (i != 0) {
      out << '.';
    }
    out << stack[i].second;
  }
  return out.str();
}

int leadingSpaces(const std::string& line) {
  int count = 0;
  for (const char ch : line) {
    if (ch != ' ') {
      break;
    }
    ++count;
  }
  return count;
}

void popSectionsAtOrAbove(std::vector<std::pair<int, std::string>>& stack, int indent) {
  while (!stack.empty() && indent <= stack.back().first) {
    stack.pop_back();
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
  } else if (section == "storage.sqlite") {
    if (key == "path") {
      config.sqlite_path = value;
    } else if (key == "retention_days") {
      config.sqlite_retention_days = parseInt(value, config.sqlite_retention_days);
    } else if (key == "max_db_mb") {
      config.sqlite_max_db_mb = parseInt(value, config.sqlite_max_db_mb);
    } else if (key == "max_events") {
      config.sqlite_max_events = static_cast<std::size_t>(parseUint64(value, config.sqlite_max_events));
    } else if (key == "max_traffic_points_per_device") {
      config.sqlite_max_traffic_points_per_device = static_cast<std::size_t>(parseUint64(value, config.sqlite_max_traffic_points_per_device));
    } else if (key == "vacuum_on_start") {
      config.sqlite_vacuum_on_start = parseBool(value, config.sqlite_vacuum_on_start);
    }
  } else if (section == "metrics") {
    if (key == "prometheus_enabled") {
      config.prometheus_enabled = parseBool(value, config.prometheus_enabled);
    } else if (key == "prometheus_path") {
      config.prometheus_path = value.empty() || value.front() == '/' ? value : "/" + value;
    } else if (key == "include_device_labels") {
      config.prometheus_include_device_labels = parseBool(value, config.prometheus_include_device_labels);
    } else if (key == "device_label_mode") {
      config.prometheus_device_label_mode = value;
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
      std::vector<std::pair<int, std::string>> section_stack;
      std::string line;
      while (std::getline(input, line)) {
        const int indent = leadingSpaces(line);
        std::string text = stripInlineComment(line);
        if (text.empty()) {
          continue;
        }

        if (text.rfind("-", 0) == 0) {
          if (list_key == "security.trusted_router_ips") {
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

        popSectionsAtOrAbove(section_stack, indent);
        section = sectionPath(section_stack);

        if (section == "security" && key == "trusted_router_ips" && value.empty()) {
          config.trusted_router_ips.clear();
          list_key = "security.trusted_router_ips";
          continue;
        }
        if (value.empty()) {
          section_stack.push_back({indent, key});
          section = sectionPath(section_stack);
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
  setIfEnv("NETMON_STORAGE_MODE", config.storage_mode);
  setIfEnv("NETMON_SQLITE_PATH", config.sqlite_path);
  setIntIfEnv("NETMON_SQLITE_RETENTION_DAYS", config.sqlite_retention_days);
  setIntIfEnv("NETMON_SQLITE_MAX_DB_MB", config.sqlite_max_db_mb);
  setSizeIfEnv("NETMON_SQLITE_MAX_EVENTS", config.sqlite_max_events);
  setSizeIfEnv("NETMON_SQLITE_MAX_TRAFFIC_POINTS_PER_DEVICE", config.sqlite_max_traffic_points_per_device);
  setBoolIfEnv("NETMON_SQLITE_VACUUM_ON_START", config.sqlite_vacuum_on_start);
  setBoolIfEnv("NETMON_PROMETHEUS_ENABLED", config.prometheus_enabled);
  setIfEnv("NETMON_PROMETHEUS_PATH", config.prometheus_path);
  if (!config.prometheus_path.empty() && config.prometheus_path.front() != '/') {
    config.prometheus_path = "/" + config.prometheus_path;
  }
  setBoolIfEnv("NETMON_PROMETHEUS_INCLUDE_DEVICE_LABELS", config.prometheus_include_device_labels);
  setIfEnv("NETMON_PROMETHEUS_DEVICE_LABEL_MODE", config.prometheus_device_label_mode);

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
