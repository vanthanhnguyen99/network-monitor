#include "netmon/prometheus_exporter.hpp"

#include <iomanip>
#include <sstream>

#include "netmon/utils.hpp"

namespace netmon {
namespace {

std::string labelEscape(const std::string& value) {
  std::string out;
  out.reserve(value.size() + 8);
  for (const char ch : value) {
    switch (ch) {
      case '\\':
        out += "\\\\";
        break;
      case '"':
        out += "\\\"";
        break;
      case '\n':
        out += "\\n";
        break;
      default:
        out.push_back(ch);
        break;
    }
  }
  return out;
}

void appendHelpType(std::ostringstream& out, const std::string& name, const std::string& help, const std::string& type) {
  out << "# HELP " << name << ' ' << help << '\n';
  out << "# TYPE " << name << ' ' << type << '\n';
}

std::string fnv1aHex(const std::string& value) {
  std::uint64_t hash = 1469598103934665603ULL;
  for (const unsigned char ch : value) {
    hash ^= ch;
    hash *= 1099511628211ULL;
  }
  std::ostringstream out;
  out << std::hex << std::setw(16) << std::setfill('0') << hash;
  return out.str();
}

std::string deviceLabel(const Config& config, const DeviceState& device) {
  if (config.prometheus_device_label_mode == "raw_mac" && !device.mac.empty()) {
    return device.mac;
  }
  const std::string stable_id = !device.mac.empty() ? device.mac : device.ip;
  return stable_id.empty() ? "unknown" : fnv1aHex(stable_id);
}

}  // namespace

std::string renderPrometheusMetrics(const Config& config,
                                    const StateStore& state,
                                    const RuntimeStats& stats,
                                    std::chrono::steady_clock::time_point started_at) {
  const Summary summary = state.summary();
  const RuntimeStatsSnapshot runtime = stats.snapshot();
  const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - started_at).count();

  std::ostringstream out;
  out.setf(std::ios::fixed);
  out.precision(3);

  appendHelpType(out, "openwrt_netmon_up", "Whether the netmon service is running.", "gauge");
  out << "openwrt_netmon_up 1\n";

  appendHelpType(out, "openwrt_netmon_uptime_seconds", "Netmon service uptime in seconds.", "counter");
  out << "openwrt_netmon_uptime_seconds " << uptime << "\n";

  appendHelpType(out, "openwrt_netmon_syslog_messages_total", "Syslog messages received by parsed type.", "counter");
  out << "openwrt_netmon_syslog_messages_total{type=\"all\"} " << runtime.syslog_messages_total << "\n";
  for (const auto& [type, count] : runtime.syslog_messages_by_type) {
    out << "openwrt_netmon_syslog_messages_total{type=\"" << labelEscape(type) << "\"} " << count << "\n";
  }

  appendHelpType(out, "openwrt_netmon_parse_errors_total", "Syslog messages that could not be parsed into a known event.", "counter");
  out << "openwrt_netmon_parse_errors_total " << runtime.parse_errors_total << "\n";

  appendHelpType(out, "openwrt_netmon_devices", "Number of devices by current status.", "gauge");
  out << "openwrt_netmon_devices{status=\"online\"} " << summary.active_devices << "\n";
  out << "openwrt_netmon_devices{status=\"idle\"} " << summary.idle_devices << "\n";
  out << "openwrt_netmon_devices{status=\"offline\"} " << summary.offline_devices << "\n";
  out << "openwrt_netmon_devices{status=\"unknown\"} " << summary.unknown_devices << "\n";

  appendHelpType(out, "openwrt_netmon_rx_rate_bps", "Current aggregate receive rate in bits per second.", "gauge");
  out << "openwrt_netmon_rx_rate_bps " << summary.rx_rate_bps << "\n";

  appendHelpType(out, "openwrt_netmon_tx_rate_bps", "Current aggregate transmit rate in bits per second.", "gauge");
  out << "openwrt_netmon_tx_rate_bps " << summary.tx_rate_bps << "\n";

  appendHelpType(out, "openwrt_netmon_wan_attacks_total", "WAN attack or firewall drop events observed.", "counter");
  out << "openwrt_netmon_wan_attacks_total " << runtime.wan_attacks_total << "\n";

  appendHelpType(out, "openwrt_netmon_wan_attacks_5m", "WAN attack or firewall drop events in the last five minutes.", "gauge");
  out << "openwrt_netmon_wan_attacks_5m " << summary.wan_attack_5m << "\n";

  appendHelpType(out, "openwrt_netmon_event_buffer_size", "Current in-memory event buffer size.", "gauge");
  out << "openwrt_netmon_event_buffer_size " << state.eventBufferSize() << "\n";

  if (config.prometheus_include_device_labels) {
    const std::vector<DeviceState> devices = state.devices();
    appendHelpType(out, "openwrt_netmon_device_rx_rate_bps", "Current per-device receive rate in bits per second.", "gauge");
    for (const DeviceState& device : devices) {
      out << "openwrt_netmon_device_rx_rate_bps{device=\"" << labelEscape(deviceLabel(config, device))
          << "\",status=\"" << labelEscape(toString(device.status)) << "\"} " << device.rx_rate_bps << "\n";
    }
    appendHelpType(out, "openwrt_netmon_device_tx_rate_bps", "Current per-device transmit rate in bits per second.", "gauge");
    for (const DeviceState& device : devices) {
      out << "openwrt_netmon_device_tx_rate_bps{device=\"" << labelEscape(deviceLabel(config, device))
          << "\",status=\"" << labelEscape(toString(device.status)) << "\"} " << device.tx_rate_bps << "\n";
    }
  }

  return out.str();
}

}  // namespace netmon
