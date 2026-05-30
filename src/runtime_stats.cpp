#include "netmon/runtime_stats.hpp"

#include "netmon/utils.hpp"

namespace netmon {

void RuntimeStats::recordSyslogMessage(const std::string& type) {
  ++syslog_messages_total_;
  std::lock_guard lock(mutex_);
  ++syslog_messages_by_type_[type.empty() ? "unknown" : lower(type)];
}

void RuntimeStats::recordParseError() {
  ++parse_errors_total_;
}

void RuntimeStats::recordWANAttack() {
  ++wan_attacks_total_;
}

RuntimeStatsSnapshot RuntimeStats::snapshot() const {
  RuntimeStatsSnapshot out;
  out.syslog_messages_total = syslog_messages_total_.load();
  out.parse_errors_total = parse_errors_total_.load();
  out.wan_attacks_total = wan_attacks_total_.load();
  std::lock_guard lock(mutex_);
  out.syslog_messages_by_type = syslog_messages_by_type_;
  return out;
}

}  // namespace netmon
