#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>

namespace netmon {

struct RuntimeStatsSnapshot {
  std::uint64_t syslog_messages_total = 0;
  std::uint64_t parse_errors_total = 0;
  std::uint64_t wan_attacks_total = 0;
  std::map<std::string, std::uint64_t> syslog_messages_by_type;
};

class RuntimeStats {
 public:
  void recordSyslogMessage(const std::string& type);
  void recordParseError();
  void recordWANAttack();

  RuntimeStatsSnapshot snapshot() const;

 private:
  std::atomic<std::uint64_t> syslog_messages_total_{0};
  std::atomic<std::uint64_t> parse_errors_total_{0};
  std::atomic<std::uint64_t> wan_attacks_total_{0};
  mutable std::mutex mutex_;
  std::map<std::string, std::uint64_t> syslog_messages_by_type_;
};

}  // namespace netmon
