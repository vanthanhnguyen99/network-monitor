#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "netmon/config.hpp"
#include "netmon/state_store.hpp"
#include "netmon/types.hpp"

namespace netmon {

struct TrafficHistoryPoint {
  std::chrono::system_clock::time_point ts{};
  double rx_rate_bps = 0.0;
  double tx_rate_bps = 0.0;
  std::size_t samples = 0;
};

struct DeviceTrafficTotal {
  std::string mac;
  std::string ip;
  std::string hostname;
  std::chrono::system_clock::time_point first_ts{};
  std::chrono::system_clock::time_point last_ts{};
  std::uint64_t rx_bytes = 0;
  std::uint64_t tx_bytes = 0;
  std::size_t samples = 0;
};

class SqliteStore {
 public:
  explicit SqliteStore(Config config);
  ~SqliteStore();

  SqliteStore(const SqliteStore&) = delete;
  SqliteStore& operator=(const SqliteStore&) = delete;

  bool enabled() const;
  void loadInto(StateStore& state);
  void upsertDevices(const std::vector<DeviceState>& devices);
  void insertTraffic(const TrafficSnapshot& snapshot);
  void insertEvent(const Event& event);
  void insertWANAttack(const WANAttackEvent& event);
  void applyRetention();
  std::vector<DeviceState> devices(std::size_t limit) const;
  std::vector<Event> recentEvents(std::size_t limit) const;
  std::vector<WANAttackEvent> recentWANAttacks(std::size_t limit) const;
  std::vector<TrafficHistoryPoint> trafficHistory(std::size_t limit) const;
  std::vector<DeviceTrafficTotal> deviceTrafficTotals(std::chrono::hours window, std::size_t limit) const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace netmon
