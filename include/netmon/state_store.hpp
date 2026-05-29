#pragma once

#include <atomic>
#include <chrono>
#include <deque>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "netmon/config.hpp"
#include "netmon/ring_buffer.hpp"
#include "netmon/types.hpp"

namespace netmon {

class StateStore {
 public:
  explicit StateStore(Config config);

  void updateDevice(const DeviceState& device);
  void updateTraffic(const TrafficSnapshot& snapshot);
  void updateInterface(const InterfaceSnapshot& snapshot);
  void addEvent(const Event& event);
  void addWANAttack(const WANAttackEvent& event);

  std::vector<DeviceState> devices() const;
  std::vector<Event> recentEvents(std::size_t limit) const;
  std::vector<WANAttackEvent> recentWANAttacks(std::size_t limit) const;
  Summary summary() const;

  void cleanup(std::chrono::system_clock::time_point now);
  DeviceStatus statusFor(const DeviceState& device, std::chrono::system_clock::time_point now) const;
  std::string nextEventId();

 private:
  std::string findKeyLocked(const std::string& mac, const std::string& ip) const;
  std::string makeKey(const std::string& mac, const std::string& ip) const;
  void mergeDeviceLocked(DeviceState& current, const DeviceState& incoming, std::chrono::system_clock::time_point now);
  void pushEventLocked(Event event);
  void touchLastLogLocked(std::chrono::system_clock::time_point ts);

  Config config_;
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, DeviceState> devices_by_key_;
  std::unordered_map<std::string, std::string> ip_to_key_;
  std::unordered_map<std::string, std::deque<TrafficSnapshot>> traffic_points_;
  std::unordered_map<std::string, InterfaceSnapshot> interface_snapshots_;
  std::unordered_map<std::string, InterfaceState> interfaces_by_name_;
  RingBuffer<Event> events_;
  RingBuffer<WANAttackEvent> wan_attacks_;
  std::chrono::system_clock::time_point last_log_ts_{};
  std::atomic<std::uint64_t> event_seq_{0};
};

}  // namespace netmon
