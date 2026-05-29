#include "netmon/state_store.hpp"

#include <algorithm>
#include <cmath>
#include <mutex>
#include <sstream>

#include "netmon/utils.hpp"

namespace netmon {
namespace {

constexpr std::chrono::seconds kInterfaceRateFreshWindow{10};

bool isReachableNeighbour(const std::string& state) {
  const std::string normalized = upper(state);
  return normalized == "REACHABLE" || normalized == "STALE" || normalized == "DELAY" || normalized == "PROBE";
}

bool isFailedNeighbour(const std::string& state) {
  const std::string normalized = upper(state);
  return normalized == "FAILED" || normalized == "INCOMPLETE" || normalized == "NOARP";
}

void setIfNotEmpty(std::string& dest, const std::string& value) {
  if (!value.empty() && value != "unknown" && value != "*") {
    dest = value;
  }
}

bool hasTag(const std::vector<std::string>& tags, const std::string& tag) {
  return std::find(tags.begin(), tags.end(), tag) != tags.end();
}

}  // namespace

StateStore::StateStore(Config config)
    : config_(std::move(config)), events_(config_.max_events), wan_attacks_(config_.max_attack_events) {}

void StateStore::updateDevice(const DeviceState& device) {
  const std::chrono::system_clock::time_point now = nowSystem();
  std::unique_lock lock(mutex_);
  std::string key = findKeyLocked(device.mac, device.ip);
  if (key.empty()) {
    key = makeKey(device.mac, device.ip);
  }
  if (key.empty()) {
    return;
  }

  const std::string desired_key = makeKey(device.mac, device.ip);
  if (!device.mac.empty() && key.rfind("ip:", 0) == 0 && !desired_key.empty() && desired_key != key) {
    auto node = devices_by_key_.extract(key);
    if (!node.empty()) {
      node.key() = desired_key;
      devices_by_key_.insert(std::move(node));
      traffic_points_[desired_key] = std::move(traffic_points_[key]);
      traffic_points_.erase(key);
      key = desired_key;
    }
  }

  DeviceState& current = devices_by_key_[key];
  mergeDeviceLocked(current, device, now);
  if (!current.ip.empty()) {
    ip_to_key_[current.ip] = key;
  }
  touchLastLogLocked(current.last_seen);
}

void StateStore::updateTraffic(const TrafficSnapshot& snapshot) {
  if (snapshot.mac.empty() && snapshot.ip.empty()) {
    return;
  }

  TrafficSnapshot current_snapshot = snapshot;
  if (current_snapshot.ts.time_since_epoch().count() == 0) {
    current_snapshot.ts = nowSystem();
  }
  current_snapshot.mac = lower(current_snapshot.mac);

  std::unique_lock lock(mutex_);
  std::string key = findKeyLocked(current_snapshot.mac, current_snapshot.ip);
  if (key.empty()) {
    key = makeKey(current_snapshot.mac, current_snapshot.ip);
  }
  if (key.empty()) {
    return;
  }

  std::deque<TrafficSnapshot>& points = traffic_points_[key];
  DeviceState& device = devices_by_key_[key];

  bool should_store_point = points.empty();
  bool counters_reset = false;
  bool counters_changed = points.empty();
  double rx_rate = device.rx_rate_bps;
  double tx_rate = device.tx_rate_bps;

  if (!points.empty()) {
    const TrafficSnapshot& previous = points.back();
    counters_changed = current_snapshot.rx_bytes != previous.rx_bytes || current_snapshot.tx_bytes != previous.tx_bytes;
    counters_reset = current_snapshot.rx_bytes < previous.rx_bytes || current_snapshot.tx_bytes < previous.tx_bytes;

    if (counters_reset) {
      rx_rate = 0.0;
      tx_rate = 0.0;
      should_store_point = true;
    } else if (counters_changed) {
      const auto delta_time = std::chrono::duration_cast<std::chrono::duration<double>>(current_snapshot.ts - previous.ts).count();
      if (delta_time > 0) {
        rx_rate = static_cast<double>(current_snapshot.rx_bytes - previous.rx_bytes) * 8.0 / delta_time;
        tx_rate = static_cast<double>(current_snapshot.tx_bytes - previous.tx_bytes) * 8.0 / delta_time;
        should_store_point = true;
      }
    } else {
      const bool has_recent_rate = device.last_rate.time_since_epoch().count() != 0 &&
          current_snapshot.ts - device.last_rate <= std::chrono::seconds(config_.traffic_rate_hold_seconds);
      if (!has_recent_rate) {
        rx_rate = 0.0;
        tx_rate = 0.0;
      }
    }
  }

  if (should_store_point) {
    points.push_back(current_snapshot);
    while (points.size() > config_.max_traffic_points_per_device) {
      points.pop_front();
    }
  }

  if (device.first_seen.time_since_epoch().count() == 0) {
    device.first_seen = current_snapshot.ts;
  }
  device.last_seen = std::max(device.last_seen, current_snapshot.ts);
  device.last_traffic = current_snapshot.ts;
  setIfNotEmpty(device.mac, current_snapshot.mac);
  setIfNotEmpty(device.ip, current_snapshot.ip);
  device.source = "traffic";
  device.rx_bytes_total = current_snapshot.rx_bytes;
  device.tx_bytes_total = current_snapshot.tx_bytes;
  device.rx_rate_bps = rx_rate;
  device.tx_rate_bps = tx_rate;
  if (rx_rate > 0.0 || tx_rate > 0.0) {
    device.last_rate = current_snapshot.ts;
  } else if (counters_reset) {
    device.last_rate = {};
  }
  if (!hasTag(device.tags, "traffic")) {
    device.tags.push_back("traffic");
  }
  device.status = statusFor(device, current_snapshot.ts);
  if (!device.ip.empty()) {
    ip_to_key_[device.ip] = key;
  }
  touchLastLogLocked(current_snapshot.ts);
}

void StateStore::updateInterface(const InterfaceSnapshot& snapshot) {
  if (snapshot.interface_name.empty()) {
    return;
  }

  InterfaceSnapshot current_snapshot = snapshot;
  if (current_snapshot.ts.time_since_epoch().count() == 0) {
    current_snapshot.ts = nowSystem();
  }

  std::unique_lock lock(mutex_);
  InterfaceState& state = interfaces_by_name_[current_snapshot.interface_name];
  state.interface_name = current_snapshot.interface_name;

  double rx_rate = 0.0;
  double tx_rate = 0.0;
  bool rate_ready = false;

  if (const auto previous_it = interface_snapshots_.find(current_snapshot.interface_name); previous_it != interface_snapshots_.end()) {
    const InterfaceSnapshot& previous = previous_it->second;
    const auto delta_time = std::chrono::duration_cast<std::chrono::duration<double>>(current_snapshot.ts - previous.ts).count();
    const bool counters_reset = current_snapshot.rx_bytes < previous.rx_bytes || current_snapshot.tx_bytes < previous.tx_bytes;
    if (delta_time > 0.0 && !counters_reset) {
      rx_rate = static_cast<double>(current_snapshot.rx_bytes - previous.rx_bytes) * 8.0 / delta_time;
      tx_rate = static_cast<double>(current_snapshot.tx_bytes - previous.tx_bytes) * 8.0 / delta_time;
      rate_ready = true;
    }
  }

  interface_snapshots_[current_snapshot.interface_name] = current_snapshot;
  state.last_seen = current_snapshot.ts;
  state.rx_bytes_total = current_snapshot.rx_bytes;
  state.tx_bytes_total = current_snapshot.tx_bytes;
  state.rx_rate_bps = rx_rate;
  state.tx_rate_bps = tx_rate;
  if (rate_ready) {
    state.last_rate = current_snapshot.ts;
  }
  touchLastLogLocked(current_snapshot.ts);
}

void StateStore::addEvent(const Event& event) {
  std::unique_lock lock(mutex_);
  pushEventLocked(event);
}

void StateStore::addWANAttack(const WANAttackEvent& event) {
  WANAttackEvent attack = event;
  if (attack.ts.time_since_epoch().count() == 0) {
    attack.ts = nowSystem();
  }
  std::unique_lock lock(mutex_);
  wan_attacks_.push(std::move(attack));
  touchLastLogLocked(event.ts.time_since_epoch().count() == 0 ? nowSystem() : event.ts);
}

std::vector<DeviceState> StateStore::devices() const {
  std::shared_lock lock(mutex_);
  std::vector<DeviceState> out;
  out.reserve(devices_by_key_.size());
  for (const auto& [_, device] : devices_by_key_) {
    out.push_back(device);
  }
  std::sort(out.begin(), out.end(), [](const DeviceState& lhs, const DeviceState& rhs) {
    if (lhs.status != rhs.status) {
      return static_cast<int>(lhs.status) < static_cast<int>(rhs.status);
    }
    return lhs.last_seen > rhs.last_seen;
  });
  return out;
}

std::vector<Event> StateStore::recentEvents(std::size_t limit) const {
  std::shared_lock lock(mutex_);
  return events_.items(limit);
}

std::vector<WANAttackEvent> StateStore::recentWANAttacks(std::size_t limit) const {
  std::shared_lock lock(mutex_);
  return wan_attacks_.items(limit);
}

Summary StateStore::summary() const {
  const auto now = nowSystem();
  const auto window_start = now - std::chrono::minutes(5);
  std::shared_lock lock(mutex_);
  Summary out;
  out.last_log_ts = last_log_ts_;
  double device_rx_rate_bps = 0.0;
  double device_tx_rate_bps = 0.0;
  for (const auto& [_, device] : devices_by_key_) {
    const DeviceStatus status = statusFor(device, now);
    switch (status) {
      case DeviceStatus::Online:
        ++out.active_devices;
        break;
      case DeviceStatus::Idle:
        ++out.idle_devices;
        break;
      case DeviceStatus::Offline:
        ++out.offline_devices;
        break;
      case DeviceStatus::Unknown:
        ++out.unknown_devices;
        break;
    }
    device_rx_rate_bps += device.rx_rate_bps;
    device_tx_rate_bps += device.tx_rate_bps;
  }

  out.rx_rate_bps = device_rx_rate_bps;
  out.tx_rate_bps = device_tx_rate_bps;

  const InterfaceState* freshest_interface = nullptr;
  for (const auto& [_, iface] : interfaces_by_name_) {
    if (iface.last_rate.time_since_epoch().count() == 0 || now - iface.last_rate > kInterfaceRateFreshWindow) {
      continue;
    }
    if (freshest_interface == nullptr || iface.last_rate > freshest_interface->last_rate) {
      freshest_interface = &iface;
    }
  }

  if (freshest_interface != nullptr) {
    out.rx_rate_bps = freshest_interface->rx_rate_bps;
    out.tx_rate_bps = freshest_interface->tx_rate_bps;
    out.rate_source = "interface";
    out.rate_interface = freshest_interface->interface_name;
    out.last_interface_ts = freshest_interface->last_seen;
  }

  for (const WANAttackEvent& event : wan_attacks_.raw()) {
    if (event.ts >= window_start) {
      ++out.wan_attack_5m;
    }
  }
  return out;
}

void StateStore::cleanup(std::chrono::system_clock::time_point now) {
  std::unique_lock lock(mutex_);
  std::vector<std::string> erase_keys;
  for (auto& [key, device] : devices_by_key_) {
    if ((device.rx_rate_bps > 0.0 || device.tx_rate_bps > 0.0) &&
        (device.last_rate.time_since_epoch().count() == 0 ||
         now - device.last_rate > std::chrono::seconds(config_.traffic_rate_hold_seconds))) {
      device.rx_rate_bps = 0.0;
      device.tx_rate_bps = 0.0;
    }

    const DeviceStatus previous = device.status;
    device.status = statusFor(device, now);
    if (previous != DeviceStatus::Offline && device.status == DeviceStatus::Offline) {
      Event event;
      event.id = nextEventId();
      event.ts = now;
      event.type = "device";
      event.severity = EventSeverity::Warning;
      event.source = "state";
      event.message = "Device offline";
      event.fields["mac"] = device.mac;
      event.fields["ip"] = device.ip;
      event.fields["hostname"] = device.hostname;
      events_.push(std::move(event));
      touchLastLogLocked(now);
    }

    if (device.status == DeviceStatus::Offline && device.last_seen.time_since_epoch().count() != 0 &&
        now - device.last_seen > std::chrono::seconds(config_.device_keep_ttl_seconds)) {
      erase_keys.push_back(key);
    }
  }

  for (const std::string& key : erase_keys) {
    devices_by_key_.erase(key);
    traffic_points_.erase(key);
    for (auto it = ip_to_key_.begin(); it != ip_to_key_.end();) {
      if (it->second == key) {
        it = ip_to_key_.erase(it);
      } else {
        ++it;
      }
    }
  }
}

DeviceStatus StateStore::statusFor(const DeviceState& device, std::chrono::system_clock::time_point now) const {
  if (device.last_seen.time_since_epoch().count() == 0) {
    return DeviceStatus::Unknown;
  }

  const auto age = now - device.last_seen;
  if (age > std::chrono::seconds(config_.device_idle_ttl_seconds)) {
    return DeviceStatus::Offline;
  }
  if (isFailedNeighbour(device.neigh_state)) {
    return DeviceStatus::Idle;
  }
  if (age <= std::chrono::seconds(config_.device_online_ttl_seconds)) {
    if (device.neigh_state.empty() || isReachableNeighbour(device.neigh_state) || device.source == "dhcp" || device.source == "traffic" || device.source == "wifi") {
      return DeviceStatus::Online;
    }
  }
  return DeviceStatus::Idle;
}

std::string StateStore::nextEventId() {
  const std::uint64_t id = ++event_seq_;
  std::ostringstream out;
  out << "evt-" << id;
  return out.str();
}

std::string StateStore::findKeyLocked(const std::string& mac, const std::string& ip) const {
  const std::string normalized_mac = lower(mac);
  if (!normalized_mac.empty()) {
    const std::string key = "mac:" + normalized_mac;
    if (devices_by_key_.find(key) != devices_by_key_.end()) {
      return key;
    }
  }
  if (!ip.empty()) {
    const auto it = ip_to_key_.find(ip);
    if (it != ip_to_key_.end()) {
      return it->second;
    }
    const std::string key = "ip:" + ip;
    if (devices_by_key_.find(key) != devices_by_key_.end()) {
      return key;
    }
  }
  return {};
}

std::string StateStore::makeKey(const std::string& mac, const std::string& ip) const {
  const std::string normalized_mac = lower(mac);
  if (!normalized_mac.empty()) {
    return "mac:" + normalized_mac;
  }
  if (!ip.empty()) {
    return "ip:" + ip;
  }
  return {};
}

void StateStore::mergeDeviceLocked(DeviceState& current, const DeviceState& incoming, std::chrono::system_clock::time_point now) {
  DeviceState normalized = incoming;
  normalized.mac = lower(normalized.mac);
  const auto incoming_seen = normalized.last_seen.time_since_epoch().count() == 0 ? now : normalized.last_seen;

  if (current.first_seen.time_since_epoch().count() == 0) {
    current.first_seen = incoming_seen;
  }
  if (current.last_seen.time_since_epoch().count() == 0 || incoming_seen > current.last_seen) {
    current.last_seen = incoming_seen;
  }

  setIfNotEmpty(current.mac, normalized.mac);
  setIfNotEmpty(current.ip, normalized.ip);
  setIfNotEmpty(current.hostname, normalized.hostname);
  setIfNotEmpty(current.interface_name, normalized.interface_name);
  setIfNotEmpty(current.source, normalized.source);
  setIfNotEmpty(current.neigh_state, normalized.neigh_state);

  if (normalized.last_dhcp.time_since_epoch().count() != 0) {
    current.last_dhcp = normalized.last_dhcp;
  }
  if (normalized.rx_bytes_total > 0) {
    current.rx_bytes_total = normalized.rx_bytes_total;
  }
  if (normalized.tx_bytes_total > 0) {
    current.tx_bytes_total = normalized.tx_bytes_total;
  }
  if (std::fabs(normalized.rx_rate_bps) > 0.0) {
    current.rx_rate_bps = normalized.rx_rate_bps;
  }
  if (std::fabs(normalized.tx_rate_bps) > 0.0) {
    current.tx_rate_bps = normalized.tx_rate_bps;
  }

  for (const std::string& tag : normalized.tags) {
    if (!hasTag(current.tags, tag)) {
      current.tags.push_back(tag);
    }
  }

  if (normalized.status == DeviceStatus::Offline) {
    current.status = DeviceStatus::Offline;
  } else {
    current.status = statusFor(current, now);
  }
}

void StateStore::pushEventLocked(Event event) {
  if (event.id.empty()) {
    event.id = nextEventId();
  }
  if (event.ts.time_since_epoch().count() == 0) {
    event.ts = nowSystem();
  }
  events_.push(event);
  touchLastLogLocked(event.ts);
}

void StateStore::touchLastLogLocked(std::chrono::system_clock::time_point ts) {
  if (ts.time_since_epoch().count() == 0) {
    ts = nowSystem();
  }
  if (last_log_ts_.time_since_epoch().count() == 0 || ts > last_log_ts_) {
    last_log_ts_ = ts;
  }
}

}  // namespace netmon
