#include "netmon/app.hpp"

#include <iostream>
#include <utility>

#include "netmon/utils.hpp"

namespace netmon {
namespace {

std::string fieldOr(const ParseResult& result, const std::string& key, const std::string& fallback = {}) {
  const auto it = result.fields.find(key);
  return it == result.fields.end() ? fallback : it->second;
}

std::chrono::system_clock::time_point tsFromFields(const ParseResult& result) {
  const std::uint64_t ts = parseUint64(fieldOr(result, "ts"), 0);
  if (ts > 0) {
    return fromUnixSeconds(static_cast<std::int64_t>(ts));
  }
  return nowSystem();
}

Event makeEvent(StateStore& state, const ParseResult& result, const std::string& peer_ip) {
  Event event;
  event.id = state.nextEventId();
  event.ts = nowSystem();
  event.type = result.type;
  event.severity = EventSeverity::Info;
  event.source = peer_ip;
  event.message = result.raw;
  event.fields = result.fields;
  return event;
}

}  // namespace

App::App(Config config)
    : config_(std::move(config)), state_(config_), started_at_(std::chrono::steady_clock::now()) {}

App::~App() {
  stop();
}

void App::start() {
  running_ = true;
  web_server_ = std::make_unique<WebServer>(config_, state_, started_at_);
  syslog_server_ = std::make_unique<SyslogServer>(config_, [this](std::string line, std::string peer_ip) {
    handleLog(std::move(line), std::move(peer_ip));
  });
  web_server_->start();
  syslog_server_->start();
  cleanup_thread_ = std::thread(&App::runCleanupLoop, this);
}

void App::stop() {
  const bool was_running = running_.exchange(false);
  if (syslog_server_) {
    syslog_server_->stop();
  }
  if (web_server_) {
    web_server_->stop();
  }
  if (cleanup_thread_.joinable()) {
    cleanup_thread_.join();
  }
  wait_cv_.notify_all();
  if (was_running) {
    std::cerr << "app: stopped\n";
  }
}

void App::wait() {
  std::unique_lock lock(wait_mutex_);
  wait_cv_.wait(lock, [this] { return !running_.load(); });
}

void App::handleLog(std::string line, std::string peer_ip) {
  ParseResult result = parser_.parse(line);
  if (!result.matched) {
    result.type = "raw";
    result.raw = line;
    Event event = makeEvent(state_, result, peer_ip);
    event.source = peer_ip;
    event.message = line;
    event.fields["raw"] = line;
    state_.addEvent(event);
    publishUpdate("event");
    return;
  }

  applyParseResult(result, peer_ip);
}

void App::runCleanupLoop() {
  while (running_.load()) {
    for (int i = 0; i < 60 && running_.load(); ++i) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    if (!running_.load()) {
      break;
    }
    state_.cleanup(nowSystem());
    publishUpdate("summary_update");
  }
}

void App::applyParseResult(const ParseResult& result, const std::string& peer_ip) {
  Event event = makeEvent(state_, result, peer_ip);
  event.ts = tsFromFields(result);

  if (result.type == "netdev") {
    DeviceState device;
    device.mac = fieldOr(result, "mac");
    device.ip = fieldOr(result, "ip");
    device.hostname = fieldOr(result, "hostname", fieldOr(result, "host"));
    device.interface_name = fieldOr(result, "interface", fieldOr(result, "if"));
    device.neigh_state = fieldOr(result, "neigh");
    device.source = "netdev";
    device.last_seen = event.ts;
    device.tags = {"netdev"};
    state_.updateDevice(device);
    event.type = "device";
    event.message = "Device snapshot";
    state_.addEvent(event);
    publishUpdate("device_update");
    return;
  }

  if (result.type == "dhcp") {
    DeviceState device;
    device.mac = fieldOr(result, "mac");
    device.ip = fieldOr(result, "ip");
    device.hostname = fieldOr(result, "hostname");
    device.interface_name = fieldOr(result, "interface");
    device.source = "dhcp";
    device.last_seen = event.ts;
    device.last_dhcp = event.ts;
    device.tags = {"dhcp"};
    state_.updateDevice(device);
    event.type = "dhcp";
    event.message = fieldOr(result, "event", "DHCP event");
    state_.addEvent(event);
    publishUpdate("device_update");
    return;
  }

  if (result.type == "nettraffic") {
    if (result.fields.contains("rx_bytes") && result.fields.contains("tx_bytes")) {
      TrafficSnapshot snapshot;
      snapshot.mac = fieldOr(result, "mac");
      snapshot.ip = fieldOr(result, "ip");
      snapshot.ts = event.ts;
      snapshot.rx_bytes = parseUint64(fieldOr(result, "rx_bytes"), 0);
      snapshot.tx_bytes = parseUint64(fieldOr(result, "tx_bytes"), 0);
      state_.updateTraffic(snapshot);
      event.type = "traffic";
      event.message = "Traffic snapshot";
    } else {
      event.type = "traffic";
      event.message = "Traffic CSV snapshot";
    }
    state_.addEvent(event);
    publishUpdate("traffic_update");
    return;
  }

  if (result.type == "netiface") {
    if (result.fields.contains("rx_bytes") && result.fields.contains("tx_bytes")) {
      InterfaceSnapshot snapshot;
      snapshot.interface_name = fieldOr(result, "interface", fieldOr(result, "if", fieldOr(result, "iface")));
      snapshot.ts = event.ts;
      snapshot.rx_bytes = parseUint64(fieldOr(result, "rx_bytes"), 0);
      snapshot.tx_bytes = parseUint64(fieldOr(result, "tx_bytes"), 0);
      state_.updateInterface(snapshot);
      publishUpdate("summary_update");
    }
    return;
  }

  if (result.type == "wan_attack") {
    WANAttackEvent attack;
    attack.ts = event.ts;
    attack.in_if = fieldOr(result, "in_if");
    attack.src_ip = fieldOr(result, "src_ip");
    attack.dst_ip = fieldOr(result, "dst_ip");
    attack.src_port = fieldOr(result, "src_port");
    attack.dst_port = fieldOr(result, "dst_port");
    attack.proto = fieldOr(result, "proto");
    attack.length = fieldOr(result, "len");
    attack.raw = result.raw;
    state_.addWANAttack(attack);
    event.severity = EventSeverity::Critical;
    event.message = "WAN attack/firewall drop";
    state_.addEvent(event);
    publishUpdate("wan_attack");
    return;
  }

  if (result.type == "wan") {
    event.type = "wan";
    event.message = fieldOr(result, "message", result.raw);
    if (fieldOr(result, "state") == "down") {
      event.severity = EventSeverity::Warning;
    }
    state_.addEvent(event);
    publishUpdate("event");
    return;
  }

  if (result.type == "wifi") {
    DeviceState device;
    device.mac = fieldOr(result, "mac");
    device.source = "wifi";
    device.last_seen = event.ts;
    device.tags = {"wifi"};
    if (fieldOr(result, "event") == "wifi_disconnected") {
      device.status = DeviceStatus::Offline;
      event.severity = EventSeverity::Warning;
    }
    state_.updateDevice(device);
    event.type = "device";
    event.message = fieldOr(result, "event", "WiFi client event");
    state_.addEvent(event);
    publishUpdate("device_update");
    return;
  }

  state_.addEvent(event);
  publishUpdate("event");
}

void App::publishUpdate(const std::string& type) {
  if (!web_server_) {
    return;
  }
  web_server_->broadcast("{\"type\":" + jsonQuote(type) + ",\"payload\":{}}");
}

}  // namespace netmon
