#include "netmon/sqlite_store.hpp"

#include <dlfcn.h>

#include <algorithm>
#include <vector>
#include <chrono>
#include <cstddef>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <utility>

#include "netmon/utils.hpp"

struct sqlite3;
struct sqlite3_stmt;

namespace netmon {
namespace {

constexpr int kSqliteOk = 0;
constexpr int kSqliteRow = 100;
constexpr int kSqliteDone = 101;
constexpr int kSqliteOpenReadWrite = 0x00000002;
constexpr int kSqliteOpenCreate = 0x00000004;
constexpr int kSqliteOpenFullMutex = 0x00010000;

using SqliteDestructor = void (*)(void*);

SqliteDestructor sqliteTransient() {
  return reinterpret_cast<SqliteDestructor>(-1);
}

std::int64_t unixSeconds(std::chrono::system_clock::time_point tp) {
  if (tp.time_since_epoch().count() == 0) {
    return 0;
  }
  return std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
}

std::chrono::system_clock::time_point timeFromColumn(sqlite3_stmt* stmt, int column, std::int64_t (*column_int64)(sqlite3_stmt*, int)) {
  const std::int64_t seconds = column_int64(stmt, column);
  if (seconds <= 0) {
    return {};
  }
  return fromUnixSeconds(seconds);
}

std::string statusToString(DeviceStatus status) {
  return toString(status);
}

DeviceStatus parseStatus(const std::string& value) {
  const std::string normalized = lower(value);
  if (normalized == "online") {
    return DeviceStatus::Online;
  }
  if (normalized == "idle") {
    return DeviceStatus::Idle;
  }
  if (normalized == "offline") {
    return DeviceStatus::Offline;
  }
  return DeviceStatus::Unknown;
}

EventSeverity parseSeverity(const std::string& value) {
  const std::string normalized = lower(value);
  if (normalized == "warning") {
    return EventSeverity::Warning;
  }
  if (normalized == "critical") {
    return EventSeverity::Critical;
  }
  return EventSeverity::Info;
}

std::string tagsText(const std::vector<std::string>& tags) {
  std::ostringstream out;
  for (std::size_t i = 0; i < tags.size(); ++i) {
    if (i != 0) {
      out << ',';
    }
    out << tags[i];
  }
  return out.str();
}

std::vector<std::string> parseTags(const std::string& value) {
  std::vector<std::string> out;
  for (std::string item : split(value, ',')) {
    item = trim(item);
    if (!item.empty()) {
      out.push_back(item);
    }
  }
  return out;
}

std::string fieldsJson(const std::unordered_map<std::string, std::string>& fields) {
  std::vector<std::string> keys;
  keys.reserve(fields.size());
  for (const auto& [key, _] : fields) {
    keys.push_back(key);
  }
  std::sort(keys.begin(), keys.end());

  std::ostringstream out;
  out << '{';
  bool first = true;
  for (const std::string& key : keys) {
    if (!first) {
      out << ',';
    }
    first = false;
    out << jsonQuote(key) << ':' << jsonQuote(fields.at(key));
  }
  out << '}';
  return out.str();
}

std::string deviceKey(const DeviceState& device) {
  const std::string mac = lower(device.mac);
  if (!mac.empty()) {
    return "mac:" + mac;
  }
  if (!device.ip.empty()) {
    return "ip:" + device.ip;
  }
  return {};
}

}  // namespace

struct SqliteStore::Impl {
  struct Api {
    void* handle = nullptr;
    int (*open_v2)(const char*, sqlite3**, int, const char*) = nullptr;
    int (*close)(sqlite3*) = nullptr;
    int (*exec)(sqlite3*, const char*, int (*)(void*, int, char**, char**), void*, char**) = nullptr;
    const char* (*errmsg)(sqlite3*) = nullptr;
    void (*free_mem)(void*) = nullptr;
    int (*prepare_v2)(sqlite3*, const char*, int, sqlite3_stmt**, const char**) = nullptr;
    int (*step)(sqlite3_stmt*) = nullptr;
    int (*reset)(sqlite3_stmt*) = nullptr;
    int (*clear_bindings)(sqlite3_stmt*) = nullptr;
    int (*finalize)(sqlite3_stmt*) = nullptr;
    int (*bind_text)(sqlite3_stmt*, int, const char*, int, SqliteDestructor) = nullptr;
    int (*bind_int64)(sqlite3_stmt*, int, std::int64_t) = nullptr;
    int (*bind_double)(sqlite3_stmt*, int, double) = nullptr;
    const unsigned char* (*column_text)(sqlite3_stmt*, int) = nullptr;
    std::int64_t (*column_int64)(sqlite3_stmt*, int) = nullptr;
    double (*column_double)(sqlite3_stmt*, int) = nullptr;
  };

  explicit Impl(Config config) : config(std::move(config)) {
    if (lower(this->config.storage_mode) != "sqlite") {
      return;
    }
    loadApi();
    openDatabase();
    initializeSchema();
    applyRetention();
    if (this->config.sqlite_vacuum_on_start) {
      execLog("PRAGMA incremental_vacuum;");
    }
    enabled = true;
  }

  ~Impl() {
    if (db != nullptr && api.close != nullptr) {
      api.close(db);
      db = nullptr;
    }
    if (api.handle != nullptr) {
      dlclose(api.handle);
      api.handle = nullptr;
    }
  }

  Config config;
  Api api;
  sqlite3* db = nullptr;
  bool enabled = false;
  mutable std::mutex mutex;

  template <typename T>
  void loadSymbol(T& target, const char* name) {
    target = reinterpret_cast<T>(dlsym(api.handle, name));
    if (target == nullptr) {
      throw std::runtime_error(std::string("sqlite: missing symbol ") + name);
    }
  }

  void loadApi() {
    api.handle = dlopen("libsqlite3.so.0", RTLD_NOW | RTLD_LOCAL);
    if (api.handle == nullptr) {
      api.handle = dlopen("libsqlite3.so", RTLD_NOW | RTLD_LOCAL);
    }
    if (api.handle == nullptr) {
      throw std::runtime_error("storage.mode=sqlite requires libsqlite3 at runtime");
    }
    loadSymbol(api.open_v2, "sqlite3_open_v2");
    loadSymbol(api.close, "sqlite3_close");
    loadSymbol(api.exec, "sqlite3_exec");
    loadSymbol(api.errmsg, "sqlite3_errmsg");
    loadSymbol(api.free_mem, "sqlite3_free");
    loadSymbol(api.prepare_v2, "sqlite3_prepare_v2");
    loadSymbol(api.step, "sqlite3_step");
    loadSymbol(api.reset, "sqlite3_reset");
    loadSymbol(api.clear_bindings, "sqlite3_clear_bindings");
    loadSymbol(api.finalize, "sqlite3_finalize");
    loadSymbol(api.bind_text, "sqlite3_bind_text");
    loadSymbol(api.bind_int64, "sqlite3_bind_int64");
    loadSymbol(api.bind_double, "sqlite3_bind_double");
    loadSymbol(api.column_text, "sqlite3_column_text");
    loadSymbol(api.column_int64, "sqlite3_column_int64");
    loadSymbol(api.column_double, "sqlite3_column_double");
  }

  void openDatabase() {
    const int flags = kSqliteOpenReadWrite | kSqliteOpenCreate | kSqliteOpenFullMutex;
    const int rc = api.open_v2(config.sqlite_path.c_str(), &db, flags, nullptr);
    if (rc != kSqliteOk) {
      const std::string message = db != nullptr ? api.errmsg(db) : "unknown error";
      throw std::runtime_error("sqlite: could not open " + config.sqlite_path + ": " + message);
    }
  }

  std::string lastError() const {
    return db != nullptr && api.errmsg != nullptr ? api.errmsg(db) : "unknown sqlite error";
  }

  void execRequired(const std::string& sql) {
    char* error = nullptr;
    const int rc = api.exec(db, sql.c_str(), nullptr, nullptr, &error);
    if (rc != kSqliteOk) {
      std::string message = error != nullptr ? error : lastError();
      if (error != nullptr) {
        api.free_mem(error);
      }
      throw std::runtime_error("sqlite: " + message);
    }
  }

  bool execLog(const std::string& sql) {
    char* error = nullptr;
    const int rc = api.exec(db, sql.c_str(), nullptr, nullptr, &error);
    if (rc != kSqliteOk) {
      std::cerr << "sqlite: " << (error != nullptr ? error : lastError()) << '\n';
      if (error != nullptr) {
        api.free_mem(error);
      }
      return false;
    }
    return true;
  }

  sqlite3_stmt* prepare(const std::string& sql) {
    sqlite3_stmt* stmt = nullptr;
    const int rc = api.prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != kSqliteOk) {
      std::cerr << "sqlite: prepare failed: " << lastError() << '\n';
      return nullptr;
    }
    return stmt;
  }

  void bindText(sqlite3_stmt* stmt, int index, const std::string& value) {
    api.bind_text(stmt, index, value.c_str(), -1, sqliteTransient());
  }

  std::string columnText(sqlite3_stmt* stmt, int index) const {
    const unsigned char* text = api.column_text(stmt, index);
    return text == nullptr ? std::string{} : reinterpret_cast<const char*>(text);
  }

  void initializeSchema() {
    execRequired("PRAGMA journal_mode=WAL;");
    execRequired("PRAGMA synchronous=NORMAL;");
    execRequired("PRAGMA busy_timeout=250;");
    execRequired("PRAGMA auto_vacuum=INCREMENTAL;");
    execRequired(R"sql(
CREATE TABLE IF NOT EXISTS schema_migrations(
  version INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices(
  device_key TEXT PRIMARY KEY,
  mac TEXT,
  ip TEXT,
  hostname TEXT,
  interface_name TEXT,
  source TEXT,
  neigh_state TEXT,
  status TEXT,
  first_seen INTEGER,
  last_seen INTEGER,
  last_dhcp INTEGER,
  last_traffic INTEGER,
  last_rate INTEGER,
  rx_bytes_total INTEGER,
  tx_bytes_total INTEGER,
  rx_rate_bps REAL,
  tx_rate_bps REAL,
  tags TEXT,
  updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS traffic_samples(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mac TEXT,
  ip TEXT,
  ts INTEGER NOT NULL,
  rx_bytes INTEGER NOT NULL,
  tx_bytes INTEGER NOT NULL,
  rx_rate_bps REAL DEFAULT 0,
  tx_rate_bps REAL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_traffic_samples_device_ts ON traffic_samples(mac, ip, ts);
CREATE TABLE IF NOT EXISTS events(
  id TEXT PRIMARY KEY,
  ts INTEGER NOT NULL,
  type TEXT,
  severity TEXT,
  source TEXT,
  message TEXT,
  fields_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS wan_attacks(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  in_if TEXT,
  src_ip TEXT,
  dst_ip TEXT,
  src_port TEXT,
  dst_port TEXT,
  proto TEXT,
  length TEXT,
  raw TEXT
);
CREATE INDEX IF NOT EXISTS idx_wan_attacks_ts ON wan_attacks(ts);
INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(1, strftime('%s','now'));
)sql");
  }

  void upsertDevices(const std::vector<DeviceState>& devices) {
    if (!enabled || devices.empty()) {
      return;
    }
    std::lock_guard lock(mutex);
    execLog("BEGIN IMMEDIATE;");
    sqlite3_stmt* stmt = prepare(R"sql(
INSERT INTO devices(device_key, mac, ip, hostname, interface_name, source, neigh_state, status, first_seen, last_seen, last_dhcp, last_traffic, last_rate, rx_bytes_total, tx_bytes_total, rx_rate_bps, tx_rate_bps, tags, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(device_key) DO UPDATE SET
  mac=excluded.mac,
  ip=excluded.ip,
  hostname=excluded.hostname,
  interface_name=excluded.interface_name,
  source=excluded.source,
  neigh_state=excluded.neigh_state,
  status=excluded.status,
  first_seen=excluded.first_seen,
  last_seen=excluded.last_seen,
  last_dhcp=excluded.last_dhcp,
  last_traffic=excluded.last_traffic,
  last_rate=excluded.last_rate,
  rx_bytes_total=excluded.rx_bytes_total,
  tx_bytes_total=excluded.tx_bytes_total,
  rx_rate_bps=excluded.rx_rate_bps,
  tx_rate_bps=excluded.tx_rate_bps,
  tags=excluded.tags,
  updated_at=excluded.updated_at;
)sql");
    if (stmt == nullptr) {
      execLog("ROLLBACK;");
      return;
    }

    for (const DeviceState& device : devices) {
      const std::string key = deviceKey(device);
      if (key.empty()) {
        continue;
      }
      bindText(stmt, 1, key);
      bindText(stmt, 2, lower(device.mac));
      bindText(stmt, 3, device.ip);
      bindText(stmt, 4, device.hostname);
      bindText(stmt, 5, device.interface_name);
      bindText(stmt, 6, device.source);
      bindText(stmt, 7, device.neigh_state);
      bindText(stmt, 8, statusToString(device.status));
      api.bind_int64(stmt, 9, unixSeconds(device.first_seen));
      api.bind_int64(stmt, 10, unixSeconds(device.last_seen));
      api.bind_int64(stmt, 11, unixSeconds(device.last_dhcp));
      api.bind_int64(stmt, 12, unixSeconds(device.last_traffic));
      api.bind_int64(stmt, 13, unixSeconds(device.last_rate));
      api.bind_int64(stmt, 14, static_cast<std::int64_t>(device.rx_bytes_total));
      api.bind_int64(stmt, 15, static_cast<std::int64_t>(device.tx_bytes_total));
      api.bind_double(stmt, 16, device.rx_rate_bps);
      api.bind_double(stmt, 17, device.tx_rate_bps);
      bindText(stmt, 18, tagsText(device.tags));
      api.bind_int64(stmt, 19, unixSeconds(nowSystem()));
      const int rc = api.step(stmt);
      if (rc != kSqliteDone) {
        std::cerr << "sqlite: device upsert failed: " << lastError() << '\n';
      }
      api.reset(stmt);
      api.clear_bindings(stmt);
    }
    if (stmt != nullptr) {
      api.finalize(stmt);
    }
    execLog("COMMIT;");
  }

  void insertTraffic(const TrafficSnapshot& snapshot) {
    if (!enabled) {
      return;
    }
    std::lock_guard lock(mutex);
    sqlite3_stmt* stmt = prepare("INSERT INTO traffic_samples(mac, ip, ts, rx_bytes, tx_bytes) VALUES(?, ?, ?, ?, ?);");
    if (stmt == nullptr) {
      return;
    }
    bindText(stmt, 1, lower(snapshot.mac));
    bindText(stmt, 2, snapshot.ip);
    api.bind_int64(stmt, 3, unixSeconds(snapshot.ts));
    api.bind_int64(stmt, 4, static_cast<std::int64_t>(snapshot.rx_bytes));
    api.bind_int64(stmt, 5, static_cast<std::int64_t>(snapshot.tx_bytes));
    if (api.step(stmt) != kSqliteDone) {
      std::cerr << "sqlite: traffic insert failed: " << lastError() << '\n';
    }
    api.finalize(stmt);
  }

  void insertEvent(const Event& event) {
    if (!enabled) {
      return;
    }
    std::lock_guard lock(mutex);
    sqlite3_stmt* stmt = prepare("INSERT OR REPLACE INTO events(id, ts, type, severity, source, message, fields_json) VALUES(?, ?, ?, ?, ?, ?, ?);");
    if (stmt == nullptr) {
      return;
    }
    bindText(stmt, 1, event.id);
    api.bind_int64(stmt, 2, unixSeconds(event.ts));
    bindText(stmt, 3, event.type);
    bindText(stmt, 4, toString(event.severity));
    bindText(stmt, 5, event.source);
    bindText(stmt, 6, event.message);
    bindText(stmt, 7, fieldsJson(event.fields));
    if (api.step(stmt) != kSqliteDone) {
      std::cerr << "sqlite: event insert failed: " << lastError() << '\n';
    }
    api.finalize(stmt);
  }

  void insertWANAttack(const WANAttackEvent& event) {
    if (!enabled) {
      return;
    }
    std::lock_guard lock(mutex);
    sqlite3_stmt* stmt = prepare("INSERT INTO wan_attacks(ts, in_if, src_ip, dst_ip, src_port, dst_port, proto, length, raw) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?);");
    if (stmt == nullptr) {
      return;
    }
    api.bind_int64(stmt, 1, unixSeconds(event.ts));
    bindText(stmt, 2, event.in_if);
    bindText(stmt, 3, event.src_ip);
    bindText(stmt, 4, event.dst_ip);
    bindText(stmt, 5, event.src_port);
    bindText(stmt, 6, event.dst_port);
    bindText(stmt, 7, event.proto);
    bindText(stmt, 8, event.length);
    bindText(stmt, 9, event.raw);
    if (api.step(stmt) != kSqliteDone) {
      std::cerr << "sqlite: wan attack insert failed: " << lastError() << '\n';
    }
    api.finalize(stmt);
  }

  void loadInto(StateStore& state) {
    if (!enabled) {
      return;
    }
    std::lock_guard lock(mutex);
    loadDevices(state);
    loadEvents(state);
    loadWANAttacks(state);
  }

  void loadDevices(StateStore& state) {
    sqlite3_stmt* stmt = prepare(R"sql(
SELECT mac, ip, hostname, interface_name, source, neigh_state, status, first_seen, last_seen, last_dhcp, last_traffic, last_rate, rx_bytes_total, tx_bytes_total, rx_rate_bps, tx_rate_bps, tags
FROM devices
ORDER BY last_seen ASC;
)sql");
    if (stmt == nullptr) {
      return;
    }
    while (api.step(stmt) == kSqliteRow) {
      DeviceState device;
      device.mac = columnText(stmt, 0);
      device.ip = columnText(stmt, 1);
      device.hostname = columnText(stmt, 2);
      device.interface_name = columnText(stmt, 3);
      device.source = columnText(stmt, 4);
      device.neigh_state = columnText(stmt, 5);
      device.status = parseStatus(columnText(stmt, 6));
      device.first_seen = timeFromColumn(stmt, 7, api.column_int64);
      device.last_seen = timeFromColumn(stmt, 8, api.column_int64);
      device.last_dhcp = timeFromColumn(stmt, 9, api.column_int64);
      device.last_traffic = timeFromColumn(stmt, 10, api.column_int64);
      device.last_rate = timeFromColumn(stmt, 11, api.column_int64);
      device.rx_bytes_total = static_cast<std::uint64_t>(api.column_int64(stmt, 12));
      device.tx_bytes_total = static_cast<std::uint64_t>(api.column_int64(stmt, 13));
      device.rx_rate_bps = api.column_double(stmt, 14);
      device.tx_rate_bps = api.column_double(stmt, 15);
      device.tags = parseTags(columnText(stmt, 16));
      state.updateDevice(device);
    }
    api.finalize(stmt);
  }

  DeviceState deviceFromStatement(sqlite3_stmt* stmt) {
    DeviceState device;
    device.mac = columnText(stmt, 0);
    device.ip = columnText(stmt, 1);
    device.hostname = columnText(stmt, 2);
    device.interface_name = columnText(stmt, 3);
    device.source = columnText(stmt, 4);
    device.neigh_state = columnText(stmt, 5);
    device.status = parseStatus(columnText(stmt, 6));
    device.first_seen = timeFromColumn(stmt, 7, api.column_int64);
    device.last_seen = timeFromColumn(stmt, 8, api.column_int64);
    device.last_dhcp = timeFromColumn(stmt, 9, api.column_int64);
    device.last_traffic = timeFromColumn(stmt, 10, api.column_int64);
    device.last_rate = timeFromColumn(stmt, 11, api.column_int64);
    device.rx_bytes_total = static_cast<std::uint64_t>(api.column_int64(stmt, 12));
    device.tx_bytes_total = static_cast<std::uint64_t>(api.column_int64(stmt, 13));
    device.rx_rate_bps = api.column_double(stmt, 14);
    device.tx_rate_bps = api.column_double(stmt, 15);
    device.tags = parseTags(columnText(stmt, 16));
    return device;
  }

  std::vector<DeviceState> devices(std::size_t limit) {
    std::lock_guard lock(mutex);
    sqlite3_stmt* stmt = prepare(R"sql(
SELECT mac, ip, hostname, interface_name, source, neigh_state, status, first_seen, last_seen, last_dhcp, last_traffic, last_rate, rx_bytes_total, tx_bytes_total, rx_rate_bps, tx_rate_bps, tags
FROM devices
ORDER BY last_seen DESC
LIMIT ?;
)sql");
    std::vector<DeviceState> out;
    if (stmt == nullptr) {
      return out;
    }
    api.bind_int64(stmt, 1, static_cast<std::int64_t>(limit == 0 ? 1000 : limit));
    while (api.step(stmt) == kSqliteRow) {
      out.push_back(deviceFromStatement(stmt));
    }
    api.finalize(stmt);
    return out;
  }

  void loadEvents(StateStore& state) {
    sqlite3_stmt* stmt = prepare(R"sql(
SELECT id, ts, type, severity, source, message, fields_json
FROM (SELECT id, ts, type, severity, source, message, fields_json FROM events ORDER BY ts DESC LIMIT ?)
ORDER BY ts ASC;
)sql");
    if (stmt == nullptr) {
      return;
    }
    api.bind_int64(stmt, 1, static_cast<std::int64_t>(config.max_events));
    while (api.step(stmt) == kSqliteRow) {
      Event event;
      event.id = columnText(stmt, 0);
      event.ts = timeFromColumn(stmt, 1, api.column_int64);
      event.type = columnText(stmt, 2);
      event.severity = parseSeverity(columnText(stmt, 3));
      event.source = columnText(stmt, 4);
      event.message = columnText(stmt, 5);
      const std::string persisted_fields = columnText(stmt, 6);
      if (!persisted_fields.empty()) {
        event.fields["fields_json"] = persisted_fields;
      }
      state.addEvent(event);
    }
    api.finalize(stmt);
  }

  Event eventFromStatement(sqlite3_stmt* stmt) {
    Event event;
    event.id = columnText(stmt, 0);
    event.ts = timeFromColumn(stmt, 1, api.column_int64);
    event.type = columnText(stmt, 2);
    event.severity = parseSeverity(columnText(stmt, 3));
    event.source = columnText(stmt, 4);
    event.message = columnText(stmt, 5);
    const std::string persisted_fields = columnText(stmt, 6);
    if (!persisted_fields.empty()) {
      event.fields["fields_json"] = persisted_fields;
    }
    return event;
  }

  std::vector<Event> recentEvents(std::size_t limit) {
    std::lock_guard lock(mutex);
    sqlite3_stmt* stmt = prepare(R"sql(
SELECT id, ts, type, severity, source, message, fields_json
FROM events
ORDER BY ts DESC
LIMIT ?;
)sql");
    std::vector<Event> out;
    if (stmt == nullptr) {
      return out;
    }
    api.bind_int64(stmt, 1, static_cast<std::int64_t>(limit == 0 ? 100 : limit));
    while (api.step(stmt) == kSqliteRow) {
      out.push_back(eventFromStatement(stmt));
    }
    api.finalize(stmt);
    return out;
  }

  void loadWANAttacks(StateStore& state) {
    sqlite3_stmt* stmt = prepare(R"sql(
SELECT ts, in_if, src_ip, dst_ip, src_port, dst_port, proto, length, raw
FROM (SELECT ts, in_if, src_ip, dst_ip, src_port, dst_port, proto, length, raw FROM wan_attacks ORDER BY ts DESC LIMIT ?)
ORDER BY ts ASC;
)sql");
    if (stmt == nullptr) {
      return;
    }
    api.bind_int64(stmt, 1, static_cast<std::int64_t>(config.max_attack_events));
    while (api.step(stmt) == kSqliteRow) {
      WANAttackEvent event;
      event.ts = timeFromColumn(stmt, 0, api.column_int64);
      event.in_if = columnText(stmt, 1);
      event.src_ip = columnText(stmt, 2);
      event.dst_ip = columnText(stmt, 3);
      event.src_port = columnText(stmt, 4);
      event.dst_port = columnText(stmt, 5);
      event.proto = columnText(stmt, 6);
      event.length = columnText(stmt, 7);
      event.raw = columnText(stmt, 8);
      state.addWANAttack(event);
    }
    api.finalize(stmt);
  }

  WANAttackEvent wanAttackFromStatement(sqlite3_stmt* stmt) {
    WANAttackEvent event;
    event.ts = timeFromColumn(stmt, 0, api.column_int64);
    event.in_if = columnText(stmt, 1);
    event.src_ip = columnText(stmt, 2);
    event.dst_ip = columnText(stmt, 3);
    event.src_port = columnText(stmt, 4);
    event.dst_port = columnText(stmt, 5);
    event.proto = columnText(stmt, 6);
    event.length = columnText(stmt, 7);
    event.raw = columnText(stmt, 8);
    return event;
  }

  std::vector<WANAttackEvent> recentWANAttacks(std::size_t limit) {
    std::lock_guard lock(mutex);
    sqlite3_stmt* stmt = prepare(R"sql(
SELECT ts, in_if, src_ip, dst_ip, src_port, dst_port, proto, length, raw
FROM wan_attacks
ORDER BY ts DESC
LIMIT ?;
)sql");
    std::vector<WANAttackEvent> out;
    if (stmt == nullptr) {
      return out;
    }
    api.bind_int64(stmt, 1, static_cast<std::int64_t>(limit == 0 ? 100 : limit));
    while (api.step(stmt) == kSqliteRow) {
      out.push_back(wanAttackFromStatement(stmt));
    }
    api.finalize(stmt);
    return out;
  }

  std::vector<TrafficHistoryPoint> trafficHistory(std::size_t limit) {
    std::lock_guard lock(mutex);
    const std::size_t wanted = limit == 0 ? 180 : std::min<std::size_t>(limit, 720);
    const std::size_t row_limit = std::max<std::size_t>(wanted * 12, wanted);
    sqlite3_stmt* stmt = prepare(R"sql(
SELECT mac, ip, ts, rx_bytes, tx_bytes
FROM (SELECT mac, ip, ts, rx_bytes, tx_bytes, id FROM traffic_samples ORDER BY ts DESC, id DESC LIMIT ?)
ORDER BY ts ASC, id ASC;
)sql");
    std::vector<TrafficHistoryPoint> out;
    if (stmt == nullptr) {
      return out;
    }

    struct PreviousSample {
      std::chrono::system_clock::time_point ts{};
      std::uint64_t rx_bytes = 0;
      std::uint64_t tx_bytes = 0;
    };
    struct Bucket {
      double rx_rate_bps = 0.0;
      double tx_rate_bps = 0.0;
      std::size_t samples = 0;
    };

    std::unordered_map<std::string, PreviousSample> previous_by_device;
    std::map<std::int64_t, Bucket> buckets;
    api.bind_int64(stmt, 1, static_cast<std::int64_t>(row_limit));
    while (api.step(stmt) == kSqliteRow) {
      const std::string mac = columnText(stmt, 0);
      const std::string ip = columnText(stmt, 1);
      const std::int64_t ts_seconds = api.column_int64(stmt, 2);
      const std::uint64_t rx_bytes = static_cast<std::uint64_t>(api.column_int64(stmt, 3));
      const std::uint64_t tx_bytes = static_cast<std::uint64_t>(api.column_int64(stmt, 4));
      const std::string key = !mac.empty() ? "mac:" + lower(mac) : "ip:" + ip;
      if (key == "ip:") {
        continue;
      }
      const auto ts = fromUnixSeconds(ts_seconds);
      const auto previous_it = previous_by_device.find(key);
      if (previous_it != previous_by_device.end()) {
        const PreviousSample& previous = previous_it->second;
        const auto dt = std::chrono::duration_cast<std::chrono::duration<double>>(ts - previous.ts).count();
        const bool reset = rx_bytes < previous.rx_bytes || tx_bytes < previous.tx_bytes;
        if (dt > 0.0 && !reset) {
          const std::int64_t bucket_ts = ts_seconds - (ts_seconds % 5);
          Bucket& bucket = buckets[bucket_ts];
          bucket.rx_rate_bps += static_cast<double>(rx_bytes - previous.rx_bytes) * 8.0 / dt;
          bucket.tx_rate_bps += static_cast<double>(tx_bytes - previous.tx_bytes) * 8.0 / dt;
          ++bucket.samples;
        }
      }
      previous_by_device[key] = PreviousSample{ts, rx_bytes, tx_bytes};
    }
    api.finalize(stmt);

    for (const auto& [bucket_ts, bucket] : buckets) {
      out.push_back(TrafficHistoryPoint{fromUnixSeconds(bucket_ts), bucket.rx_rate_bps, bucket.tx_rate_bps, bucket.samples});
    }
    if (out.size() > wanted) {
      out.erase(out.begin(), out.end() - static_cast<std::ptrdiff_t>(wanted));
    }
    return out;
  }

  std::vector<DeviceTrafficTotal> deviceTrafficTotals(std::chrono::hours window, std::size_t limit) {
    std::lock_guard lock(mutex);
    const auto cutoff = nowSystem() - window;
    sqlite3_stmt* stmt = prepare(R"sql(
SELECT s.mac,
       COALESCE(NULLIF(s.ip, ''), d.ip, '') AS ip,
       COALESCE(d.hostname, '') AS hostname,
       s.ts,
       s.rx_bytes,
       s.tx_bytes
FROM traffic_samples s
LEFT JOIN devices d ON d.device_key = CASE
  WHEN s.mac IS NOT NULL AND s.mac != '' THEN 'mac:' || lower(s.mac)
  ELSE 'ip:' || s.ip
END
WHERE s.ts >= ?
ORDER BY CASE WHEN s.mac IS NOT NULL AND s.mac != '' THEN 'mac:' || lower(s.mac) ELSE 'ip:' || s.ip END,
         s.ts ASC,
         s.id ASC;
)sql");
    std::vector<DeviceTrafficTotal> out;
    if (stmt == nullptr) {
      return out;
    }

    struct Accumulator {
      DeviceTrafficTotal total;
      std::uint64_t previous_rx = 0;
      std::uint64_t previous_tx = 0;
      bool has_previous = false;
    };

    std::unordered_map<std::string, Accumulator> by_device;
    api.bind_int64(stmt, 1, unixSeconds(cutoff));
    while (api.step(stmt) == kSqliteRow) {
      const std::string mac = lower(columnText(stmt, 0));
      const std::string ip = columnText(stmt, 1);
      const std::string key = !mac.empty() ? "mac:" + mac : "ip:" + ip;
      if (key == "ip:") {
        continue;
      }
      const auto ts = timeFromColumn(stmt, 3, api.column_int64);
      const std::uint64_t rx_bytes = static_cast<std::uint64_t>(api.column_int64(stmt, 4));
      const std::uint64_t tx_bytes = static_cast<std::uint64_t>(api.column_int64(stmt, 5));

      Accumulator& acc = by_device[key];
      DeviceTrafficTotal& total = acc.total;
      if (total.samples == 0) {
        total.mac = mac;
        total.ip = ip;
        total.hostname = columnText(stmt, 2);
        total.first_ts = ts;
      } else if (acc.has_previous) {
        total.rx_bytes += rx_bytes >= acc.previous_rx ? rx_bytes - acc.previous_rx : rx_bytes;
        total.tx_bytes += tx_bytes >= acc.previous_tx ? tx_bytes - acc.previous_tx : tx_bytes;
      }
      total.last_ts = ts;
      ++total.samples;
      acc.previous_rx = rx_bytes;
      acc.previous_tx = tx_bytes;
      acc.has_previous = true;
    }
    api.finalize(stmt);

    out.reserve(by_device.size());
    for (auto& [_, acc] : by_device) {
      out.push_back(std::move(acc.total));
    }
    std::sort(out.begin(), out.end(), [](const DeviceTrafficTotal& lhs, const DeviceTrafficTotal& rhs) {
      const std::uint64_t lhs_total = lhs.rx_bytes + lhs.tx_bytes;
      const std::uint64_t rhs_total = rhs.rx_bytes + rhs.tx_bytes;
      if (lhs_total != rhs_total) {
        return lhs_total > rhs_total;
      }
      return lhs.last_ts > rhs.last_ts;
    });
    if (limit > 0 && out.size() > limit) {
      out.resize(limit);
    }
    return out;
  }

  std::int64_t queryInt(const std::string& sql) {
    sqlite3_stmt* stmt = prepare(sql);
    if (stmt == nullptr) {
      return 0;
    }
    std::int64_t value = 0;
    if (api.step(stmt) == kSqliteRow) {
      value = api.column_int64(stmt, 0);
    }
    api.finalize(stmt);
    return value;
  }

  void applyRetention() {
    if (!enabled && lower(config.storage_mode) != "sqlite") {
      return;
    }
    std::lock_guard lock(mutex);
    const int retention_days = std::max(1, config.sqlite_retention_days);
    const auto cutoff = nowSystem() - std::chrono::hours(24 * retention_days);
    const std::int64_t cutoff_seconds = unixSeconds(cutoff);
    execLog("BEGIN IMMEDIATE;");
    deleteOlderThan("events", cutoff_seconds);
    deleteOlderThan("wan_attacks", cutoff_seconds);
    deleteOlderThan("traffic_samples", cutoff_seconds);
    deleteBeyondLimit("events", "id", std::max<std::size_t>(1, config.sqlite_max_events));
    deleteBeyondLimit("wan_attacks", "id", std::max<std::size_t>(1, config.max_attack_events));
    deleteTrafficBeyondDeviceLimit(std::max<std::size_t>(1, config.sqlite_max_traffic_points_per_device));
    execLog("COMMIT;");
    enforceSizeLimit();
  }

  void deleteOlderThan(const std::string& table, std::int64_t cutoff_seconds) {
    sqlite3_stmt* stmt = prepare("DELETE FROM " + table + " WHERE ts < ?;");
    if (stmt == nullptr) {
      return;
    }
    api.bind_int64(stmt, 1, cutoff_seconds);
    if (api.step(stmt) != kSqliteDone) {
      std::cerr << "sqlite: retention delete failed for " << table << ": " << lastError() << '\n';
    }
    api.finalize(stmt);
  }

  void deleteBeyondLimit(const std::string& table, const std::string& id_column, std::size_t limit) {
    const std::string sql = "DELETE FROM " + table + " WHERE " + id_column + " IN "
        "(SELECT " + id_column + " FROM " + table + " ORDER BY ts DESC, " + id_column + " DESC LIMIT -1 OFFSET ?);";
    sqlite3_stmt* stmt = prepare(sql);
    if (stmt == nullptr) {
      return;
    }
    api.bind_int64(stmt, 1, static_cast<std::int64_t>(limit));
    if (api.step(stmt) != kSqliteDone) {
      std::cerr << "sqlite: retention trim failed for " << table << ": " << lastError() << '\n';
    }
    api.finalize(stmt);
  }

  void deleteTrafficBeyondDeviceLimit(std::size_t limit) {
    sqlite3_stmt* stmt = prepare(R"sql(
DELETE FROM traffic_samples WHERE id IN (
  SELECT id FROM (
    SELECT id,
           ROW_NUMBER() OVER (
             PARTITION BY CASE WHEN mac IS NOT NULL AND mac != '' THEN mac ELSE ip END
             ORDER BY ts DESC, id DESC
           ) AS rn
    FROM traffic_samples
  ) WHERE rn > ?
);
)sql");
    if (stmt == nullptr) {
      return;
    }
    api.bind_int64(stmt, 1, static_cast<std::int64_t>(limit));
    if (api.step(stmt) != kSqliteDone) {
      std::cerr << "sqlite: traffic retention trim failed: " << lastError() << '\n';
    }
    api.finalize(stmt);
  }

  std::int64_t databaseBytes() {
    execLog("PRAGMA wal_checkpoint(PASSIVE);");
    const std::int64_t page_count = queryInt("PRAGMA page_count;");
    const std::int64_t page_size = queryInt("PRAGMA page_size;");
    return page_count * page_size;
  }

  void pruneOldRows(const std::string& table, std::size_t limit) {
    const std::string sql = "DELETE FROM " + table + " WHERE id IN (SELECT id FROM " + table + " ORDER BY ts ASC, id ASC LIMIT ?);";
    sqlite3_stmt* stmt = prepare(sql);
    if (stmt == nullptr) {
      return;
    }
    api.bind_int64(stmt, 1, static_cast<std::int64_t>(limit));
    api.step(stmt);
    api.finalize(stmt);
  }

  void enforceSizeLimit() {
    const std::int64_t max_bytes = static_cast<std::int64_t>(std::max(1, config.sqlite_max_db_mb)) * 1024LL * 1024LL;
    if (databaseBytes() <= max_bytes) {
      return;
    }

    execLog("PRAGMA wal_checkpoint(TRUNCATE);");
    for (int round = 0; round < 12 && databaseBytes() > max_bytes; ++round) {
      execLog("BEGIN IMMEDIATE;");
      pruneOldRows("traffic_samples", 1000);
      pruneOldRows("events", 250);
      pruneOldRows("wan_attacks", 250);
      execLog("COMMIT;");
      execLog("PRAGMA incremental_vacuum(256);");
    }
    const std::int64_t final_bytes = databaseBytes();
    if (final_bytes > max_bytes) {
      std::cerr << "sqlite: database remains above configured size cap: " << final_bytes << " > " << max_bytes << " bytes\n";
    }
  }
};

SqliteStore::SqliteStore(Config config) : impl_(std::make_unique<Impl>(std::move(config))) {}

SqliteStore::~SqliteStore() = default;

bool SqliteStore::enabled() const {
  return impl_ != nullptr && impl_->enabled;
}

void SqliteStore::loadInto(StateStore& state) {
  if (enabled()) {
    impl_->loadInto(state);
  }
}

void SqliteStore::upsertDevices(const std::vector<DeviceState>& devices) {
  if (enabled()) {
    impl_->upsertDevices(devices);
  }
}

void SqliteStore::insertTraffic(const TrafficSnapshot& snapshot) {
  if (enabled()) {
    impl_->insertTraffic(snapshot);
  }
}

void SqliteStore::insertEvent(const Event& event) {
  if (enabled()) {
    impl_->insertEvent(event);
  }
}

void SqliteStore::insertWANAttack(const WANAttackEvent& event) {
  if (enabled()) {
    impl_->insertWANAttack(event);
  }
}

void SqliteStore::applyRetention() {
  if (enabled()) {
    impl_->applyRetention();
  }
}

std::vector<DeviceState> SqliteStore::devices(std::size_t limit) const {
  if (!enabled()) {
    return {};
  }
  return impl_->devices(limit);
}

std::vector<Event> SqliteStore::recentEvents(std::size_t limit) const {
  if (!enabled()) {
    return {};
  }
  return impl_->recentEvents(limit);
}

std::vector<WANAttackEvent> SqliteStore::recentWANAttacks(std::size_t limit) const {
  if (!enabled()) {
    return {};
  }
  return impl_->recentWANAttacks(limit);
}

std::vector<TrafficHistoryPoint> SqliteStore::trafficHistory(std::size_t limit) const {
  if (!enabled()) {
    return {};
  }
  return impl_->trafficHistory(limit);
}

std::vector<DeviceTrafficTotal> SqliteStore::deviceTrafficTotals(std::chrono::hours window, std::size_t limit) const {
  if (!enabled()) {
    return {};
  }
  return impl_->deviceTrafficTotals(window, limit);
}

}  // namespace netmon
