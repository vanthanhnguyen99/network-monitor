#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "netmon/config.hpp"
#include "netmon/log_parser.hpp"
#include "netmon/state_store.hpp"
#include "netmon/syslog_server.hpp"
#include "netmon/web_server.hpp"

namespace netmon {

class App {
 public:
  explicit App(Config config);
  ~App();

  App(const App&) = delete;
  App& operator=(const App&) = delete;

  void start();
  void stop();
  void wait();
  void handleLog(std::string line, std::string peer_ip);

 private:
  void runCleanupLoop();
  void applyParseResult(const ParseResult& result, const std::string& peer_ip);
  void publishUpdate(const std::string& type);

  Config config_;
  StateStore state_;
  LogParser parser_;
  std::chrono::steady_clock::time_point started_at_;
  std::unique_ptr<SyslogServer> syslog_server_;
  std::unique_ptr<WebServer> web_server_;
  std::atomic<bool> running_{false};
  std::thread cleanup_thread_;
  std::mutex wait_mutex_;
  std::condition_variable wait_cv_;
};

}  // namespace netmon
