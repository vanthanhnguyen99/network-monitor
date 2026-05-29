#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "netmon/config.hpp"

namespace netmon {

class SyslogServer {
 public:
  using LogHandler = std::function<void(std::string line, std::string peer_ip)>;

  SyslogServer(Config config, LogHandler handler);
  ~SyslogServer();

  SyslogServer(const SyslogServer&) = delete;
  SyslogServer& operator=(const SyslogServer&) = delete;

  void start();
  void stop();

 private:
  void runUdp();
  void runTcp();
  void handleTcpClient(int client_fd, std::string peer_ip);
  bool shouldAccept(const std::string& peer_ip) const;
  void deliver(std::string_view line, const std::string& peer_ip) const;

  Config config_;
  LogHandler handler_;
  std::atomic<bool> running_{false};
  int udp_fd_ = -1;
  int tcp_fd_ = -1;
  std::thread udp_thread_;
  std::thread tcp_thread_;
  std::mutex client_threads_mutex_;
  std::vector<std::thread> client_threads_;
};

}  // namespace netmon
