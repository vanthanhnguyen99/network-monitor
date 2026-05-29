#include "netmon/syslog_server.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "netmon/net_utils.hpp"
#include "netmon/utils.hpp"

namespace netmon {
namespace {

void closeIfOpen(int& fd) {
  if (fd >= 0) {
    close(fd);
    fd = -1;
  }
}

sockaddr_in makeSockaddr(const Address& address) {
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(address.port);
  if (inet_pton(AF_INET, address.host.c_str(), &addr.sin_addr) != 1) {
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
  }
  return addr;
}

std::string peerIp(const sockaddr_in& addr) {
  char buffer[INET_ADDRSTRLEN]{};
  if (inet_ntop(AF_INET, &addr.sin_addr, buffer, sizeof(buffer)) == nullptr) {
    return {};
  }
  return buffer;
}

bool waitReadable(int fd, std::atomic<bool>& running) {
  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(fd, &readfds);
  timeval tv{};
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  const int rc = select(fd + 1, &readfds, nullptr, nullptr, &tv);
  return running.load() && rc > 0 && FD_ISSET(fd, &readfds);
}

}  // namespace

SyslogServer::SyslogServer(Config config, LogHandler handler) : config_(std::move(config)), handler_(std::move(handler)) {}

SyslogServer::~SyslogServer() {
  stop();
}

void SyslogServer::start() {
  running_ = true;
  if (config_.enable_udp) {
    udp_thread_ = std::thread(&SyslogServer::runUdp, this);
  }
  if (config_.enable_tcp) {
    tcp_thread_ = std::thread(&SyslogServer::runTcp, this);
  }
}

void SyslogServer::stop() {
  const bool was_running = running_.exchange(false);
  closeIfOpen(udp_fd_);
  closeIfOpen(tcp_fd_);
  if (udp_thread_.joinable()) {
    udp_thread_.join();
  }
  if (tcp_thread_.joinable()) {
    tcp_thread_.join();
  }
  std::lock_guard lock(client_threads_mutex_);
  for (std::thread& thread : client_threads_) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  client_threads_.clear();
  if (was_running) {
    std::cerr << "syslog: stopped\n";
  }
}

void SyslogServer::runUdp() {
  const auto parsed = parseAddress(config_.syslog_udp_addr);
  if (!parsed) {
    std::cerr << "syslog udp: invalid address " << config_.syslog_udp_addr << '\n';
    return;
  }

  udp_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_fd_ < 0) {
    std::cerr << "syslog udp: socket failed: " << std::strerror(errno) << '\n';
    return;
  }
  int yes = 1;
  setsockopt(udp_fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  const sockaddr_in bind_addr = makeSockaddr(*parsed);
  if (bind(udp_fd_, reinterpret_cast<const sockaddr*>(&bind_addr), sizeof(bind_addr)) != 0) {
    std::cerr << "syslog udp: bind failed on " << config_.syslog_udp_addr << ": " << std::strerror(errno) << '\n';
    closeIfOpen(udp_fd_);
    return;
  }

  std::cerr << "syslog udp: listening on " << config_.syslog_udp_addr << '\n';
  std::vector<char> buffer(config_.max_syslog_line_length + 1);
  while (running_.load()) {
    if (!waitReadable(udp_fd_, running_)) {
      continue;
    }
    sockaddr_in remote{};
    socklen_t remote_len = sizeof(remote);
    const ssize_t n = recvfrom(udp_fd_, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&remote), &remote_len);
    if (n <= 0) {
      continue;
    }
    const std::string ip = peerIp(remote);
    if (!shouldAccept(ip)) {
      continue;
    }
    deliver(std::string_view(buffer.data(), static_cast<std::size_t>(n)), ip);
  }
}

void SyslogServer::runTcp() {
  const auto parsed = parseAddress(config_.syslog_tcp_addr);
  if (!parsed) {
    std::cerr << "syslog tcp: invalid address " << config_.syslog_tcp_addr << '\n';
    return;
  }

  tcp_fd_ = socket(AF_INET, SOCK_STREAM, 0);
  if (tcp_fd_ < 0) {
    std::cerr << "syslog tcp: socket failed: " << std::strerror(errno) << '\n';
    return;
  }
  int yes = 1;
  setsockopt(tcp_fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  const sockaddr_in bind_addr = makeSockaddr(*parsed);
  if (bind(tcp_fd_, reinterpret_cast<const sockaddr*>(&bind_addr), sizeof(bind_addr)) != 0) {
    std::cerr << "syslog tcp: bind failed on " << config_.syslog_tcp_addr << ": " << std::strerror(errno) << '\n';
    closeIfOpen(tcp_fd_);
    return;
  }
  if (listen(tcp_fd_, 16) != 0) {
    std::cerr << "syslog tcp: listen failed: " << std::strerror(errno) << '\n';
    closeIfOpen(tcp_fd_);
    return;
  }

  std::cerr << "syslog tcp: listening on " << config_.syslog_tcp_addr << '\n';
  while (running_.load()) {
    if (!waitReadable(tcp_fd_, running_)) {
      continue;
    }
    sockaddr_in remote{};
    socklen_t remote_len = sizeof(remote);
    const int client_fd = accept(tcp_fd_, reinterpret_cast<sockaddr*>(&remote), &remote_len);
    if (client_fd < 0) {
      continue;
    }
    const std::string ip = peerIp(remote);
    if (!shouldAccept(ip)) {
      close(client_fd);
      continue;
    }
    std::lock_guard lock(client_threads_mutex_);
    client_threads_.emplace_back(&SyslogServer::handleTcpClient, this, client_fd, ip);
  }
}

void SyslogServer::handleTcpClient(int client_fd, std::string peer_ip) {
  timeval tv{};
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  std::string pending;
  std::vector<char> buffer(1024);
  while (running_.load()) {
    const ssize_t n = recv(client_fd, buffer.data(), buffer.size(), 0);
    if (n == 0) {
      break;
    }
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        continue;
      }
      break;
    }
    pending.append(buffer.data(), static_cast<std::size_t>(n));
    std::size_t newline = std::string::npos;
    while ((newline = pending.find('\n')) != std::string::npos) {
      std::string line = pending.substr(0, newline);
      pending.erase(0, newline + 1);
      deliver(line, peer_ip);
    }
    if (pending.size() > config_.max_syslog_line_length) {
      pending.clear();
    }
  }
  if (!pending.empty()) {
    deliver(pending, peer_ip);
  }
  close(client_fd);
}

bool SyslogServer::shouldAccept(const std::string& peer_ip) const {
  return isTrustedPeer(config_.trusted_router_ips, peer_ip);
}

void SyslogServer::deliver(std::string_view line, const std::string& peer_ip) const {
  const auto bounded = boundedLine(line, config_.max_syslog_line_length);
  if (!bounded || bounded->empty()) {
    return;
  }
  try {
    handler_(*bounded, peer_ip);
  } catch (const std::exception& ex) {
    std::cerr << "syslog: handler failed: " << ex.what() << '\n';
  }
}

}  // namespace netmon
