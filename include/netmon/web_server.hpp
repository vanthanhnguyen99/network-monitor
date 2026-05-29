#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>

#include "netmon/config.hpp"
#include "netmon/state_store.hpp"

namespace netmon {

class WebServer {
 public:
  WebServer(Config config, StateStore& state, std::chrono::steady_clock::time_point started_at);
  ~WebServer();

  WebServer(const WebServer&) = delete;
  WebServer& operator=(const WebServer&) = delete;

  void start();
  void stop();
  void broadcast(const std::string& message);

 private:
  struct Request {
    std::string method;
    std::string target;
    std::string path;
    std::string query;
    std::unordered_map<std::string, std::string> headers;
  };

  void run();
  void handleClient(int client_fd);
  bool parseRequest(const std::string& raw, Request& request) const;
  void routeHttp(int client_fd, const Request& request);
  void handleWebSocket(int client_fd, const Request& request);

  bool authorized(const Request& request) const;
  std::string queryParam(const Request& request, const std::string& key) const;
  void sendResponse(int client_fd, int status, const std::string& status_text, const std::string& content_type, const std::string& body) const;
  void sendJson(int client_fd, const std::string& body) const;
  void sendNotFound(int client_fd) const;
  void sendUnauthorized(int client_fd) const;
  std::string readStaticFile(const std::string& path, std::string& content_type) const;

  std::string healthJson() const;
  std::string summaryJson() const;
  std::string devicesJson() const;
  std::string eventsJson(std::size_t limit) const;
  std::string wanAttacksJson(std::size_t limit) const;

  void addWebSocketClient(int fd);
  void removeWebSocketClient(int fd);
  bool sendWebSocketText(int fd, const std::string& message) const;

  Config config_;
  StateStore& state_;
  std::chrono::steady_clock::time_point started_at_;
  std::atomic<bool> running_{false};
  int listen_fd_ = -1;
  std::thread thread_;
  mutable std::mutex ws_mutex_;
  std::set<int> ws_clients_;
};

std::string websocketAcceptKey(const std::string& key);

}  // namespace netmon
