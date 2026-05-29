#include "netmon/web_server.hpp"

#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <netinet/in.h>
#include <sstream>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <vector>

#include "netmon/net_utils.hpp"
#include "netmon/utils.hpp"

#ifndef NETMON_VERSION
#define NETMON_VERSION "0.1.0"
#endif

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

bool sendAll(int fd, const char* data, std::size_t size) {
  std::size_t sent = 0;
  while (sent < size) {
    const ssize_t n = send(fd, data + sent, size - sent, MSG_NOSIGNAL);
    if (n <= 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    sent += static_cast<std::size_t>(n);
  }
  return true;
}

bool sendAll(int fd, const std::string& data) {
  return sendAll(fd, data.data(), data.size());
}

std::string headerValue(const std::unordered_map<std::string, std::string>& headers, const std::string& key) {
  const auto it = headers.find(lower(key));
  if (it == headers.end()) {
    return {};
  }
  return it->second;
}

std::string contentTypeFor(const std::string& path) {
  if (path.ends_with(".html")) {
    return "text/html; charset=utf-8";
  }
  if (path.ends_with(".css")) {
    return "text/css; charset=utf-8";
  }
  if (path.ends_with(".js")) {
    return "application/javascript; charset=utf-8";
  }
  if (path.ends_with(".svg")) {
    return "image/svg+xml";
  }
  return "application/octet-stream";
}

std::string jsonFields(const std::unordered_map<std::string, std::string>& fields) {
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

std::string tagsJson(const std::vector<std::string>& tags) {
  std::ostringstream out;
  out << '[';
  for (std::size_t i = 0; i < tags.size(); ++i) {
    if (i != 0) {
      out << ',';
    }
    out << jsonQuote(tags[i]);
  }
  out << ']';
  return out.str();
}

std::string deviceJson(const DeviceState& device) {
  std::ostringstream out;
  out << '{'
      << "\"mac\":" << jsonQuote(device.mac) << ','
      << "\"ip\":" << jsonQuote(device.ip) << ','
      << "\"hostname\":" << jsonQuote(device.hostname) << ','
      << "\"interface_name\":" << jsonQuote(device.interface_name) << ','
      << "\"source\":" << jsonQuote(device.source) << ','
      << "\"neigh_state\":" << jsonQuote(device.neigh_state) << ','
      << "\"status\":" << jsonQuote(toString(device.status)) << ','
      << "\"first_seen\":" << jsonQuote(formatIso8601(device.first_seen)) << ','
      << "\"last_seen\":" << jsonQuote(formatIso8601(device.last_seen)) << ','
      << "\"last_dhcp\":" << jsonQuote(formatIso8601(device.last_dhcp)) << ','
      << "\"last_traffic\":" << jsonQuote(formatIso8601(device.last_traffic)) << ','
      << "\"last_rate\":" << jsonQuote(formatIso8601(device.last_rate)) << ','
      << "\"rx_bytes_total\":" << device.rx_bytes_total << ','
      << "\"tx_bytes_total\":" << device.tx_bytes_total << ','
      << "\"rx_rate_bps\":" << device.rx_rate_bps << ','
      << "\"tx_rate_bps\":" << device.tx_rate_bps << ','
      << "\"tags\":" << tagsJson(device.tags)
      << '}';
  return out.str();
}

std::string eventJson(const Event& event) {
  std::ostringstream out;
  out << '{'
      << "\"id\":" << jsonQuote(event.id) << ','
      << "\"ts\":" << jsonQuote(formatIso8601(event.ts)) << ','
      << "\"type\":" << jsonQuote(event.type) << ','
      << "\"severity\":" << jsonQuote(toString(event.severity)) << ','
      << "\"source\":" << jsonQuote(event.source) << ','
      << "\"message\":" << jsonQuote(event.message) << ','
      << "\"fields\":" << jsonFields(event.fields)
      << '}';
  return out.str();
}

std::string wanAttackJson(const WANAttackEvent& event) {
  std::ostringstream out;
  out << '{'
      << "\"ts\":" << jsonQuote(formatIso8601(event.ts)) << ','
      << "\"in_if\":" << jsonQuote(event.in_if) << ','
      << "\"src_ip\":" << jsonQuote(event.src_ip) << ','
      << "\"dst_ip\":" << jsonQuote(event.dst_ip) << ','
      << "\"src_port\":" << jsonQuote(event.src_port) << ','
      << "\"dst_port\":" << jsonQuote(event.dst_port) << ','
      << "\"proto\":" << jsonQuote(event.proto) << ','
      << "\"length\":" << jsonQuote(event.length) << ','
      << "\"raw\":" << jsonQuote(event.raw)
      << '}';
  return out.str();
}

std::array<std::uint8_t, 20> sha1(const std::string& input) {
  auto rol = [](std::uint32_t value, std::uint32_t bits) {
    return (value << bits) | (value >> (32U - bits));
  };

  std::vector<std::uint8_t> message(input.begin(), input.end());
  const std::uint64_t bit_len = static_cast<std::uint64_t>(message.size()) * 8ULL;
  message.push_back(0x80);
  while ((message.size() % 64) != 56) {
    message.push_back(0);
  }
  for (int i = 7; i >= 0; --i) {
    message.push_back(static_cast<std::uint8_t>((bit_len >> (i * 8)) & 0xffU));
  }

  std::uint32_t h0 = 0x67452301U;
  std::uint32_t h1 = 0xEFCDAB89U;
  std::uint32_t h2 = 0x98BADCFEU;
  std::uint32_t h3 = 0x10325476U;
  std::uint32_t h4 = 0xC3D2E1F0U;

  for (std::size_t chunk = 0; chunk < message.size(); chunk += 64) {
    std::array<std::uint32_t, 80> w{};
    for (std::size_t i = 0; i < 16; ++i) {
      const std::size_t j = chunk + i * 4;
      w[i] = (static_cast<std::uint32_t>(message[j]) << 24U) |
             (static_cast<std::uint32_t>(message[j + 1]) << 16U) |
             (static_cast<std::uint32_t>(message[j + 2]) << 8U) |
             static_cast<std::uint32_t>(message[j + 3]);
    }
    for (std::size_t i = 16; i < 80; ++i) {
      w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    std::uint32_t a = h0;
    std::uint32_t b = h1;
    std::uint32_t c = h2;
    std::uint32_t d = h3;
    std::uint32_t e = h4;

    for (std::size_t i = 0; i < 80; ++i) {
      std::uint32_t f = 0;
      std::uint32_t k = 0;
      if (i < 20) {
        f = (b & c) | ((~b) & d);
        k = 0x5A827999U;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1U;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDCU;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6U;
      }
      const std::uint32_t temp = rol(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = rol(b, 30);
      b = a;
      a = temp;
    }

    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }

  std::array<std::uint8_t, 20> digest{};
  const std::array<std::uint32_t, 5> words{h0, h1, h2, h3, h4};
  for (std::size_t i = 0; i < words.size(); ++i) {
    digest[i * 4] = static_cast<std::uint8_t>((words[i] >> 24U) & 0xffU);
    digest[i * 4 + 1] = static_cast<std::uint8_t>((words[i] >> 16U) & 0xffU);
    digest[i * 4 + 2] = static_cast<std::uint8_t>((words[i] >> 8U) & 0xffU);
    digest[i * 4 + 3] = static_cast<std::uint8_t>(words[i] & 0xffU);
  }
  return digest;
}

std::string base64Encode(const std::uint8_t* data, std::size_t size) {
  static constexpr char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((size + 2) / 3) * 4);
  for (std::size_t i = 0; i < size; i += 3) {
    const std::uint32_t octet_a = data[i];
    const std::uint32_t octet_b = i + 1 < size ? data[i + 1] : 0;
    const std::uint32_t octet_c = i + 2 < size ? data[i + 2] : 0;
    const std::uint32_t triple = (octet_a << 16U) | (octet_b << 8U) | octet_c;
    out.push_back(table[(triple >> 18U) & 0x3fU]);
    out.push_back(table[(triple >> 12U) & 0x3fU]);
    out.push_back(i + 1 < size ? table[(triple >> 6U) & 0x3fU] : '=');
    out.push_back(i + 2 < size ? table[triple & 0x3fU] : '=');
  }
  return out;
}

}  // namespace

WebServer::WebServer(Config config, StateStore& state, std::chrono::steady_clock::time_point started_at)
    : config_(std::move(config)), state_(state), started_at_(started_at) {}

WebServer::~WebServer() {
  stop();
}

void WebServer::start() {
  running_ = true;
  thread_ = std::thread(&WebServer::run, this);
}

void WebServer::stop() {
  running_ = false;
  closeIfOpen(listen_fd_);
  if (thread_.joinable()) {
    thread_.join();
  }
  std::lock_guard lock(ws_mutex_);
  for (int fd : ws_clients_) {
    close(fd);
  }
  ws_clients_.clear();
}

void WebServer::broadcast(const std::string& message) {
  std::vector<int> failed;
  std::lock_guard lock(ws_mutex_);
  for (int fd : ws_clients_) {
    if (!sendWebSocketText(fd, message)) {
      failed.push_back(fd);
    }
  }
  for (int fd : failed) {
    close(fd);
    ws_clients_.erase(fd);
  }
}

void WebServer::run() {
  const auto parsed = parseAddress(config_.http_addr);
  if (!parsed) {
    std::cerr << "web: invalid address " << config_.http_addr << '\n';
    return;
  }

  listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd_ < 0) {
    std::cerr << "web: socket failed: " << std::strerror(errno) << '\n';
    return;
  }
  int yes = 1;
  setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  const sockaddr_in bind_addr = makeSockaddr(*parsed);
  if (bind(listen_fd_, reinterpret_cast<const sockaddr*>(&bind_addr), sizeof(bind_addr)) != 0) {
    std::cerr << "web: bind failed on " << config_.http_addr << ": " << std::strerror(errno) << '\n';
    closeIfOpen(listen_fd_);
    return;
  }
  if (listen(listen_fd_, 64) != 0) {
    std::cerr << "web: listen failed: " << std::strerror(errno) << '\n';
    closeIfOpen(listen_fd_);
    return;
  }
  std::cerr << "web: listening on " << config_.http_addr << '\n';

  while (running_.load()) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(listen_fd_, &readfds);
    timeval tv{};
    tv.tv_sec = 1;
    const int rc = select(listen_fd_ + 1, &readfds, nullptr, nullptr, &tv);
    if (!running_.load()) {
      break;
    }
    if (rc <= 0 || !FD_ISSET(listen_fd_, &readfds)) {
      continue;
    }
    const int client_fd = accept(listen_fd_, nullptr, nullptr);
    if (client_fd < 0) {
      continue;
    }
    std::thread(&WebServer::handleClient, this, client_fd).detach();
  }
}

void WebServer::handleClient(int client_fd) {
  timeval tv{};
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  std::string raw;
  std::array<char, 1024> buffer{};
  while (raw.find("\r\n\r\n") == std::string::npos && raw.size() < 16384) {
    const ssize_t n = recv(client_fd, buffer.data(), buffer.size(), 0);
    if (n <= 0) {
      close(client_fd);
      return;
    }
    raw.append(buffer.data(), static_cast<std::size_t>(n));
  }

  Request request;
  if (!parseRequest(raw, request)) {
    sendResponse(client_fd, 400, "Bad Request", "application/json", "{\"error\":\"bad_request\"}");
    close(client_fd);
    return;
  }

  if (request.path == "/ws") {
    handleWebSocket(client_fd, request);
    return;
  }

  routeHttp(client_fd, request);
  close(client_fd);
}

bool WebServer::parseRequest(const std::string& raw, Request& request) const {
  std::istringstream stream(raw);
  std::string line;
  if (!std::getline(stream, line)) {
    return false;
  }
  if (!line.empty() && line.back() == '\r') {
    line.pop_back();
  }
  std::istringstream first_line(line);
  if (!(first_line >> request.method >> request.target)) {
    return false;
  }
  const std::size_t query_pos = request.target.find('?');
  request.path = query_pos == std::string::npos ? request.target : request.target.substr(0, query_pos);
  request.query = query_pos == std::string::npos ? std::string{} : request.target.substr(query_pos + 1);

  while (std::getline(stream, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (line.empty()) {
      break;
    }
    const std::size_t colon = line.find(':');
    if (colon == std::string::npos) {
      continue;
    }
    request.headers[lower(trim(line.substr(0, colon)))] = trim(line.substr(colon + 1));
  }
  return true;
}

void WebServer::routeHttp(int client_fd, const Request& request) {
  if (request.method != "GET") {
    sendResponse(client_fd, 405, "Method Not Allowed", "application/json", "{\"error\":\"method_not_allowed\"}");
    return;
  }

  if (request.path.rfind("/api/", 0) == 0 && !authorized(request)) {
    sendUnauthorized(client_fd);
    return;
  }

  if (request.path == "/api/health") {
    sendJson(client_fd, healthJson());
  } else if (request.path == "/api/summary") {
    sendJson(client_fd, summaryJson());
  } else if (request.path == "/api/devices") {
    sendJson(client_fd, devicesJson());
  } else if (request.path == "/api/events") {
    const std::size_t limit = static_cast<std::size_t>(parseUint64(queryParam(request, "limit"), 100));
    sendJson(client_fd, eventsJson(std::min<std::size_t>(limit, 1000)));
  } else if (request.path == "/api/wan-attacks") {
    const std::size_t limit = static_cast<std::size_t>(parseUint64(queryParam(request, "limit"), 100));
    sendJson(client_fd, wanAttacksJson(std::min<std::size_t>(limit, 1000)));
  } else if (request.path == "/" || request.path == "/index.html" || request.path == "/app.js" || request.path == "/style.css") {
    std::string content_type;
    const std::string path = request.path == "/" ? "/index.html" : request.path;
    const std::string body = readStaticFile(path, content_type);
    if (body.empty()) {
      sendNotFound(client_fd);
    } else {
      sendResponse(client_fd, 200, "OK", content_type, body);
    }
  } else {
    sendNotFound(client_fd);
  }
}

void WebServer::handleWebSocket(int client_fd, const Request& request) {
  if (!authorized(request)) {
    sendUnauthorized(client_fd);
    close(client_fd);
    return;
  }
  const std::string upgrade = lower(headerValue(request.headers, "upgrade"));
  const std::string key = headerValue(request.headers, "sec-websocket-key");
  if (upgrade != "websocket" || key.empty()) {
    sendResponse(client_fd, 400, "Bad Request", "application/json", "{\"error\":\"websocket_required\"}");
    close(client_fd);
    return;
  }

  std::ostringstream response;
  response << "HTTP/1.1 101 Switching Protocols\r\n"
           << "Upgrade: websocket\r\n"
           << "Connection: Upgrade\r\n"
           << "Sec-WebSocket-Accept: " << websocketAcceptKey(key) << "\r\n\r\n";
  if (!sendAll(client_fd, response.str())) {
    close(client_fd);
    return;
  }

  addWebSocketClient(client_fd);
  sendWebSocketText(client_fd, "{\"type\":\"connected\",\"payload\":{}}");

  timeval tv{};
  tv.tv_sec = 15;
  tv.tv_usec = 0;
  setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  std::array<char, 256> buffer{};
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
  }
  removeWebSocketClient(client_fd);
  close(client_fd);
}

bool WebServer::authorized(const Request& request) const {
  if (config_.dashboard_token.empty()) {
    return true;
  }
  if (headerValue(request.headers, "x-netmon-token") == config_.dashboard_token) {
    return true;
  }
  return queryParam(request, "token") == config_.dashboard_token;
}

std::string WebServer::queryParam(const Request& request, const std::string& key) const {
  for (const std::string& part : split(request.query, '&')) {
    const std::size_t eq = part.find('=');
    if (eq == std::string::npos) {
      continue;
    }
    if (part.substr(0, eq) == key) {
      return part.substr(eq + 1);
    }
  }
  return {};
}

void WebServer::sendResponse(int client_fd, int status, const std::string& status_text, const std::string& content_type, const std::string& body) const {
  std::ostringstream response;
  response << "HTTP/1.1 " << status << ' ' << status_text << "\r\n"
           << "Content-Type: " << content_type << "\r\n"
           << "Content-Length: " << body.size() << "\r\n"
           << "Connection: close\r\n"
           << "Cache-Control: no-store\r\n"
           << "X-Content-Type-Options: nosniff\r\n"
           << "\r\n"
           << body;
  sendAll(client_fd, response.str());
}

void WebServer::sendJson(int client_fd, const std::string& body) const {
  sendResponse(client_fd, 200, "OK", "application/json; charset=utf-8", body);
}

void WebServer::sendNotFound(int client_fd) const {
  sendResponse(client_fd, 404, "Not Found", "application/json; charset=utf-8", "{\"error\":\"not_found\"}");
}

void WebServer::sendUnauthorized(int client_fd) const {
  sendResponse(client_fd, 401, "Unauthorized", "application/json; charset=utf-8", "{\"error\":\"unauthorized\"}");
}

std::string WebServer::readStaticFile(const std::string& path, std::string& content_type) const {
  if (path.find("..") != std::string::npos) {
    return {};
  }
  const std::string relative = path.empty() || path.front() != '/' ? path : path.substr(1);
  const std::string full_path = config_.web_root + "/" + relative;
  content_type = contentTypeFor(full_path);
  std::ifstream input(full_path, std::ios::binary);
  if (!input) {
    return {};
  }
  std::ostringstream out;
  out << input.rdbuf();
  return out.str();
}

std::string WebServer::healthJson() const {
  const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - started_at_).count();
  std::ostringstream out;
  out << "{\"ok\":true,\"uptime_seconds\":" << uptime << ",\"version\":" << jsonQuote(NETMON_VERSION) << '}';
  return out.str();
}

std::string WebServer::summaryJson() const {
  const Summary summary = state_.summary();
  std::ostringstream out;
  out << '{'
      << "\"active_devices\":" << summary.active_devices << ','
      << "\"idle_devices\":" << summary.idle_devices << ','
      << "\"offline_devices\":" << summary.offline_devices << ','
      << "\"unknown_devices\":" << summary.unknown_devices << ','
      << "\"wan_attack_5m\":" << summary.wan_attack_5m << ','
      << "\"rx_rate_bps\":" << summary.rx_rate_bps << ','
      << "\"tx_rate_bps\":" << summary.tx_rate_bps << ','
      << "\"last_log_ts\":" << jsonQuote(formatIso8601(summary.last_log_ts))
      << '}';
  return out.str();
}

std::string WebServer::devicesJson() const {
  const std::vector<DeviceState> devices = state_.devices();
  std::ostringstream out;
  out << '[';
  for (std::size_t i = 0; i < devices.size(); ++i) {
    if (i != 0) {
      out << ',';
    }
    out << deviceJson(devices[i]);
  }
  out << ']';
  return out.str();
}

std::string WebServer::eventsJson(std::size_t limit) const {
  const std::vector<Event> events = state_.recentEvents(limit);
  std::ostringstream out;
  out << '[';
  bool first = true;
  for (auto it = events.rbegin(); it != events.rend(); ++it) {
    if (!first) {
      out << ',';
    }
    first = false;
    out << eventJson(*it);
  }
  out << ']';
  return out.str();
}

std::string WebServer::wanAttacksJson(std::size_t limit) const {
  const std::vector<WANAttackEvent> attacks = state_.recentWANAttacks(limit);
  std::ostringstream out;
  out << '[';
  bool first = true;
  for (auto it = attacks.rbegin(); it != attacks.rend(); ++it) {
    if (!first) {
      out << ',';
    }
    first = false;
    out << wanAttackJson(*it);
  }
  out << ']';
  return out.str();
}

void WebServer::addWebSocketClient(int fd) {
  std::lock_guard lock(ws_mutex_);
  ws_clients_.insert(fd);
}

void WebServer::removeWebSocketClient(int fd) {
  std::lock_guard lock(ws_mutex_);
  ws_clients_.erase(fd);
}

bool WebServer::sendWebSocketText(int fd, const std::string& message) const {
  std::string frame;
  frame.push_back(static_cast<char>(0x81));
  const std::size_t len = message.size();
  if (len < 126) {
    frame.push_back(static_cast<char>(len));
  } else if (len <= 0xffff) {
    frame.push_back(static_cast<char>(126));
    frame.push_back(static_cast<char>((len >> 8U) & 0xffU));
    frame.push_back(static_cast<char>(len & 0xffU));
  } else {
    frame.push_back(static_cast<char>(127));
    for (int i = 7; i >= 0; --i) {
      frame.push_back(static_cast<char>((static_cast<std::uint64_t>(len) >> (i * 8)) & 0xffU));
    }
  }
  frame += message;
  return sendAll(fd, frame);
}

std::string websocketAcceptKey(const std::string& key) {
  static const std::string guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  const auto digest = sha1(key + guid);
  return base64Encode(digest.data(), digest.size());
}

}  // namespace netmon
