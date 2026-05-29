#include "netmon/net_utils.hpp"

#include <charconv>

#include "netmon/utils.hpp"

namespace netmon {

std::optional<Address> parseAddress(const std::string& value) {
  const std::string text = trim(value);
  const std::size_t colon = text.rfind(':');
  if (colon == std::string::npos) {
    return std::nullopt;
  }

  Address address;
  address.host = text.substr(0, colon);
  if (address.host.empty()) {
    address.host = "0.0.0.0";
  }

  const std::string port_text = text.substr(colon + 1);
  int port = 0;
  const auto* first = port_text.data();
  const auto* last = port_text.data() + port_text.size();
  const auto result = std::from_chars(first, last, port);
  if (result.ec != std::errc() || result.ptr != last || port <= 0 || port > 65535) {
    return std::nullopt;
  }

  address.port = static_cast<std::uint16_t>(port);
  return address;
}

bool isTrustedPeer(const std::vector<std::string>& trusted_ips, const std::string& peer_ip) {
  if (trusted_ips.empty()) {
    return true;
  }
  const std::string normalized_peer = trim(peer_ip);
  for (const std::string& trusted : trusted_ips) {
    if (trim(trusted) == normalized_peer) {
      return true;
    }
  }
  return false;
}

}  // namespace netmon
