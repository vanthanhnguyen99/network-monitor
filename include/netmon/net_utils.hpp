#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace netmon {

struct Address {
  std::string host;
  std::uint16_t port = 0;
};

std::optional<Address> parseAddress(const std::string& value);
bool isTrustedPeer(const std::vector<std::string>& trusted_ips, const std::string& peer_ip);

}  // namespace netmon
