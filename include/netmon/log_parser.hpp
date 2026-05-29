#pragma once

#include <string>
#include <string_view>
#include <unordered_map>

namespace netmon {

struct ParseResult {
  bool matched = false;
  std::string type = "unknown";
  std::unordered_map<std::string, std::string> fields;
  std::string raw;
};

class LogParser {
 public:
  ParseResult parse(std::string_view line) const;

  static std::unordered_map<std::string, std::string> parseKeyValues(std::string_view value);

 private:
  ParseResult parseWANAttack(std::string_view line) const;
  ParseResult parseDHCP(std::string_view line) const;
  ParseResult parseNetDev(std::string_view line) const;
  ParseResult parseNetTraffic(std::string_view line) const;
  ParseResult parseWanLink(std::string_view line) const;
  ParseResult parseHostapd(std::string_view line) const;
};

}  // namespace netmon
