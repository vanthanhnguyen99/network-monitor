#include "netmon/log_parser.hpp"

#include <optional>
#include <regex>
#include <sstream>
#include <vector>

#include "netmon/utils.hpp"

namespace netmon {
namespace {

std::string stripSyslogPriority(std::string_view line) {
  std::string text = trim(line);
  if (!text.empty() && text.front() == '<') {
    const std::size_t end = text.find('>');
    if (end != std::string::npos && end < 8) {
      text = trim(std::string_view(text).substr(end + 1));
    }
  }
  return text;
}

bool looksLikeIpv4(const std::string& value) {
  int dots = 0;
  for (const char ch : value) {
    if (ch == '.') {
      ++dots;
    } else if (std::isdigit(static_cast<unsigned char>(ch)) == 0) {
      return false;
    }
  }
  return dots == 3;
}

bool looksLikeMac(const std::string& value) {
  static const std::regex mac_regex(R"(^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$)");
  return std::regex_match(value, mac_regex);
}

std::string eventNameForDhcpMethod(const std::string& method) {
  if (method == "DHCPREQUEST") {
    return "dhcp_request";
  }
  if (method == "DHCPACK") {
    return "dhcp_ack";
  }
  if (method == "DHCPDISCOVER") {
    return "dhcp_discover";
  }
  if (method == "DHCPOFFER") {
    return "dhcp_offer";
  }
  return "dhcp";
}

std::string afterTag(std::string_view line, std::string_view tag) {
  const std::size_t tag_pos = line.find(tag);
  if (tag_pos == std::string_view::npos) {
    return {};
  }
  std::size_t pos = tag_pos + tag.size();
  if (pos < line.size() && line[pos] == ':') {
    ++pos;
  }
  return trim(line.substr(pos));
}

bool isNumericToken(const std::string& value) {
  if (value.empty()) {
    return false;
  }
  for (const char ch : value) {
    if (std::isdigit(static_cast<unsigned char>(ch)) == 0) {
      return false;
    }
  }
  return true;
}

std::vector<std::string> splitSeparated(std::string_view line, char separator) {
  std::vector<std::string> out;
  std::string current;
  bool in_quote = false;
  char quote = '\0';
  for (const char ch : line) {
    if ((ch == '"' || ch == '\'') && (!in_quote || quote == ch)) {
      if (!in_quote) {
        in_quote = true;
        quote = ch;
      } else {
        in_quote = false;
        quote = '\0';
      }
      continue;
    }
    if (ch == separator && !in_quote) {
      out.push_back(stripQuotes(trim(current)));
      current.clear();
      continue;
    }
    current.push_back(ch);
  }
  out.push_back(stripQuotes(trim(current)));
  return out;
}

std::vector<std::string> splitLooseColumns(std::string_view line) {
  std::string text = trim(line);
  if (text.find(',') != std::string::npos) {
    return splitSeparated(text, ',');
  }
  if (text.find(';') != std::string::npos) {
    return splitSeparated(text, ';');
  }

  std::vector<std::string> out;
  std::istringstream stream(text);
  std::string token;
  while (stream >> token) {
    out.push_back(stripQuotes(token));
  }
  return out;
}

std::optional<std::unordered_map<std::string, std::string>> parseNlbwCsv(std::string_view payload) {
  const std::vector<std::string> tokens = splitLooseColumns(payload);
  if (tokens.empty()) {
    return std::nullopt;
  }

  for (const std::string& token : tokens) {
    const std::string name = lower(token);
    if (name == "rx_bytes" || name == "tx_bytes" || name == "downld." || name == "upload") {
      return std::nullopt;
    }
  }

  std::optional<std::size_t> mac_index;
  std::optional<std::size_t> ip_index;
  for (std::size_t i = 0; i < tokens.size(); ++i) {
    if (!mac_index && looksLikeMac(tokens[i])) {
      mac_index = i;
    }
    if (!ip_index && looksLikeIpv4(tokens[i])) {
      ip_index = i;
    }
  }

  if (!mac_index && !ip_index) {
    return std::nullopt;
  }

  const std::size_t anchor = mac_index ? *mac_index : *ip_index;
  std::vector<std::string> numeric;
  for (std::size_t i = anchor + 1; i < tokens.size(); ++i) {
    if (isNumericToken(tokens[i])) {
      numeric.push_back(tokens[i]);
    }
  }

  if (numeric.size() < 4) {
    return std::nullopt;
  }

  std::unordered_map<std::string, std::string> fields;
  if (mac_index) {
    fields["mac"] = lower(tokens[*mac_index]);
  }
  if (ip_index) {
    fields["ip"] = tokens[*ip_index];
  }
  fields["conns"] = numeric[0];
  fields["rx_bytes"] = numeric[1];
  fields["rx_pkts"] = numeric[2];
  fields["tx_bytes"] = numeric[3];
  if (numeric.size() > 4) {
    fields["tx_pkts"] = numeric[4];
  }
  return fields;
}

}  // namespace

ParseResult LogParser::parse(std::string_view line) const {
  ParseResult result;
  result.raw = stripSyslogPriority(line);
  const std::string text = result.raw;

  for (const auto parser : {
           &LogParser::parseWANAttack,
           &LogParser::parseNetDev,
           &LogParser::parseNetIface,
           &LogParser::parseNetTraffic,
           &LogParser::parseDHCP,
           &LogParser::parseWanLink,
           &LogParser::parseHostapd,
       }) {
    ParseResult parsed = (this->*parser)(text);
    if (parsed.matched) {
      parsed.raw = text;
      return parsed;
    }
  }

  return result;
}

std::unordered_map<std::string, std::string> LogParser::parseKeyValues(std::string_view value) {
  return parseKeyValueFields(value);
}

ParseResult LogParser::parseWANAttack(std::string_view line) const {
  ParseResult result;
  const std::string marker = "WAN_ATTACK:";
  const std::size_t pos = line.find(marker);
  if (pos == std::string_view::npos) {
    return result;
  }

  const std::string payload = trim(line.substr(pos + marker.size()));
  const auto fields = parseKeyValueFields(payload);
  result.matched = true;
  result.type = "wan_attack";
  result.fields = fields;

  const auto copy_if_present = [&](const std::string& source, const std::string& dest) {
    const auto it = fields.find(source);
    if (it != fields.end()) {
      result.fields[dest] = it->second;
    }
  };
  copy_if_present("IN", "in_if");
  copy_if_present("OUT", "out_if");
  copy_if_present("SRC", "src_ip");
  copy_if_present("DST", "dst_ip");
  copy_if_present("SPT", "src_port");
  copy_if_present("DPT", "dst_port");
  copy_if_present("PROTO", "proto");
  copy_if_present("LEN", "len");
  return result;
}

ParseResult LogParser::parseDHCP(std::string_view line) const {
  ParseResult result;
  if (line.find("dnsmasq-dhcp") == std::string_view::npos) {
    return result;
  }

  static const std::regex dhcp_regex(R"((DHCPREQUEST|DHCPACK|DHCPDISCOVER|DHCPOFFER)\(([^)]*)\)\s+(.+)$)");
  std::match_results<std::string_view::const_iterator> match;
  if (!std::regex_search(line.begin(), line.end(), match, dhcp_regex)) {
    return result;
  }

  const std::string method = match[1].str();
  result.matched = true;
  result.type = "dhcp";
  result.fields["event"] = eventNameForDhcpMethod(method);
  result.fields["method"] = method;
  result.fields["interface"] = match[2].str();

  const std::vector<std::string> tokens = split(match[3].str(), ' ');
  std::vector<std::string> clean_tokens;
  for (const std::string& token : tokens) {
    const std::string clean = trim(token);
    if (!clean.empty()) {
      clean_tokens.push_back(clean);
    }
  }

  if (!clean_tokens.empty()) {
    if (looksLikeIpv4(clean_tokens[0])) {
      result.fields["ip"] = clean_tokens[0];
      if (clean_tokens.size() > 1 && looksLikeMac(clean_tokens[1])) {
        result.fields["mac"] = lower(clean_tokens[1]);
      }
      if (clean_tokens.size() > 2) {
        result.fields["hostname"] = clean_tokens[2];
      }
    } else if (looksLikeMac(clean_tokens[0])) {
      result.fields["mac"] = lower(clean_tokens[0]);
      if (clean_tokens.size() > 1) {
        result.fields["hostname"] = clean_tokens[1];
      }
    }
  }
  return result;
}

ParseResult LogParser::parseNetDev(std::string_view line) const {
  ParseResult result;
  if (line.find("NETDEV") == std::string_view::npos) {
    return result;
  }

  result.matched = true;
  result.type = "netdev";
  result.fields = parseKeyValueFields(afterTag(line, "NETDEV"));
  if (const auto it = result.fields.find("mac"); it != result.fields.end()) {
    it->second = lower(it->second);
  }
  if (const auto it = result.fields.find("host"); it != result.fields.end()) {
    result.fields["hostname"] = it->second;
  }
  return result;
}

ParseResult LogParser::parseNetIface(std::string_view line) const {
  ParseResult result;
  if (line.find("NETIFACE") == std::string_view::npos) {
    return result;
  }

  result.matched = true;
  result.type = "netiface";
  result.fields = parseKeyValueFields(afterTag(line, "NETIFACE"));
  if (const auto it = result.fields.find("if"); it != result.fields.end()) {
    result.fields["interface"] = it->second;
  } else if (const auto iface_it = result.fields.find("iface"); iface_it != result.fields.end()) {
    result.fields["interface"] = iface_it->second;
  }
  return result;
}

ParseResult LogParser::parseNetTraffic(std::string_view line) const {
  ParseResult result;
  if (line.find("NETTRAFFIC") == std::string_view::npos) {
    return result;
  }

  result.matched = true;
  result.type = "nettraffic";
  result.fields = parseKeyValueFields(afterTag(line, "NETTRAFFIC"));
  if (const auto it = result.fields.find("mac"); it != result.fields.end()) {
    it->second = lower(it->second);
  }
  if (const auto it = result.fields.find("csv"); it != result.fields.end()) {
    if (const auto parsed_csv = parseNlbwCsv(it->second)) {
      for (const auto& [key, value] : *parsed_csv) {
        result.fields[key] = value;
      }
    }
  }
  return result;
}

ParseResult LogParser::parseWanLink(std::string_view line) const {
  ParseResult result;
  const std::string text = lower(line);
  if (text.find("netifd") == std::string::npos && text.find("pppd") == std::string::npos) {
    return result;
  }
  if (text.find("wan") == std::string::npos && text.find("pppoe") == std::string::npos) {
    return result;
  }

  result.matched = true;
  result.type = "wan";
  result.fields["message"] = std::string(line);
  if (text.find("down") != std::string::npos || text.find("fail") != std::string::npos || text.find("disconnect") != std::string::npos) {
    result.fields["state"] = "down";
  } else if (text.find("up") != std::string::npos || text.find("connect") != std::string::npos) {
    result.fields["state"] = "up";
  }
  return result;
}

ParseResult LogParser::parseHostapd(std::string_view line) const {
  ParseResult result;
  if (line.find("hostapd") == std::string_view::npos) {
    return result;
  }
  const std::string text = std::string(line);
  const bool connected = text.find("AP-STA-CONNECTED") != std::string::npos;
  const bool disconnected = text.find("AP-STA-DISCONNECTED") != std::string::npos;
  if (!connected && !disconnected) {
    return result;
  }

  static const std::regex wifi_regex(R"((AP-STA-CONNECTED|AP-STA-DISCONNECTED)\s+([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}))");
  std::smatch match;
  if (!std::regex_search(text, match, wifi_regex)) {
    return result;
  }

  result.matched = true;
  result.type = "wifi";
  result.fields["event"] = connected ? "wifi_connected" : "wifi_disconnected";
  result.fields["mac"] = lower(match[2].str());
  return result;
}

}  // namespace netmon
