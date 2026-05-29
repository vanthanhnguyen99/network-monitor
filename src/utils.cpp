#include "netmon/utils.hpp"

#include <algorithm>
#include <charconv>
#include <ctime>
#include <iomanip>
#include <sstream>

#include "netmon/types.hpp"

namespace netmon {

std::string trim(std::string_view value) {
  auto begin = value.begin();
  auto end = value.end();
  while (begin != end && std::isspace(static_cast<unsigned char>(*begin)) != 0) {
    ++begin;
  }
  while (begin != end && std::isspace(static_cast<unsigned char>(*(end - 1))) != 0) {
    --end;
  }
  return std::string(begin, end);
}

std::string lower(std::string_view value) {
  std::string out(value);
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return out;
}

std::string upper(std::string_view value) {
  std::string out(value);
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char ch) {
    return static_cast<char>(std::toupper(ch));
  });
  return out;
}

std::string stripInlineComment(std::string_view value) {
  bool in_single = false;
  bool in_double = false;
  for (std::size_t i = 0; i < value.size(); ++i) {
    const char ch = value[i];
    if (ch == '\'' && !in_double) {
      in_single = !in_single;
    } else if (ch == '"' && !in_single) {
      in_double = !in_double;
    } else if (ch == '#' && !in_single && !in_double) {
      return trim(value.substr(0, i));
    }
  }
  return trim(value);
}

std::string stripQuotes(std::string_view value) {
  std::string out = trim(value);
  if (out.size() >= 2) {
    const char first = out.front();
    const char last = out.back();
    if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
      return out.substr(1, out.size() - 2);
    }
  }
  return out;
}

bool parseBool(std::string_view value, bool fallback) {
  const std::string normalized = lower(trim(value));
  if (normalized == "true" || normalized == "yes" || normalized == "on" || normalized == "1") {
    return true;
  }
  if (normalized == "false" || normalized == "no" || normalized == "off" || normalized == "0") {
    return false;
  }
  return fallback;
}

std::uint64_t parseUint64(std::string_view value, std::uint64_t fallback) {
  const std::string text = trim(value);
  std::uint64_t parsed = 0;
  const auto* first = text.data();
  const auto* last = text.data() + text.size();
  const auto result = std::from_chars(first, last, parsed);
  if (result.ec == std::errc() && result.ptr == last) {
    return parsed;
  }
  return fallback;
}

int parseInt(std::string_view value, int fallback) {
  const std::string text = trim(value);
  int parsed = 0;
  const auto* first = text.data();
  const auto* last = text.data() + text.size();
  const auto result = std::from_chars(first, last, parsed);
  if (result.ec == std::errc() && result.ptr == last) {
    return parsed;
  }
  return fallback;
}

std::optional<std::string> boundedLine(std::string_view line, std::size_t max_length) {
  if (line.size() > max_length) {
    return std::nullopt;
  }
  std::string out(line);
  while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == '\0')) {
    out.pop_back();
  }
  return out;
}

std::vector<std::string> split(std::string_view value, char delimiter) {
  std::vector<std::string> out;
  std::size_t start = 0;
  while (start <= value.size()) {
    const std::size_t pos = value.find(delimiter, start);
    if (pos == std::string_view::npos) {
      out.push_back(std::string(value.substr(start)));
      break;
    }
    out.push_back(std::string(value.substr(start, pos - start)));
    start = pos + 1;
  }
  return out;
}

std::chrono::system_clock::time_point fromUnixSeconds(std::int64_t seconds) {
  return std::chrono::system_clock::time_point{std::chrono::seconds{seconds}};
}

std::string formatIso8601(std::chrono::system_clock::time_point tp) {
  if (tp.time_since_epoch().count() == 0) {
    return "";
  }
  const std::time_t raw = std::chrono::system_clock::to_time_t(tp);
  std::tm tm{};
  gmtime_r(&raw, &tm);
  std::ostringstream out;
  out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
  return out.str();
}

std::chrono::system_clock::time_point nowSystem() {
  return std::chrono::system_clock::now();
}

std::string jsonEscape(std::string_view value) {
  std::string out;
  out.reserve(value.size() + 8);
  for (const unsigned char ch : value) {
    switch (ch) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\b':
        out += "\\b";
        break;
      case '\f':
        out += "\\f";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (ch < 0x20) {
          std::ostringstream escaped;
          escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(ch);
          out += escaped.str();
        } else {
          out.push_back(static_cast<char>(ch));
        }
    }
  }
  return out;
}

std::string jsonQuote(std::string_view value) {
  return '"' + jsonEscape(value) + '"';
}

std::unordered_map<std::string, std::string> parseKeyValueFields(std::string_view value) {
  std::unordered_map<std::string, std::string> fields;
  std::size_t pos = 0;
  while (pos < value.size()) {
    while (pos < value.size() && std::isspace(static_cast<unsigned char>(value[pos])) != 0) {
      ++pos;
    }
    if (pos >= value.size()) {
      break;
    }

    const std::size_t key_begin = pos;
    while (pos < value.size() && value[pos] != '=' && std::isspace(static_cast<unsigned char>(value[pos])) == 0) {
      ++pos;
    }
    if (pos >= value.size() || value[pos] != '=') {
      while (pos < value.size() && std::isspace(static_cast<unsigned char>(value[pos])) == 0) {
        ++pos;
      }
      continue;
    }

    std::string key = std::string(value.substr(key_begin, pos - key_begin));
    ++pos;

    if (key == "csv") {
      fields[key] = trim(value.substr(pos));
      break;
    }

    std::string parsed_value;
    if (pos < value.size() && (value[pos] == '"' || value[pos] == '\'')) {
      const char quote = value[pos++];
      const std::size_t value_begin = pos;
      while (pos < value.size() && value[pos] != quote) {
        ++pos;
      }
      parsed_value = std::string(value.substr(value_begin, pos - value_begin));
      if (pos < value.size() && value[pos] == quote) {
        ++pos;
      }
    } else {
      const std::size_t value_begin = pos;
      while (pos < value.size() && std::isspace(static_cast<unsigned char>(value[pos])) == 0) {
        ++pos;
      }
      parsed_value = std::string(value.substr(value_begin, pos - value_begin));
    }
    fields[std::move(key)] = std::move(parsed_value);
  }
  return fields;
}

std::string toString(DeviceStatus status) {
  switch (status) {
    case DeviceStatus::Online:
      return "online";
    case DeviceStatus::Idle:
      return "idle";
    case DeviceStatus::Offline:
      return "offline";
    case DeviceStatus::Unknown:
      return "unknown";
  }
  return "unknown";
}

std::string toString(EventSeverity severity) {
  switch (severity) {
    case EventSeverity::Info:
      return "info";
    case EventSeverity::Warning:
      return "warning";
    case EventSeverity::Critical:
      return "critical";
  }
  return "info";
}

}  // namespace netmon
