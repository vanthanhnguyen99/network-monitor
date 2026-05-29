#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace netmon {

std::string trim(std::string_view value);
std::string lower(std::string_view value);
std::string upper(std::string_view value);
std::string stripInlineComment(std::string_view value);
std::string stripQuotes(std::string_view value);
bool parseBool(std::string_view value, bool fallback = false);
std::uint64_t parseUint64(std::string_view value, std::uint64_t fallback = 0);
int parseInt(std::string_view value, int fallback = 0);
std::optional<std::string> boundedLine(std::string_view line, std::size_t max_length);
std::vector<std::string> split(std::string_view value, char delimiter);

std::chrono::system_clock::time_point fromUnixSeconds(std::int64_t seconds);
std::string formatIso8601(std::chrono::system_clock::time_point tp);
std::chrono::system_clock::time_point nowSystem();

std::string jsonEscape(std::string_view value);
std::string jsonQuote(std::string_view value);

std::unordered_map<std::string, std::string> parseKeyValueFields(std::string_view value);

}  // namespace netmon
