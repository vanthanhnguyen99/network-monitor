#pragma once

#include <chrono>
#include <string>

#include "netmon/config.hpp"
#include "netmon/runtime_stats.hpp"
#include "netmon/state_store.hpp"

namespace netmon {

std::string renderPrometheusMetrics(const Config& config,
                                    const StateStore& state,
                                    const RuntimeStats& stats,
                                    std::chrono::steady_clock::time_point started_at);

}  // namespace netmon
