#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

#include "netmon/app.hpp"
#include "netmon/config.hpp"

namespace {

std::atomic<bool> stop_requested{false};

void handleSignal(int) {
  stop_requested = true;
}

void printUsage(const char* argv0) {
  std::cout << "Usage: " << argv0 << " [--config path]\n";
}

}  // namespace

int main(int argc, char** argv) {
  std::string config_path = "./config.example.yaml";
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--config" && i + 1 < argc) {
      config_path = argv[++i];
    } else if (arg == "--help" || arg == "-h") {
      printUsage(argv[0]);
      return 0;
    } else {
      std::cerr << "unknown argument: " << arg << '\n';
      printUsage(argv[0]);
      return 2;
    }
  }

  std::signal(SIGINT, handleSignal);
  std::signal(SIGTERM, handleSignal);

  netmon::Config config = netmon::loadConfig(config_path);
  if (config.enable_debug_file_log) {
    std::cerr << "debug file logging is disabled in this MVP build; using stdout/stderr only\n";
  }

  try {
    netmon::App app(config);
    app.start();
    while (!stop_requested.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    app.stop();
  } catch (const std::exception& ex) {
    std::cerr << "fatal: " << ex.what() << '\n';
    return 2;
  }
  return 0;
}
