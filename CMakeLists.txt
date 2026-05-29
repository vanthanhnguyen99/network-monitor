cmake_minimum_required(VERSION 3.20)

project(openwrt-netmon-lite VERSION 0.1.0 LANGUAGES CXX)

option(NETMON_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(netmon_core
  src/app.cpp
  src/config.cpp
  src/log_parser.cpp
  src/net_utils.cpp
  src/state_store.cpp
  src/syslog_server.cpp
  src/utils.cpp
  src/web_server.cpp
)

target_include_directories(netmon_core PUBLIC include)
target_compile_definitions(netmon_core PUBLIC NETMON_VERSION="${PROJECT_VERSION}")
target_compile_options(netmon_core PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(netmon_core PUBLIC pthread)

if(NETMON_ENABLE_SANITIZERS)
  target_compile_options(netmon_core PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(netmon_core PUBLIC -fsanitize=address,undefined)
endif()

add_executable(openwrt-netmon-lite src/main.cpp)
target_link_libraries(openwrt-netmon-lite PRIVATE netmon_core)
target_compile_options(openwrt-netmon-lite PRIVATE -Wall -Wextra -Wpedantic)

enable_testing()

add_executable(netmon_tests tests/netmon_tests.cpp)
target_link_libraries(netmon_tests PRIVATE netmon_core)
target_compile_options(netmon_tests PRIVATE -Wall -Wextra -Wpedantic)

add_test(NAME netmon_tests COMMAND netmon_tests)
