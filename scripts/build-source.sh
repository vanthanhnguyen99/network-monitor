#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="build"
BUILD_TYPE="Release"
RUN_TESTS="true"
ENABLE_SANITIZERS="false"
CLEAN="false"

usage() {
  cat <<'EOF'
Usage: scripts/build-source.sh [options]

Build the OpenWRT Netmon Lite C++ source code with CMake.

Options:
  --build-dir DIR       Build directory to use. Default: build
  --type TYPE           CMake build type. Default: Release
  --debug               Shortcut for --type Debug --build-dir build-debug
  --sanitizers          Enable AddressSanitizer and UndefinedBehaviorSanitizer
  --no-tests            Build only; skip ctest
  --clean               Remove the selected build directory before building
  -h, --help            Show this help

Examples:
  scripts/build-source.sh
  scripts/build-source.sh --debug --sanitizers
  scripts/build-source.sh --build-dir build-release --type Release --no-tests
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir)
      BUILD_DIR="${2:?missing build directory}"
      shift 2
      ;;
    --type)
      BUILD_TYPE="${2:?missing build type}"
      shift 2
      ;;
    --debug)
      BUILD_TYPE="Debug"
      BUILD_DIR="build-debug"
      shift
      ;;
    --sanitizers)
      ENABLE_SANITIZERS="true"
      shift
      ;;
    --no-tests)
      RUN_TESTS="false"
      shift
      ;;
    --clean)
      CLEAN="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if ! command -v cmake >/dev/null 2>&1; then
  echo "cmake is required to build the source code" >&2
  exit 1
fi

if [[ "$CLEAN" == "true" ]]; then
  rm -rf "$BUILD_DIR"
fi

SANITIZER_FLAG="OFF"
if [[ "$ENABLE_SANITIZERS" == "true" ]]; then
  SANITIZER_FLAG="ON"
fi

JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

cmake -S . -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
  -DNETMON_ENABLE_SANITIZERS="$SANITIZER_FLAG"

cmake --build "$BUILD_DIR" -j"$JOBS"

if [[ "$RUN_TESTS" == "true" ]]; then
  ctest --test-dir "$BUILD_DIR" --output-on-failure
fi

echo
echo "Build complete: $BUILD_DIR/openwrt-netmon-lite"
