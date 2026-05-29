#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="true"
FOLLOW_LOGS="false"

usage() {
  cat <<'EOF'
Usage: scripts/start-docker-service.sh [options]

Start the OpenWRT Netmon Lite Docker Compose service.

Options:
  --no-build      Start the existing image without rebuilding
  --logs          Follow service logs after startup
  -h, --help      Show this help

Examples:
  scripts/start-docker-service.sh
  scripts/start-docker-service.sh --no-build
  scripts/start-docker-service.sh --logs
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build)
      BUILD="false"
      shift
      ;;
    --logs)
      FOLLOW_LOGS="true"
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

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to start the service" >&2
  exit 1
fi

cd "$PROJECT_ROOT"

if [[ "$BUILD" == "true" ]]; then
  docker compose up -d --build
else
  docker compose up -d
fi

docker compose ps

cat <<'EOF'

Dashboard: http://localhost:8080
Syslog UDP: 0.0.0.0:1514/udp

Stop service:
  docker compose down
EOF

if [[ "$FOLLOW_LOGS" == "true" ]]; then
  docker compose logs -f openwrt-netmon-lite
fi
