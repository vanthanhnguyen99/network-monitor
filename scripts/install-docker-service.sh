#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="openwrt-netmon-lite"
SERVICE_FILE=""
FORCE="false"
START_SERVICE="true"

usage() {
  cat <<'EOF'
Usage: scripts/install-docker-service.sh [options]

Install OpenWRT Netmon Lite as a systemd service that starts the Docker Compose
stack on boot. The application still runs inside Docker containers.

Options:
  --name NAME     systemd service name. Default: openwrt-netmon-lite
  --force         Overwrite an existing service file
  --no-start      Install and enable the service, but do not start it now
  -h, --help      Show this help

Examples:
  sudo scripts/install-docker-service.sh
  sudo scripts/install-docker-service.sh --force
  sudo scripts/install-docker-service.sh --name openwrt-netmon-lite
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)
      SERVICE_NAME="${2:?missing service name}"
      shift 2
      ;;
    --force)
      FORCE="true"
      shift
      ;;
    --no-start)
      START_SERVICE="false"
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

if [[ "${EUID}" -ne 0 ]]; then
  echo "This installer must run as root. Try: sudo $0" >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl is required to install the service" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to run the service" >&2
  exit 1
fi

if [[ ! -f "$PROJECT_ROOT/docker-compose.yml" ]]; then
  echo "docker-compose.yml not found at $PROJECT_ROOT" >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "docker compose plugin is required" >&2
  exit 1
fi

SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
DOCKER_BIN="$(command -v docker)"

if [[ -e "$SERVICE_FILE" && "$FORCE" != "true" ]]; then
  echo "Service already exists: $SERVICE_FILE"
  echo "No changes were made. Use --force to overwrite it."

  if systemctl is-enabled "${SERVICE_NAME}.service" >/dev/null 2>&1; then
    echo "Service is already enabled."
  else
    echo "Service exists but is not enabled. Enable it with: sudo systemctl enable ${SERVICE_NAME}.service"
  fi

  if systemctl is-active "${SERVICE_NAME}.service" >/dev/null 2>&1; then
    echo "Service is already running."
  else
    echo "Service exists but is not running. Start it with: sudo systemctl start ${SERVICE_NAME}.service"
  fi
  exit 0
fi

tmp_unit="$(mktemp)"
trap 'rm -f "$tmp_unit"' EXIT

cat > "$tmp_unit" <<EOF
# Managed by openwrt-netmon-lite scripts/install-docker-service.sh
[Unit]
Description=OpenWRT Netmon Lite Docker Compose Service
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$PROJECT_ROOT
ExecStart=$DOCKER_BIN compose -f $PROJECT_ROOT/docker-compose.yml up -d --remove-orphans
ExecStop=$DOCKER_BIN compose -f $PROJECT_ROOT/docker-compose.yml down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

install -m 0644 "$tmp_unit" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service"

if [[ "$START_SERVICE" == "true" ]]; then
  systemctl start "${SERVICE_NAME}.service"
fi

echo "Installed systemd service: $SERVICE_FILE"
systemctl --no-pager --full status "${SERVICE_NAME}.service" || true

cat <<EOF

Useful commands:
  sudo systemctl start ${SERVICE_NAME}.service
  sudo systemctl stop ${SERVICE_NAME}.service
  sudo systemctl restart ${SERVICE_NAME}.service
  sudo systemctl status ${SERVICE_NAME}.service

Dashboard:
  http://localhost:8080
EOF
