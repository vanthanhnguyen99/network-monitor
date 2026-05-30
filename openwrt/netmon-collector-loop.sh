#!/bin/sh

[ -r /etc/netmon-collector.conf ] && . /etc/netmon-collector.conf

DEFAULT_INTERVAL="${1:-${NETMON_INTERVAL_SECONDS:-5}}"
DEVICES_INTERVAL="${NETMON_DEVICES_INTERVAL_SECONDS:-$DEFAULT_INTERVAL}"
TRAFFIC_INTERVAL="${NETMON_TRAFFIC_INTERVAL_SECONDS:-$DEFAULT_INTERVAL}"
IFACE_INTERVAL="${NETMON_IFACE_INTERVAL_SECONDS:-1}"
DEVICES_SCRIPT="${NETMON_DEVICES_SCRIPT:-/usr/bin/netmon-devices.sh}"
TRAFFIC_SCRIPT="${NETMON_TRAFFIC_SCRIPT:-/usr/bin/netmon-traffic.sh}"
IFACE_SCRIPT="${NETMON_IFACE_SCRIPT:-/usr/bin/netmon-iface.sh}"

normalize_interval() {
  value="$1"
  fallback="$2"
  case "$value" in
    ''|*[!0-9]*)
      value="$fallback"
      ;;
  esac
  [ "$value" -lt 1 ] && value="$fallback"
  printf '%s\n' "$value"
}

DEVICES_INTERVAL="$(normalize_interval "$DEVICES_INTERVAL" 5)"
TRAFFIC_INTERVAL="$(normalize_interval "$TRAFFIC_INTERVAL" 1)"
IFACE_INTERVAL="$(normalize_interval "$IFACE_INTERVAL" 1)"

logger -t NETMON_COLLECTOR "starting iface_interval=${IFACE_INTERVAL}s devices_interval=${DEVICES_INTERVAL}s traffic_interval=${TRAFFIC_INTERVAL}s"

last_iface=0
last_devices=0
last_traffic=0

while :; do
  now="$(date +%s)"

  if [ -x "$IFACE_SCRIPT" ] && [ $((now - last_iface)) -ge "$IFACE_INTERVAL" ]; then
    "$IFACE_SCRIPT"
    last_iface="$now"
  fi

  if [ -x "$DEVICES_SCRIPT" ] && [ $((now - last_devices)) -ge "$DEVICES_INTERVAL" ]; then
    "$DEVICES_SCRIPT"
    last_devices="$now"
  fi

  if [ -x "$TRAFFIC_SCRIPT" ] && [ $((now - last_traffic)) -ge "$TRAFFIC_INTERVAL" ]; then
    "$TRAFFIC_SCRIPT"
    last_traffic="$now"
  fi

  sleep 1
done
