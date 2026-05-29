#!/bin/sh

INTERVAL="${1:-${NETMON_INTERVAL_SECONDS:-5}}"
DEVICES_SCRIPT="${NETMON_DEVICES_SCRIPT:-/usr/bin/netmon-devices.sh}"
TRAFFIC_SCRIPT="${NETMON_TRAFFIC_SCRIPT:-/usr/bin/netmon-traffic.sh}"

case "$INTERVAL" in
  ''|*[!0-9]*)
    INTERVAL=5
    ;;
esac

[ "$INTERVAL" -lt 1 ] && INTERVAL=5

logger -t NETMON_COLLECTOR "starting interval=${INTERVAL}s"

while :; do
  start_ts="$(date +%s)"

  if [ -x "$DEVICES_SCRIPT" ]; then
    "$DEVICES_SCRIPT"
  fi

  if [ -x "$TRAFFIC_SCRIPT" ]; then
    "$TRAFFIC_SCRIPT"
  fi

  end_ts="$(date +%s)"
  elapsed=$((end_ts - start_ts))
  sleep_for=$((INTERVAL - elapsed))
  [ "$sleep_for" -lt 1 ] && sleep_for=1
  sleep "$sleep_for"
done
