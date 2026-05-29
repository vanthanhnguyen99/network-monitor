#!/bin/sh

TS="$(date +%s)"
TMP="/tmp/netmon-traffic.$$"
trap 'rm -f "$TMP"' EXIT

command -v nlbw >/dev/null 2>&1 || exit 0

# Group by MAC so the server can join traffic counters with NETDEV snapshots.
# Expected columns: mac conns rx_bytes rx_pkts tx_bytes tx_pkts
nlbw -c csv -g mac -o mac -q 2>/dev/null > "$TMP" || nlbw -c csv 2>/dev/null > "$TMP" || exit 0

while IFS= read -r line; do
  [ -n "$line" ] || continue

  normalized="$(printf '%s\n' "$line" | tr ',;' '  ')"
  set -- $normalized

  case "${1:-}" in
    ""|mac|MAC|family|Family)
      continue
      ;;
  esac

  mac="${1:-}"
  conns="${2:-}"
  rx_bytes="${3:-}"
  rx_pkts="${4:-}"
  tx_bytes="${5:-}"
  tx_pkts="${6:-}"

  case "$mac" in
    *:*:*:*:*:*) ;;
    *)
      logger -t NETTRAFFIC "ts=$TS csv=$line"
      continue
      ;;
  esac

  case "$rx_bytes:$tx_bytes" in
    *[!0-9:]*|:|*:|:*)
      logger -t NETTRAFFIC "ts=$TS csv=$line"
      continue
      ;;
  esac

  logger -t NETTRAFFIC "ts=$TS mac=$mac rx_bytes=$rx_bytes tx_bytes=$tx_bytes rx_pkts=$rx_pkts tx_pkts=$tx_pkts conns=$conns"
done < "$TMP"
