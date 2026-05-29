#!/bin/sh

NETMON_LIB="${NETMON_LIB:-/usr/lib/netmon/netmon-lib.sh}"
[ -r "$NETMON_LIB" ] && . "$NETMON_LIB"

emit_netmon() {
  if command -v netmon_send >/dev/null 2>&1; then
    netmon_send "$@"
  else
    tag="$1"
    shift
    logger -t "$tag" "$*"
  fi
}

find_wan_iface() {
  if [ -n "${NETMON_WAN_IFACE:-}" ]; then
    printf '%s\n' "$NETMON_WAN_IFACE"
    return 0
  fi

  if [ -n "${NETMON_IFACE:-}" ]; then
    printf '%s\n' "$NETMON_IFACE"
    return 0
  fi

  if command -v uci >/dev/null 2>&1; then
    iface="$(uci -q get network.wan.device 2>/dev/null)"
    if [ -n "$iface" ]; then
      printf '%s\n' "$iface"
      return 0
    fi

    iface="$(uci -q get network.wan.ifname 2>/dev/null)"
    if [ -n "$iface" ]; then
      printf '%s\n' "$iface"
      return 0
    fi
  fi

  iface="$(ip route show default 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}')"
  if [ -n "$iface" ]; then
    printf '%s\n' "$iface"
    return 0
  fi

  printf '%s\n' "pppoe-wan"
}

IFACE="$(find_wan_iface)"
RX_FILE="/sys/class/net/$IFACE/statistics/rx_bytes"
TX_FILE="/sys/class/net/$IFACE/statistics/tx_bytes"

[ -r "$RX_FILE" ] && [ -r "$TX_FILE" ] || exit 0

TS="$(date +%s)"
RX_BYTES="$(cat "$RX_FILE")"
TX_BYTES="$(cat "$TX_FILE")"

case "$RX_BYTES:$TX_BYTES" in
  *[!0-9:]*|:|*:|:*)
    exit 0
    ;;
esac

emit_netmon NETIFACE "ts=$TS if=$IFACE rx_bytes=$RX_BYTES tx_bytes=$TX_BYTES"
