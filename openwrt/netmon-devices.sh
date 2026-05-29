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

TS="$(date +%s)"

[ -f /tmp/dhcp.leases ] || exit 0

while read -r expiry mac ip host clientid; do
  [ -n "$mac" ] || continue
  [ -n "$ip" ] || continue

  state="$(ip neigh show "$ip" 2>/dev/null | awk '{print $NF; exit}')"
  [ -n "$host" ] || host="unknown"
  [ -n "$state" ] || state="unknown"

  emit_netmon NETDEV "ts=$TS mac=$mac ip=$ip host=$host lease_expiry=$expiry neigh=$state"
done < /tmp/dhcp.leases
