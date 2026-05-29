#!/bin/sh

TS="$(date +%s)"

[ -f /tmp/dhcp.leases ] || exit 0

while read -r expiry mac ip host clientid; do
  [ -n "$mac" ] || continue
  [ -n "$ip" ] || continue

  state="$(ip neigh show "$ip" 2>/dev/null | awk '{print $NF; exit}')"
  [ -n "$host" ] || host="unknown"
  [ -n "$state" ] || state="unknown"

  logger -t NETDEV "ts=$TS mac=$mac ip=$ip host=$host lease_expiry=$expiry neigh=$state"
done < /tmp/dhcp.leases
