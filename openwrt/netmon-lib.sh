#!/bin/sh

[ -r /etc/netmon-collector.conf ] && . /etc/netmon-collector.conf

netmon_send() {
  tag="$1"
  shift
  message="$*"
  mode="${NETMON_SEND_MODE:-direct}"
  sent=1

  if [ "$mode" != "syslog" ] && [ -n "${NETMON_SERVER_IP:-}" ]; then
    port="${NETMON_SERVER_PORT:-1514}"
    if command -v nc >/dev/null 2>&1; then
      printf '<13>%s: %s\n' "$tag" "$message" | nc -u -w 1 "$NETMON_SERVER_IP" "$port" >/dev/null 2>&1 && sent=0
    fi
  fi

  if [ "$mode" = "syslog" ] || [ "$mode" = "both" ] || [ "$sent" -ne 0 ]; then
    logger -t "$tag" "$message"
  fi
}
