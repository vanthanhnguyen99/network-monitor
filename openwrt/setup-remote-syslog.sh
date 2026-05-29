#!/bin/sh
set -eu

LAN_SERVER_IP="${LAN_SERVER_IP:-192.168.10.160}"
SYSLOG_PORT="${SYSLOG_PORT:-1514}"
SYSLOG_PROTO="${SYSLOG_PROTO:-udp}"
LOG_HOSTNAME="${LOG_HOSTNAME:-openwrt-main}"
NETMON_SEND_MODE="${NETMON_SEND_MODE:-direct}"

uci set system.@system[0].log_ip="$LAN_SERVER_IP"
uci set system.@system[0].log_port="$SYSLOG_PORT"
uci set system.@system[0].log_proto="$SYSLOG_PROTO"
uci set system.@system[0].log_hostname="$LOG_HOSTNAME"
uci commit system
/etc/init.d/log restart

cat > /etc/netmon-collector.conf <<EOF
NETMON_SERVER_IP="$LAN_SERVER_IP"
NETMON_SERVER_PORT="$SYSLOG_PORT"
NETMON_SEND_MODE="$NETMON_SEND_MODE"
NETMON_IFACE_INTERVAL_SECONDS="${NETMON_IFACE_INTERVAL_SECONDS:-1}"
NETMON_DEVICES_INTERVAL_SECONDS="${NETMON_DEVICES_INTERVAL_SECONDS:-5}"
NETMON_TRAFFIC_INTERVAL_SECONDS="${NETMON_TRAFFIC_INTERVAL_SECONDS:-3}"
EOF

logger -t NETMON_TEST "remote syslog configured for $LAN_SERVER_IP:$SYSLOG_PORT/$SYSLOG_PROTO, netmon send mode $NETMON_SEND_MODE"
