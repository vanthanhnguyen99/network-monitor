#!/bin/sh
set -eu

LAN_SERVER_IP="${LAN_SERVER_IP:-192.168.10.160}"
SYSLOG_PORT="${SYSLOG_PORT:-1514}"
SYSLOG_PROTO="${SYSLOG_PROTO:-udp}"
LOG_HOSTNAME="${LOG_HOSTNAME:-openwrt-main}"

uci set system.@system[0].log_ip="$LAN_SERVER_IP"
uci set system.@system[0].log_port="$SYSLOG_PORT"
uci set system.@system[0].log_proto="$SYSLOG_PROTO"
uci set system.@system[0].log_hostname="$LOG_HOSTNAME"
uci commit system
/etc/init.d/log restart

logger -t NETMON_TEST "remote syslog configured for $LAN_SERVER_IP:$SYSLOG_PORT/$SYSLOG_PROTO"
