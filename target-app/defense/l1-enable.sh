#!/usr/bin/env bash
set -euo pipefail

TARGET_PORT="${SERVER_PORT:-8000}"
CLIENT_IP="${CLIENT_IP:-172.20.0.10}"
CLIENT_MAC="${CLIENT_MAC:?Set CLIENT_MAC to the trusted Docker client MAC}"
NET_IFACE="${NET_IFACE:-eth0}"
SYN_RATE_LIMIT="${SYN_RATE_LIMIT:-50/s}"
SYN_RATE_BURST="${SYN_RATE_BURST:-100}"
CHAIN_NAME="SYN_FLOOD_LIMIT"

echo "[L1 SHIELD] Enabling Network Layer defense (Static ARP & iptables SYN Filter)..."

bind_static_arp() {
  local ip="$1"
  local mac="$2"
  if command -v arp >/dev/null 2>&1; then
    arp -i "$NET_IFACE" -s "$ip" "$mac"
  elif command -v ip >/dev/null 2>&1; then
    ip neigh replace "$ip" lladdr "$mac" dev "$NET_IFACE" nud permanent
  else
    echo "[L1 SHIELD] Cannot configure static ARP: no arp or ip command" >&2
    return 1
  fi
}

bind_static_arp "$CLIENT_IP" "$CLIENT_MAC"
if [[ -n "${SERVER_IP:-}" && -n "${SERVER_MAC:-}" ]]; then
  bind_static_arp "$SERVER_IP" "$SERVER_MAC"
fi

if ! command -v iptables >/dev/null 2>&1; then
  echo "[L1 SHIELD] Error: 'iptables' command not found" >&2
  exit 1
fi

if ! iptables -L "$CHAIN_NAME" -n >/dev/null 2>&1; then
  iptables -N "$CHAIN_NAME"
fi
iptables -F "$CHAIN_NAME"
iptables -A "$CHAIN_NAME" -m limit --limit "$SYN_RATE_LIMIT" --limit-burst "$SYN_RATE_BURST" -j RETURN
iptables -A "$CHAIN_NAME" -j DROP

if ! iptables -C INPUT -p tcp --dport "$TARGET_PORT" --syn -m state --state NEW -j "$CHAIN_NAME" 2>/dev/null; then
  iptables -A INPUT -p tcp --dport "$TARGET_PORT" --syn -m state --state NEW -j "$CHAIN_NAME"
fi

echo "L1_NETWORK_SHIELD=ACTIVE"
