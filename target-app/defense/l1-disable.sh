#!/usr/bin/env bash
set -euo pipefail

TARGET_PORT="${SERVER_PORT:-8000}"
CLIENT_IP="${CLIENT_IP:-172.20.0.10}"
NET_IFACE="${NET_IFACE:-eth0}"
CHAIN_NAME="SYN_FLOOD_LIMIT"

echo "[L1 SHIELD] Disabling Network Layer defense (Restoring dynamic ARP & removing iptables SYN Filter)..."

clear_static_arp() {
  local ip="$1"
  if command -v arp >/dev/null 2>&1; then
    arp -d "$ip" 2>/dev/null || true
  elif command -v ip >/dev/null 2>&1; then
    ip neigh del "$ip" dev "$NET_IFACE" 2>/dev/null || true
  fi
}

clear_static_arp "$CLIENT_IP"
if [[ -n "${SERVER_IP:-}" ]]; then
  clear_static_arp "$SERVER_IP"
fi

if ! command -v iptables >/dev/null 2>&1; then
  echo "[L1 SHIELD] Error: 'iptables' command not found" >&2
  exit 1
fi

while iptables -C INPUT -p tcp --dport "$TARGET_PORT" --syn -m state --state NEW -j "$CHAIN_NAME" 2>/dev/null; do
  iptables -D INPUT -p tcp --dport "$TARGET_PORT" --syn -m state --state NEW -j "$CHAIN_NAME"
done

if iptables -L "$CHAIN_NAME" -n >/dev/null 2>&1; then
  iptables -F "$CHAIN_NAME"
  iptables -X "$CHAIN_NAME"
fi

echo "L1_NETWORK_SHIELD=BYPASSED"
