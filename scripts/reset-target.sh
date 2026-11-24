#!/usr/bin/env bash
# ============================================================================
# PBL4 - Target App Clean State Reset Script Runner (Task W6-T3)
# Phụ trách: Hoàng Trung (TV3) - Target App & Tấn công L7
# ============================================================================
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${TARGET_APP_URL:-http://localhost:18000}"

# Ưu tiên chạy qua Node.js nếu có sẵn
if command -v node >/dev/null 2>&1; then
  exec node "$script_dir/reset-target.mjs" "$@"
fi

# Fallback sang curl gọi API reset
echo "[RESET-TARGET] Gọi HTTP API reset 1-chạm..."
curl -s -X POST "$TARGET/api/system/reset" \
  -H "Content-Type: application/json" \
  -d '{}' | jq . || cat
