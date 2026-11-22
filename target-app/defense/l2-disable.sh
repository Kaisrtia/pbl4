#!/usr/bin/env bash
set -euo pipefail

LIMITS_FILE="${L2_LIMITS_FILE:-/etc/security/limits.d/99-pbl4-l2.conf}"
L2_SERVICE_USER_SHELL="${L2_SERVICE_USER_SHELL:-/bin/sh}"

echo "[L2 SHIELD] Disabling OS & Kernel Layer defense (Disabling tcp_syncookies and restoring limits)..."

if ! command -v sysctl >/dev/null 2>&1; then
  echo "[L2 SHIELD] Error: 'sysctl' command not found" >&2
  exit 1
fi

sysctl -w net.ipv4.tcp_syncookies=0
if [[ -n "${TCP_MAX_SYN_BACKLOG_BYPASS:-}" ]]; then
  sysctl -w "net.ipv4.tcp_max_syn_backlog=${TCP_MAX_SYN_BACKLOG_BYPASS}"
fi

if [[ -f "$LIMITS_FILE" && -w "$LIMITS_FILE" ]]; then
  rm -f "$LIMITS_FILE"
fi

if [[ -n "${L2_CGROUP_PATH:-}" && -d "${L2_CGROUP_PATH}" ]]; then
  [[ -w "${L2_CGROUP_PATH}/cpu.max" ]] && echo "max" >"${L2_CGROUP_PATH}/cpu.max"
  [[ -w "${L2_CGROUP_PATH}/memory.max" ]] && echo "max" >"${L2_CGROUP_PATH}/memory.max"
  [[ -w "${L2_CGROUP_PATH}/pids.max" ]] && echo "max" >"${L2_CGROUP_PATH}/pids.max"
fi

if [[ -n "${L2_SERVICE_USER:-}" && "${L2_SERVICE_USER}" != "root" ]] && id "${L2_SERVICE_USER}" >/dev/null 2>&1; then
  if command -v usermod >/dev/null 2>&1; then
    usermod -s "$L2_SERVICE_USER_SHELL" "${L2_SERVICE_USER}"
  fi
fi

echo "L2_OS_SHIELD=BYPASSED"
