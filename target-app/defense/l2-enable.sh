#!/usr/bin/env bash
set -euo pipefail

TCP_MAX_SYN_BACKLOG="${TCP_MAX_SYN_BACKLOG:-128}"
LAB_USER="${LAB_USER:-lab}"
LAB_NOFILE_SOFT="${LAB_NOFILE_SOFT:-256}"
LAB_NOFILE_HARD="${LAB_NOFILE_HARD:-512}"
LIMITS_FILE="${L2_LIMITS_FILE:-/etc/security/limits.d/99-pbl4-l2.conf}"
CGROUP_CPU_MAX="${CGROUP_CPU_MAX:-50000 100000}"
CGROUP_MEMORY_MAX="${CGROUP_MEMORY_MAX:-256M}"
CGROUP_PIDS_MAX="${CGROUP_PIDS_MAX:-50}"

echo "[L2 SHIELD] Enabling OS & Kernel Layer defense (tcp_syncookies, ulimit, cgroups, nologin)..."

if ! command -v sysctl >/dev/null 2>&1; then
  echo "[L2 SHIELD] Error: 'sysctl' command not found" >&2
  exit 1
fi

sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w "net.ipv4.tcp_max_syn_backlog=${TCP_MAX_SYN_BACKLOG}"

limits_dir="$(dirname "$LIMITS_FILE")"
if [[ -d "$limits_dir" && -w "$limits_dir" ]]; then
  cat >"$LIMITS_FILE" <<EOF
${LAB_USER}          soft    nofile          ${LAB_NOFILE_SOFT}
${LAB_USER}          hard    nofile          ${LAB_NOFILE_HARD}
EOF
fi

if [[ -n "${L2_CGROUP_PATH:-}" && -d "${L2_CGROUP_PATH}" ]]; then
  [[ -w "${L2_CGROUP_PATH}/cpu.max" ]] && echo "$CGROUP_CPU_MAX" >"${L2_CGROUP_PATH}/cpu.max"
  [[ -w "${L2_CGROUP_PATH}/memory.max" ]] && echo "$CGROUP_MEMORY_MAX" >"${L2_CGROUP_PATH}/memory.max"
  [[ -w "${L2_CGROUP_PATH}/pids.max" ]] && echo "$CGROUP_PIDS_MAX" >"${L2_CGROUP_PATH}/pids.max"
fi

if [[ -n "${L2_SERVICE_USER:-}" && "${L2_SERVICE_USER}" != "root" ]] && id "${L2_SERVICE_USER}" >/dev/null 2>&1; then
  if command -v usermod >/dev/null 2>&1; then
    nologin_shell="/sbin/nologin"
    [[ -x "$nologin_shell" ]] || nologin_shell="/usr/sbin/nologin"
    [[ -x "$nologin_shell" ]] || nologin_shell="/bin/false"
    usermod -s "$nologin_shell" "${L2_SERVICE_USER}"
  fi
fi

echo "L2_OS_SHIELD=ACTIVE"
