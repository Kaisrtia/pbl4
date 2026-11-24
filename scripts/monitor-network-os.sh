#!/usr/bin/env bash
# Called by integration-lab.sh with the Docker Compose command for this lab.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose=("$@")
session=pbl4-tv2-monitor
command -v tmux >/dev/null || { echo 'Install tmux on the Docker host to open the four panes.' >&2; exit 1; }
if ! tmux has-session -t "=$session" 2>/dev/null; then
  tmux new-session -d -x 160 -y 48 -s "$session" -c "$root" \
    watch -t -n 3 -x "${compose[@]}" ps --format 'table {{.Service}}\t{{.Status}}'
  for service in client target; do
    tmux split-window -d -t "$session" -c "$root" watch -t -n 5 -x bash -c \
      'service=$1; shift; exec "$@" exec -T "$service" python3 - < integration/monitor_node.py' bash "$service" "${compose[@]}"
    tmux select-layout -t "$session" tiled >/dev/null
  done
  tmux split-window -d -t "$session" -c "$root" watch -t -n 5 -x bash -c \
    'exec "$@" exec -T target python3 - < integration/defense_status.py' bash "${compose[@]}"
  tmux select-layout -t "$session" tiled >/dev/null
fi
exec tmux attach-session -t "$session"
