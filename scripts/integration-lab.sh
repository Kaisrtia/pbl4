#!/usr/bin/env bash
set -euo pipefail
task_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$task_root"
if [[ "${1:-}" == init ]]; then
  python3 - <<'PY'
from pathlib import Path
import secrets
destination = Path('integration/.env.local')
if destination.exists():
    print('Keeping existing integration/.env.local')
else:
    template = Path('integration/.env.example').read_text()
    template = template.replace('GENERATE_LOCALLY', secrets.token_hex(32), 1)
    template = template.replace('GENERATE_LOCALLY', secrets.token_hex(32), 1)
    with destination.open('x') as output:
        destination.chmod(0o600)
        output.write(template)
    print('Created integration/.env.local with local credentials')
PY
  exit 0
fi
if [[ ! -f integration/.env.local ]]; then
  echo 'Run ./scripts/integration-lab.sh init first.' >&2
  exit 1
fi
compose=(docker compose --project-name pbl4-integration --env-file integration/.env.local -f compose.integration.yaml)
case "${1:-}" in
  lan|local)
    python3 - "${1}" "${2:-}" <<'PY'
from pathlib import Path
import ipaddress
import socket
import sys

mode, value = sys.argv[1:]
if mode == 'local':
    value = '127.0.0.1'
else:
    try:
        ip = ipaddress.IPv4Address(value)
        networks = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
        if not any(ip in ipaddress.ip_network(network) for network in networks):
            raise ValueError('Use the private Wi-Fi IPv4 address of this machine')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((value, 0))
    except (ValueError, OSError) as error:
        raise SystemExit(f'Cannot use LAN address: {error}. Usage: ./scripts/integration-lab.sh lan <Wi-Fi IPv4>')
file = Path('integration/.env.local')
lines = [line for line in file.read_text().splitlines() if not line.startswith('LAB_BIND_IP=')]
lines.append(f'LAB_BIND_IP={value}')
file.write_text('\n'.join(lines) + '\n')
file.chmod(0o600)
print(f'LAB_BIND_IP={value}. Run ./scripts/integration-lab.sh up to apply.')
PY
    ;;
  urls)
    python3 - <<'PY'
from pathlib import Path
values = dict(line.split('=', 1) for line in Path('integration/.env.local').read_text().splitlines() if line and not line.startswith('#') and '=' in line)
host = values.get('LAB_BIND_IP', '127.0.0.1')
for name, key, fallback, suffix in [('God-View', 'LAB_GODVIEW_PORT', '14000', ''), ('Attacker', 'LAB_ATTACKER_PORT', '19090', ''), ('ElectroShop', 'LAB_TARGET_PORT', '18000', ''), ('Target Swagger', 'LAB_TARGET_PORT', '18000', '/api/docs')]:
    print(f'{name}: http://{host}:{values.get(key, fallback)}{suffix}')
PY
    ;;
  up) "${compose[@]}" up --build -d --wait --wait-timeout 120 ;;
  down) "${compose[@]}" down ;;
  status) "${compose[@]}" ps ;;
  defense-status) "${compose[@]}" exec -T target python3 - < integration/defense_status.py ;;
  monitor)
    command -v tmux >/dev/null || { echo 'Install tmux on the Docker host to open the four panes.' >&2; exit 1; }
    session=pbl4-tv2-monitor
    if ! tmux has-session -t "=$session" 2>/dev/null; then
      tmux new-session -d -s "$session" -c "$task_root" watch -n 3 -x "$task_root/scripts/integration-lab.sh" status
      for service in client target; do
        tmux split-window -d -t "$session" -c "$task_root" watch -n 5 -x "${compose[@]}" exec -T "$service" \
          python3 -c 'import json; s=json.load(open("/tmp/pbl4-host-telemetry.json")); print(s["node"],s["timestamp"]); print(json.dumps(s["metrics"],indent=2)); print(json.dumps(s["arp_neighbors"],indent=2))'
        tmux select-layout -t "$session" tiled >/dev/null
      done
      tmux split-window -d -t "$session" -c "$task_root" watch -n 5 -x "$task_root/scripts/integration-lab.sh" defense-status
      tmux select-layout -t "$session" tiled >/dev/null
    fi
    exec tmux attach-session -t "$session"
    ;;
  shields)
    case "${2:-}" in
      l1) compose+=(-f integration/shield-l1.yaml) ;;
      l2) compose+=(-f integration/shield-l2.yaml) ;;
      both) compose+=(-f integration/shield-l1.yaml -f integration/shield-l2.yaml) ;;
      off) ;;
      *) echo 'Usage: integration-lab.sh shields {off|l1|l2|both}' >&2; exit 2 ;;
    esac
    "${compose[@]}" up --build -d --wait --wait-timeout 120 godview target client
    ;;
  reset-network-os)
    # A fresh namespace drops lab processes, neighbour entries and firewall rules.
    # Keep named volumes, including SQLite and credentials, and leave the hub running.
    python3 integration/reset_network_os.py "${compose[@]}"
    ;;
  telemetry-test)
    "${compose[@]}" up --build -d --wait --wait-timeout 120 godview target client
    "${compose[@]}" exec -T client python3 - client < integration/check_host_sample.py
    "${compose[@]}" exec -T target python3 - target-server < integration/check_host_sample.py
    ;;
  logs) "${compose[@]}" logs --tail 80 ;;
  test) node --env-file=integration/.env.local integration/verify.mjs ;;
  *) echo 'Usage: ./scripts/integration-lab.sh {init|lan <IPv4>|local|urls|up|down|status|logs|test|telemetry-test|monitor|shields <off|l1|l2|both>|defense-status|reset-network-os}' >&2; exit 2 ;;
esac
