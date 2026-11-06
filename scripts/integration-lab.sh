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
  up) "${compose[@]}" up --build -d --wait --wait-timeout 120 ;;
  down) "${compose[@]}" down ;;
  status) "${compose[@]}" ps ;;
  logs) "${compose[@]}" logs --tail 80 ;;
  test) node --env-file=integration/.env.local integration/verify.mjs ;;
  *) echo 'Usage: ./scripts/integration-lab.sh {init|up|down|status|logs|test}' >&2; exit 2 ;;
esac
