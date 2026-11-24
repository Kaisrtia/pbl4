"""Interactive fixture playback for the fourth lab monitor pane."""
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
TRACES = {
    'S2': ('Target · SYN_RECV 0', 'Target · SYN_RECV 12', 'Target · SYN_RECV 4', 'Target · SYN_RECV 0'),
    'W4': ('Target · cây mẫu: app[40]', 'Target · cây mẫu: app[40] → session[41] · UID 33',
           'Phiên mẫu · đọc tệp riêng: EACCES', 'Target · phiên mẫu đã đóng · cây mẫu: app[40]'),
}


def play(scenario):
    print(f'[{scenario} · Mô phỏng] Bắt đầu phát lại', flush=True)
    if scenario in TRACES:
        for line in TRACES[scenario]:
            print(line, flush=True)
            time.sleep(1)
        return
    params = {'duration_sec': 4}
    params.update({'interval_sec': 2, 'observe': 1} if scenario == 'S5' else {'max_rst': 2, 'cooldown_sec': 1})
    request = {'schema_version': '1.0', 'run_id': str(uuid.uuid4()), 'scenario': scenario, 'parameters': params}
    with subprocess.Popen([sys.executable, str(ROOT / 'attacker/scripts/network_replay.py')],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as worker:
        worker.stdin.write(json.dumps(request))
        worker.stdin.close()
        for line in worker.stdout:
            event = json.loads(line)
            if event['type'] == 'progress':
                print(event['stage'], json.dumps({k: v for k, v in event.items()
                      if k not in ('type', 'stage', 'run_id')}, ensure_ascii=False), flush=True)
            elif event['type'] == 'result':
                print(event['result']['outcome'], event['result']['summary'], flush=True)
        if worker.wait() != 0:
            raise RuntimeError('Replay worker failed')


if __name__ == '__main__':
    while True:
        try:
            choice = input('\nMô phỏng · S2 (SYN), S5 (ARP), S6 (RST), W4 (phiên OS), Q (thoát)\n> ').strip().upper()
        except EOFError:
            break
        if choice == 'Q':
            break
        if choice in ('S2', 'S5', 'S6', 'W4'):
            play(choice)
