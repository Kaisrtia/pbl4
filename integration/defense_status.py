"""Print read-only W5 evidence inside the lab target."""
import json
import os
from pathlib import Path
import subprocess


def main():
    proc = Path('/proc')
    cgroup = Path('/sys/fs/cgroup')
    chain = subprocess.run(['iptables', '-S'], capture_output=True, text=True, check=True)
    apps = []
    for pid in proc.glob('[0-9]*'):
        try:
            if (pid / 'comm').read_text().strip() != 'node':
                continue
            status = (pid / 'status').read_text().splitlines()
            limits = (pid / 'limits').read_text().splitlines()
            apps.append({'pid': int(pid.name),
                         'effective_uid': int(next(s for s in status if s.startswith('Uid:')).split()[2]),
                         'nofile': next(s for s in limits if s.startswith('Max open files')).split()[3:5]})
        except FileNotFoundError:
            continue
    print(json.dumps({
        'client_neighbor': json.loads(subprocess.check_output(
            ['ip', '-j', 'neigh', 'show', 'to', os.environ['CLIENT_IP']], text=True)),
        'syn_filter_rules': [rule for rule in chain.stdout.splitlines() if 'SYN_FLOOD_LIMIT' in rule],
        'tcp_syncookies': int((proc / 'sys/net/ipv4/tcp_syncookies').read_text()),
        'cgroup': {name: (cgroup / name).read_text().strip()
                   for name in ('cpu.max', 'memory.max', 'pids.max') if (cgroup / name).exists()},
        'node_processes': apps,
    }, indent=2))


if __name__ == '__main__':
    main()
