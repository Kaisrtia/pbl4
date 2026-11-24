"""Show network observations for one W1 terminal pane inside a lab endpoint."""
import json
from pathlib import Path


def tcp_counters():
    rows = [line.split()[1:] for line in Path('/proc/net/snmp').read_text().splitlines()
            if line.startswith('Tcp:')]
    return dict(zip(*rows)) if len(rows) == 2 else {}


def main():
    path = Path('/tmp/pbl4-host-telemetry.json')
    if not path.exists():
        print('Waiting for acknowledged telemetry')
        return
    sample = json.loads(path.read_text())
    print(sample['node'], sample['ip'])
    print(sample['timestamp'])
    metrics = sample['metrics']
    print('SYN_RECV', metrics.get('tcp_syn_recv', '?'), 'ESTAB', metrics.get('tcp_established', '?'))
    counts = tcp_counters()
    print('OutRsts', counts.get('OutRsts', '?'), 'EstabResets', counts.get('EstabResets', '?'))
    for row in sample['arp_neighbors']:
        if row['role'] in ('CLIENT', 'TARGET_SERVER'):
            print('ARP', row['ip'], row['mac'])


if __name__ == '__main__':
    main()
