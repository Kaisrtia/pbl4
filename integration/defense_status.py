"""Print read-only W5 evidence inside the lab target."""
import argparse
import json
import os
from pathlib import Path
import pwd
import subprocess


def read_status():
    proc = Path('/proc')
    cgroup = Path('/sys/fs/cgroup')
    chain = subprocess.run(['iptables', '-S'], capture_output=True, text=True, check=True)
    apps = []
    for pid in proc.glob('[0-9]*'):
        try:
            if (pid / 'comm').read_text().strip() not in ('node', 'node-MainThread'):
                continue
            status = (pid / 'status').read_text().splitlines()
            limits = (pid / 'limits').read_text().splitlines()
            apps.append({'pid': int(pid.name),
                         'effective_uid': int(next(s for s in status if s.startswith('Uid:')).split()[2]),
                         'nofile': next(s for s in limits if s.startswith('Max open files')).split()[3:5]})
        except FileNotFoundError:
            continue
    return {
        'lab_endpoints': {'client': os.environ['CLIENT_IP'], 'target': os.environ['SERVER_IP']},
        'client_neighbor': json.loads(subprocess.check_output(
            ['ip', '-j', 'neigh', 'show', 'to', os.environ['CLIENT_IP']], text=True)),
        'syn_filter_rules': [rule for rule in chain.stdout.splitlines() if 'SYN_FLOOD_LIMIT' in rule],
        'tcp_syncookies': int((proc / 'sys/net/ipv4/tcp_syncookies').read_text()),
        'cgroup': {name: (cgroup / name).read_text().strip()
                   for name in ('cpu.max', 'memory.max', 'pids.max') if (cgroup / name).exists()},
        'node_processes': apps,
    }


def rule_installed(chain, *args):
    result = subprocess.run(['iptables', '-C', chain, *args], capture_output=True, text=True)
    if result.returncode not in (0, 1):
        result.check_returncode()
    return result.returncode == 0


def verify(status, mode, env):
    checks = {}
    if mode in ('l1', 'both'):
        mac = env.get('CLIENT_MAC', '').lower()
        checks['client_binding'] = bool(mac) and any(
            entry.get('dst') == env['CLIENT_IP'] and entry.get('dev') == env.get('NET_IFACE', 'eth0')
            and entry.get('lladdr', '').lower() == mac and 'PERMANENT' in entry.get('state', [])
            for entry in status['client_neighbor'])
        chain = 'SYN_FLOOD_LIMIT'
        checks['input_jump'] = rule_installed('INPUT', '-p', 'tcp', '--dport', env.get('SERVER_PORT', '8000'),
                                              '--syn', '-m', 'state', '--state', 'NEW', '-j', chain)
        checks['rate_limit'] = rule_installed(chain, '-m', 'limit', '--limit', env.get('SYN_RATE_LIMIT', '50/s'),
                                              '--limit-burst', env.get('SYN_RATE_BURST', '100'), '-j', 'RETURN')
        rules = [rule for rule in status['syn_filter_rules'] if rule.startswith(f'-A {chain} ')]
        checks['drop_after_limit'] = len(rules) == 2 and rules[-1] == f'-A {chain} -j DROP'
    if mode in ('l2', 'both'):
        account = pwd.getpwnam('www-data')
        apps = status['node_processes']
        cgroup = status['cgroup']
        cpu = cgroup.get('cpu.max', '').split()
        checks.update(syncookies=status['tcp_syncookies'] == 1,
                      cpu=len(cpu) == 2 and cpu[0].isdigit() and int(cpu[0]) > 0 and cpu[0] == cpu[1],
                      memory=cgroup.get('memory.max') == str(512 * 1024**2),
                      pids=cgroup.get('pids.max') == '128',
                      service_user=bool(apps) and account.pw_shell.endswith('/nologin')
                      and all(p['effective_uid'] == account.pw_uid for p in apps),
                      nofile=bool(apps) and all(p['nofile'] == ['1024', '1024'] for p in apps))
    return checks


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect', choices=('l1', 'l2', 'both'))
    args = parser.parse_args()
    status = read_status()
    if args.expect:
        status['checks'] = verify(status, args.expect, os.environ)
    print(json.dumps(status, indent=2))
    if args.expect and not all(status['checks'].values()):
        raise SystemExit(1)
