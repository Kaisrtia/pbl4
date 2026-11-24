"""Exercise W5 shields and W6 reset in a disposable, loopback-only Compose project."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import uuid

from arp_cache import snapshot as arp_snapshot
from compare_defense import compare
from reset_network_os import reset_and_verify, reset_result


ROOT = Path(__file__).resolve().parents[1]
NETWORK_SETTINGS = {'permanent_client_bindings', 'syn_filter_rules'}
OS_SETTINGS = {'tcp_syncookies', 'cgroup', 'node_identity_and_limits'}


def lab_environment(subnet):
    if subnet.version != 4 or subnet.prefixlen != 24 or not any(
        subnet.subnet_of(ipaddress.ip_network(block))
        for block in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
    ):
        raise ValueError('Expected an unused private IPv4 /24')
    env = {k: v for k, v in os.environ.items() if not k.startswith(('LAB_', 'COMPOSE_'))}
    env.update(LAB_BIND_IP='127.0.0.1', LAB_SUBNET=str(subnet), LAB_TARGET_PORT='0',
               LAB_ATTACKER_PORT='0', LAB_GODVIEW_PORT='0', LAB_JWT_SECRET=secrets.token_hex(32),
               LAB_ATTACKER_TOKEN=secrets.token_hex(32))
    for role, host in [('CLIENT', 10), ('TARGET', 20), ('ATTACKER', 66), ('GODVIEW', 99)]:
        env[f'LAB_{role}_IP'] = str(subnet[host])
    return env


def snapshot(compose, env, mode=None):
    command = [*compose, 'exec', '-T', 'target', 'python3', '-']
    if mode:
        command += ['--expect', mode]
    result = subprocess.run(command, env=env, text=True, capture_output=True,
                            input=(ROOT / 'integration/defense_status.py').read_text())
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout or 'Cannot sample target')
    return json.loads(result.stdout)


def cycle(subnet):
    env = lab_environment(subnet)
    project = 'tv2-check-' + uuid.uuid4().hex
    compose = ['docker', 'compose', '--project-name', project, '--env-file', '/dev/null',
               '-f', str(ROOT / 'compose.integration.yaml')]
    up = ['up', '-d', '--wait', '--wait-timeout', '120', 'godview', 'target', 'client']
    subprocess.run(['docker', 'info', '--format', '{{.ServerVersion}}'], check=True, env=env)
    try:
        subprocess.run([*compose, *up], env=env, check=True)
        before = snapshot(compose, env)
        for mode, layers in [('l1', ['l1']), ('l2', ['l2']), ('both', ['l1', 'l2'])]:
            overlay = compose.copy()
            for layer in layers:
                overlay += ['-f', str(ROOT / f'integration/shield-{layer}.yaml')]
            subprocess.run([*overlay, *up], env=env, check=True)
            current = snapshot(overlay, env, mode)
            changes = compare(before, current)
            inactive = {'l1': OS_SETTINGS, 'l2': NETWORK_SETTINGS, 'both': set()}[mode]
            unexpected = sorted(inactive.intersection(changes))
            print(json.dumps({'mode': mode, 'checks': current['checks'],
                              'unexpected_changes': unexpected}), flush=True)
            if unexpected:
                raise RuntimeError(f'{mode} changed inactive shield settings')
        # Copy the probe only into this disposable target before the timed reset.
        subprocess.run([*compose, 'cp', str(ROOT / 'integration/check_os_access.py'),
                        'target:/tmp/check_os_access.py'], check=True, env=env)
        subprocess.run([*compose, 'exec', '-T', 'target', 'python3', '/tmp/check_os_access.py'],
                       check=True, env=env)
        old = arp_snapshot(project)
        elapsed, new = reset_and_verify(compose, env=env)
        recreated = {}
        for role in ('client', 'target'):
            previous, current = old['endpoints'][role], new['endpoints'][role]
            recreated[role] = (previous['network'] == current['network']
                               and previous['ip'] == current['ip']
                               and previous['container'] != current['container']
                               and previous['endpoint'] != current['endpoint'])
        changes = compare(before, snapshot(compose, env))
        print(json.dumps({'reset_seconds': elapsed, 'deadline_met': elapsed <= 3,
                          'differences_after_reset': changes, 'endpoints_recreated': recreated,
                          'peer_cache_before': old['caches'], 'peer_cache_after': new['caches']}), flush=True)
        healthy_cache = {'client': 'MATCH', 'target': 'MATCH'}
        return (not changes and all(recreated.values())
                and old['caches'] == healthy_cache and reset_result(elapsed, new['caches']) == 0)
    finally:
        subprocess.run([*compose, 'down', '--volumes', '--rmi', 'local'], env=env, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--subnet', type=ipaddress.ip_network, default='172.30.214.0/24')
    args = parser.parse_args()
    try:
        passed = cycle(args.subnet)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        parser.exit(2, f'{exc}\n')
    raise SystemExit(0 if passed else 1)
