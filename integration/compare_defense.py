"""Compare W5 configuration snapshots taken on either side of a W6 reset."""
import argparse
import json
from pathlib import Path


def configuration(snapshot):
    endpoints = snapshot['lab_endpoints']
    if not endpoints['client'] or not endpoints['target']:
        raise ValueError('Missing lab endpoint identity')
    apps = snapshot['node_processes']
    if not isinstance(apps, list) or not apps:
        raise ValueError('No Node process in snapshot')
    if not isinstance(snapshot['client_neighbor'], list) or not isinstance(snapshot['syn_filter_rules'], list):
        raise ValueError('Expected neighbour and firewall rule lists')
    if type(snapshot['tcp_syncookies']) != int:
        raise ValueError('Missing numeric SYN cookies setting')
    limits = snapshot['cgroup']
    permanent = []
    for row in snapshot['client_neighbor']:
        if row['dst'] != endpoints['client']:
            raise ValueError('Unexpected client IP in neighbour table')
        if not isinstance(row['state'], list) or not row['state']:
            raise ValueError('Missing neighbour state')
        if 'PERMANENT' in row['state']:
            permanent.append((row['dev'], row['lladdr'].lower()))
    return {
        'permanent_client_bindings': sorted(permanent),
        'syn_filter_rules': snapshot['syn_filter_rules'],
        'tcp_syncookies': snapshot['tcp_syncookies'],
        'cgroup': {key: limits[key] for key in ('cpu.max', 'memory.max', 'pids.max')},
        'node_identity_and_limits': sorted((p['effective_uid'], p['nofile']) for p in apps),
    }


def compare(before, after):
    baseline, current = configuration(before), configuration(after)
    if before['lab_endpoints'] != after['lab_endpoints']:
        raise ValueError('Snapshots refer to different lab endpoints')
    return {key: {'before': value, 'after': current[key]}
            for key, value in baseline.items() if value != current[key]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before', type=Path)
    parser.add_argument('after', type=Path)
    args = parser.parse_args()
    try:
        differences = compare(json.loads(args.before.read_text()), json.loads(args.after.read_text()))
    except (OSError, KeyError, ValueError, TypeError, AttributeError) as exc:
        print(json.dumps({'result': 'INCONCLUSIVE', 'reason': str(exc)}))
        raise SystemExit(2)
    print(json.dumps({'result': 'MISMATCH' if differences else 'MATCH', 'differences': differences}, indent=2))
    raise SystemExit(int(bool(differences)))
