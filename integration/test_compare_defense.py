from copy import deepcopy
import unittest

from compare_defense import compare


class ResetEvidence(unittest.TestCase):
    def setUp(self):
        self.before = {
            'lab_endpoints': {'client': '192.0.2.10', 'target': '192.0.2.20'},
            'client_neighbor': [{'dst': '192.0.2.10', 'state': ['STALE']}],
            'syn_filter_rules': [], 'tcp_syncookies': 1,
            'cgroup': {'cpu.max': 'max 100000', 'memory.max': 'max', 'pids.max': 'max'},
            'node_processes': [{'pid': 9, 'effective_uid': 0, 'nofile': ['1024', '2048']}],
        }
        self.after = deepcopy(self.before)

    def test_recreated_pid_and_dynamic_cache_expiry(self):
        self.after['node_processes'][0]['pid'] = 17
        self.after['client_neighbor'] = []
        self.assertEqual(compare(self.before, self.after), {})

    def test_remaining_shield_settings(self):
        self.after['client_neighbor'][0].update(state=['PERMANENT'], dev='eth0', lladdr='02:00:00:00:00:10')
        self.after['cgroup']['pids.max'] = '128'
        self.after['node_processes'][0]['effective_uid'] = 33
        self.after['syn_filter_rules'] = ['-N SYN_FLOOD_LIMIT']
        self.assertEqual(set(compare(self.before, self.after)), {
            'permanent_client_bindings', 'cgroup', 'node_identity_and_limits', 'syn_filter_rules'})

    def test_missing_evidence_or_wrong_lab(self):
        for key, value in [('node_processes', []), ('cgroup', {}),
                           ('lab_endpoints', {'client': '192.0.2.10', 'target': '192.0.2.99'})]:
            with self.subTest(key=key), self.assertRaises((KeyError, ValueError)):
                compare(self.before, {**self.after, key: value})
