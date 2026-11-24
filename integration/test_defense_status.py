from types import SimpleNamespace
import unittest
from unittest.mock import patch

import defense_status


class RuntimeShields(unittest.TestCase):
    @patch('defense_status.rule_installed')
    def test_l1_requires_correct_permanent_neighbor_and_ordered_rules(self, installed):
        env = {'CLIENT_IP': '192.0.2.10', 'CLIENT_MAC': '02:00:00:00:00:10'}
        row = {'dev': 'eth0', 'dst': env['CLIENT_IP'], 'lladdr': env['CLIENT_MAC'], 'state': ['PERMANENT']}
        rules = ['-A SYN_FLOOD_LIMIT -m limit -j RETURN', '-A SYN_FLOOD_LIMIT -j DROP']
        status = {'client_neighbor': [row], 'syn_filter_rules': rules}
        installed.return_value = True
        self.assertTrue(all(defense_status.verify(status, 'l1', env).values()))
        row['state'] = ['STALE']
        rules.reverse()
        installed.return_value = False
        self.assertFalse(any(defense_status.verify(status, 'l1', env).values()))

    @patch('defense_status.pwd.getpwnam', return_value=SimpleNamespace(pw_uid=33, pw_shell='/usr/sbin/nologin'))
    def test_l2_checks_actual_limits_and_requires_app(self, account):
        status = {'tcp_syncookies': 1, 'cgroup': {'cpu.max': '100000 100000', 'memory.max': '536870912',
                  'pids.max': '128'}, 'node_processes': [{'effective_uid': 33, 'nofile': ['1024', '2048']}]}
        self.assertTrue(all(defense_status.verify(status, 'l2', {}).values()))
        status['cgroup']['cpu.max'] = 'max 100000'
        status['node_processes'] = []
        result = defense_status.verify(status, 'l2', {})
        self.assertFalse(result['cpu'])
        self.assertFalse(result['service_user'])
        self.assertFalse(result['nofile'])
