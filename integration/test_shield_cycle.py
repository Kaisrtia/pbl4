import ipaddress
from unittest import TestCase, mock

import check_shield_cycle as cycle


class DisposableShieldCycle(TestCase):
    def test_private_subnet_and_isolation(self):
        with mock.patch.dict('os.environ', {'LAB_BIND_IP': '0.0.0.0', 'COMPOSE_FILE': 'custom.yml'}):
            env = cycle.lab_environment(ipaddress.ip_network('10.100.90.0/24'))
        self.assertNotIn('COMPOSE_FILE', env)
        self.assertEqual(env['LAB_BIND_IP'], '127.0.0.1')
        self.assertEqual(env['LAB_TARGET_PORT'], '0')
        self.assertEqual(env['LAB_TARGET_IP'], '10.100.90.20')
        for subnet in ('192.0.2.0/24', '10.0.0.0/16', 'fd00::/64'):
            with self.subTest(subnet=subnet), self.assertRaises(ValueError):
                cycle.lab_environment(ipaddress.ip_network(subnet))

    def test_only_disposable_project_cleaned_after_failure(self):
        with mock.patch.object(cycle.subprocess, 'run') as run, mock.patch.object(
            cycle, 'snapshot', side_effect=RuntimeError('missing baseline')
        ), self.assertRaisesRegex(RuntimeError, 'missing baseline'):
            cycle.cycle(ipaddress.ip_network('10.100.90.0/24'))
        start, cleanup = [call.args[0] for call in run.call_args_list[1:]]
        self.assertEqual(start[:start.index('up')], cleanup[:cleanup.index('down')])
        self.assertRegex(start[start.index('--project-name') + 1], r'^tv2-check-[0-9a-f]{32}$')
        self.assertEqual(start[-3:], ['godview', 'target', 'client'])
