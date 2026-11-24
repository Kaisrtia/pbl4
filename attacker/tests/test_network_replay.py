from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from network_replay import replay


class ReplayTests(unittest.TestCase):
    def play(self, scenario, **params):
        events = []
        outcome, _, result = replay({'scenario': scenario, 'parameters': params},
                                    lambda kind, **event: events.append((kind, event)), lambda _: False)
        return outcome, result, events

    def test_arp_samples_follow_settings(self):
        for observe, count in [(1, 3), (0, 0)]:
            outcome, result, events = self.play('S5', duration_sec=5, interval_sec=2, observe=observe)
            self.assertEqual(outcome, 'OBSERVED')
            self.assertEqual(result['observed_samples'], count)
            self.assertEqual(events[-1][1]['client_cache'], 'MATCH')
            self.assertEqual(events[-1][1]['target_cache'], 'MATCH')

    def test_tcp_window_and_cap(self):
        for duration, count in [(1, 0), (2, 1), (8, 2)]:
            outcome, result, events = self.play('S6', duration_sec=duration, cooldown_sec=3, max_rst=2)
            self.assertEqual(outcome, 'OBSERVED' if count else 'INCONCLUSIVE')
            self.assertEqual([e['elapsed_sec'] for _, e in events if 'elapsed_sec' in e], [2, 5][:count])
            self.assertFalse(result['session_interruption_verified'])
