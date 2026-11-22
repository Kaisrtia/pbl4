import unittest
from unittest.mock import patch

import arp_cache


class CacheEvidence(unittest.TestCase):
    def test_peer_entry(self):
        peer = {"ip": "192.0.2.2", "mac": "02:00:00:00:00:02"}
        header = "IP address HW type Flags HW address Mask Device\n"
        row = "192.0.2.2 0x1 0x2 02:00:00:00:00:02 * eth0\n"
        for contents, expected in (
            (row, "MATCH"), (row.replace(":02 ", ":03 "), "MISMATCH"),
            (row.replace("0x2 ", "0x0 "), "UNKNOWN"), ("", "UNKNOWN"),
            (row + row, "UNKNOWN"), (row.replace("192.0.2.2", "192.0.2.3"), "UNKNOWN"),
        ):
            with self.subTest(contents=contents):
                self.assertEqual(arp_cache.peer_status(header + contents, peer), expected)

    def test_comparison_requires_two_trusted_mappings_at_both_times(self):
        before = {"timestamp": "2026-01-01T01:00:00+00:00", "endpoints": {"client": "a", "target": "b"},
                  "caches": {"client": "MATCH", "target": "MATCH"}}
        after = {**before, "timestamp": "2026-01-01T01:00:30+00:00"}
        self.assertEqual(arp_cache.compare(before, after), "BOTH_MATCH_BASELINE")
        for field, value, expected in (
            ("endpoints", {"client": "c", "target": "b"}, "INCONCLUSIVE"),
            ("timestamp", before["timestamp"], "INCONCLUSIVE"),
            ("caches", {"client": "MATCH", "target": "UNKNOWN"}, "INCONCLUSIVE"),
            ("caches", {"client": "MISMATCH", "target": "MATCH"}, "MISMATCH"),
        ):
            with self.subTest(field=field, value=value):
                self.assertEqual(arp_cache.compare(before, {**after, field: value}), expected)
        self.assertEqual(arp_cache.compare({**before, "caches": {}}, after), "INCONCLUSIVE")

    def test_collection_checks_both_namespaces(self):
        def fake_docker(*args):
            if args[0] == "ps":
                return args[-3].split("=")[-1]
            if args[0] == "inspect":
                suffix = 1 if args[-1] == "client" else 2
                return ('{"pbl4-integration_lab":{"NetworkID":"lab","EndpointID":"%s",'
                        '"IPAddress":"192.0.2.%d","MacAddress":"02:00:00:00:00:0%d"}}'
                        % (args[-1], suffix, suffix))
            opposite = {"client": 2, "target": 1}[args[1]]
            self.assertEqual(args, ("exec", args[1], "cat", "/proc/net/arp"))
            return f"header\n192.0.2.{opposite} 0x1 0x2 02:00:00:00:00:0{opposite} * eth0\n"

        with patch.object(arp_cache, "docker", side_effect=fake_docker):
            self.assertEqual(arp_cache.snapshot()["caches"], {"client": "MATCH", "target": "MATCH"})
