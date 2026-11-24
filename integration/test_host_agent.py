import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import host_agent


class HostAgent(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.proc = root / "proc"
        self.cgroup = root / "cgroup"
        (self.proc / "net").mkdir(parents=True)
        self.cgroup.mkdir()
        (self.cgroup / "cpu.stat").write_text("usage_usec 2200000\n")
        (self.cgroup / "memory.current").write_text("3145728")
        (self.proc / "net/tcp").write_text("header\n0: local remote 03\n1: local remote 01\n")
        (self.proc / "net/tcp6").write_text("header\n0: local remote 06\n")
        (self.proc / "net/arp").write_text(
            "IP address HW type Flags HW address Mask Device\n"
            "192.0.2.10 0x1 0x2 02:00:00:00:00:10 * eth0\n"
            "192.0.2.1 0x1 0x0 00:00:00:00:00:00 * eth0\n")
        for pid, parent, count in [(1, 0, 2), (4, 1, 3)]:
            process = self.proc / str(pid)
            (process / "fd").mkdir(parents=True)
            (process / "status").write_text(f"Name:\tapp\nPPid:\t{parent}\nUid:\t1000 1000 1000 1000\n")
            (process / "limits").write_text("Max open files            1024         2048        files\n")
            (process / "cmdline").write_bytes(b"app\0private-argument")
            (process / "environ").write_bytes(b"private-environment")
            for i in range(count):
                (process / "fd" / str(i)).symlink_to("/private-filename")

    def sample(self, role="target-server", mac=None, previous=None):
        return host_agent.collect(role, "192.0.2.10", "192.0.2.20", mac, previous, self.proc, self.cgroup)

    def test_target_metrics_and_privacy(self):
        with patch("host_agent.time.monotonic", return_value=7):
            sample, cpu = self.sample(mac="02:00:00:00:00:10", previous=(5, 1200000))
        self.assertEqual(cpu, (7, 2200000))
        self.assertEqual(sample["ip"], "192.0.2.20")
        self.assertEqual(sample["metrics"], {
            "cpu_percent": 50, "ram_used_mb": 3, "tcp_established": 1, "tcp_syn_recv": 1,
            "tcp_time_wait": 1, "open_fds": 3, "fd_pid": 4, "max_fds": 1024,
            "visible_fds_total": 5, "process_count": 2})
        self.assertEqual(sample["pstree"][0]["children"][0]["pid"], 4)
        self.assertEqual(len(sample["arp_neighbors"]), 1)
        self.assertFalse(sample["arp_table"][0]["spoofed"])
        self.assertNotIn("private-", json.dumps(sample))

    def test_only_verified_peer_gets_a_verdict(self):
        sample, _ = self.sample(mac="02:00:00:00:00:11")
        self.assertTrue(sample["arp_table"][0]["spoofed"])
        sample, _ = self.sample()
        self.assertNotIn("arp_table", sample)
        self.assertEqual(sample["arp_neighbors"][0]["role"], "CLIENT")
        sample, _ = self.sample("client", mac="02:00:00:00:00:20")
        self.assertEqual(sample["ip"], "192.0.2.10")
        self.assertNotIn("arp_table", sample)

    def test_missing_metrics_are_distinct_from_zero(self):
        (self.proc / "net/tcp6").unlink()
        (self.cgroup / "memory.current").unlink()
        sample, _ = self.sample()
        self.assertEqual(sample["metrics"]["tcp_time_wait"], 0)
        self.assertNotIn("cpu_percent", sample["metrics"])
        self.assertNotIn("ram_used_mb", sample["metrics"])
        (self.cgroup / "cpu.stat").unlink()
        _, cpu = self.sample()
        self.assertIsNone(cpu)

    def test_publish_contract_and_hub_failure(self):
        sample, _ = self.sample()
        with patch("host_agent.http.client.HTTPConnection") as connect:
            connection = connect.return_value
            connection.getresponse.return_value.status = 200
            host_agent.publish(sample)
            method, path, body, headers = connection.request.call_args.args
            self.assertEqual((method, path), ("POST", "/api/telemetry/host"))
            self.assertEqual(json.loads(body), sample)
            self.assertEqual(headers["Content-Type"], "application/json")
            connection.getresponse.return_value.status = 503
            with self.assertRaisesRegex(RuntimeError, "503"):
                host_agent.publish(sample)
            self.assertEqual(connection.close.call_count, 2)

    def test_retry_preserves_last_acknowledged_snapshot(self):
        latest = self.proc.parent / "latest.json"
        latest.write_text('{"timestamp":"old"}')
        stop = Mock()
        stop.is_set.side_effect = [False, False, True]
        stop.wait.side_effect = lambda _: observed.append(json.loads(latest.read_text()))
        observed = []
        sample, cpu = self.sample("client")
        with (patch.dict(host_agent.os.environ, CLIENT_IP="192.0.2.10", SERVER_IP="192.0.2.20"),
              patch.object(host_agent, "collect", return_value=(sample, cpu)) as read,
              patch.object(host_agent, "publish", side_effect=[ConnectionRefusedError(), None]),
              patch("sys.stderr")):
            host_agent.run("client", stop, latest)
        self.assertEqual(observed, [{"timestamp": "old"}, sample])
        self.assertEqual(read.call_args.args[-1], cpu)
