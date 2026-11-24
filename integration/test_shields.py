import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("docker"), "Docker CLI required to render Compose")
class Shields(unittest.TestCase):
    def test_four_modes_on_custom_subnet(self):
        env = {**os.environ, "LAB_CLIENT_IP": "172.24.3.10", "LAB_SUBNET": "172.24.3.0/24",
               "LAB_TARGET_IP": "172.24.3.20", "LAB_ATTACKER_IP": "172.24.3.66",
               "LAB_GODVIEW_IP": "172.24.3.99", "LAB_CLIENT_MAC": "02:aa:bb:00:00:10"}
        for mode in ((), ("l1",), ("l2",), ("l1", "l2")):
            with self.subTest(mode=mode):
                cmd = ["docker", "compose", "--env-file", "integration/.env.example",
                       "-f", "compose.integration.yaml"]
                for shield in mode:
                    cmd.extend(["-f", f"integration/shield-{shield}.yaml"])
                services = json.loads(subprocess.check_output(
                    cmd + ["config", "--format", "json"], cwd=ROOT, env=env))["services"]
                target = services["target"]
                self.assertEqual("LAB_L1_ENABLED" in target["environment"], "l1" in mode)
                self.assertEqual("LAB_L2_ENABLED" in target["environment"], "l2" in mode)
                self.assertFalse(target.get("privileged", False))
                if "l1" in mode:
                    mac = services["client"]["networks"]["lab"]["mac_address"]
                    self.assertEqual(mac, env["LAB_CLIENT_MAC"])
                    self.assertEqual(target["environment"]["CLIENT_MAC"], mac)
                    self.assertEqual(target["environment"]["CLIENT_IP"], env["LAB_CLIENT_IP"])
                if "l2" in mode:
                    self.assertEqual(str(target["sysctls"]["net.ipv4.tcp_syncookies"]), "1")
                    self.assertEqual(target["pids_limit"], 128)
                    self.assertEqual(target["ulimits"]["nofile"], {"soft": 1024, "hard": 1024})
                    self.assertEqual(int(target["mem_limit"]), 512 * 1024**2)
                    self.assertEqual(float(target["cpus"]), 1)
