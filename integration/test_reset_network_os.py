from contextlib import redirect_stdout
from io import StringIO
import subprocess
import unittest
from unittest.mock import patch

import reset_network_os


class NetworkOsReset(unittest.TestCase):
    def test_deadline_and_scope(self):
        compose = ["docker", "compose", "-f", "compose.integration.yaml"]
        for elapsed, verdict in [(3.0, "PASS"), (3.001, "MISSED")]:
            with self.subTest(elapsed=elapsed), patch.object(reset_network_os.subprocess, "run") as run:
                output = StringIO()
                with patch.object(reset_network_os.time, "monotonic", side_effect=[0, elapsed]), redirect_stdout(output):
                    reset_network_os.reset(compose)
                run.assert_called_once_with([*compose, "up", "-d", "--no-deps", "--force-recreate",
                                             "--wait", "--wait-timeout", "120", "target", "client"], check=True)
                self.assertEqual(output.getvalue().splitlines()[-1], f"W6 three-second deadline: {verdict}")

    def test_compose_failure_cannot_report_healthy(self):
        output = StringIO()
        failure = subprocess.CalledProcessError(1, "docker compose")
        with patch.object(reset_network_os.subprocess, "run", side_effect=failure), redirect_stdout(output):
            with self.assertRaises(subprocess.CalledProcessError):
                reset_network_os.reset(["docker", "compose"])
        self.assertEqual(output.getvalue(), "")
