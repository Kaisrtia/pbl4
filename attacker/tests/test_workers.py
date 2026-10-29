import ast
import json
import subprocess
import sys
import unittest
import uuid
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


class Workers(unittest.TestCase):
    def test_syntax(self):
        for path in SCRIPTS.glob("*.py"):
            ast.parse(path.read_text())

    def test_invalid_input(self):
        for script in ["ssh_chain.py", "syn_flood.py", "fd_exhaustion.py", "sample_transfer.py"]:
            p = subprocess.run([sys.executable, str(SCRIPTS / script)], input="{}", text=True, capture_output=True)
            self.assertNotEqual(p.returncode, 0)
            self.assertNotIn('"outcome": "OBSERVED"', p.stdout)

    def test_missing_ssh_config_never_fakes_success(self):
        config = {"schema_version":"1.0", "run_id":str(uuid.uuid4()), "scenario":"S4",
                  "parameters":{}, "target":{"ip":"127.0.0.1","ssh_port":1},
                  "ssh":{"known_hosts":"/missing-pbl4-file"}}
        p = subprocess.run([sys.executable, str(SCRIPTS / "sample_transfer.py")], input=json.dumps(config), text=True, capture_output=True)
        self.assertEqual(p.returncode, 3)
        self.assertEqual(json.loads(p.stdout.splitlines()[-1])["result"]["outcome"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
