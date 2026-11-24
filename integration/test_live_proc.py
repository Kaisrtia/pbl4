"""Validate OS telemetry against this test's own short-lived Linux child."""
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import unittest

from host_agent import process_metrics


@unittest.skipUnless(Path('/proc/self/fd').is_dir(), 'requires Linux procfs')
class LiveProcessEvidence(unittest.TestCase):
    def test_child_tree_fd_increase_and_cleanup(self):
        child_code = """
import sys
print('ready', flush=True)
if sys.stdin.readline():
    handles = [open('/dev/null', 'rb') for _ in range(8)]
    print('opened', flush=True)
    sys.stdin.readline()
"""
        with tempfile.TemporaryDirectory() as temp, subprocess.Popen(
            [sys.executable, '-c', child_code], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True,
        ) as child, selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            root = Path(temp)
            try:
                for pid in (os.getpid(), child.pid):
                    (root / str(pid)).symlink_to(Path('/proc') / str(pid))
                self.assertTrue(selector.select(timeout=5))
                self.assertEqual(child.stdout.readline().strip(), 'ready')
                start, tree = process_metrics(root)
                self.assertEqual(tree[0]['children'][0]['pid'], child.pid)
                self.assertEqual(tree[0]['children'][0]['user'], str(os.getuid()))
                child.stdin.write('open\n')
                child.stdin.flush()
                self.assertTrue(selector.select(timeout=5))
                self.assertEqual(child.stdout.readline().strip(), 'opened')
                active, _ = process_metrics(root)
                self.assertEqual(active['visible_fds_total'] - start['visible_fds_total'], 8)
                child.stdin.close()
                self.assertEqual(child.wait(timeout=5), 0)
                cleaned, tree = process_metrics(root)
                self.assertEqual(cleaned['process_count'], 1)
                self.assertEqual(tree[0]['children'], [])
            finally:
                if child.poll() is None:
                    child.kill()
