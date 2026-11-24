"""Measure www-data file access and FD cleanup on disposable fixtures in the L2 target."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile


def probe(public, private):
    with public.open('rb') as stream:
        readable = stream.read() == b'PBL4'
    try:
        with private.open('rb'):
            denied = False
    except PermissionError:
        denied = True
    fd_dir = Path('/proc/self/fd')
    before = len(list(fd_dir.iterdir()))
    with ExitStack() as stack:
        for _ in range(8):
            stack.enter_context(public.open('rb'))
        opened = len(list(fd_dir.iterdir())) - before
    return {'uid': os.geteuid(), 'public_readable': readable, 'private_denied': denied,
            'fds_added': opened, 'fds_after_close_minus_before': len(list(fd_dir.iterdir())) - before}


def check():
    account = pwd.getpwnam('www-data')
    with tempfile.TemporaryDirectory(prefix='pbl4-os-') as directory:
        root = Path(directory)
        root.chmod(0o711)
        public, private = root / 'public', root / 'private'
        for file, mode in [(public, 0o644), (private, 0o600)]:
            file.write_bytes(b'PBL4')
            file.chmod(mode)
        # The child gets the service UID with no inherited supplementary groups.
        result = subprocess.run([sys.executable, __file__, str(public), str(private)],
                                user=account.pw_uid, group=account.pw_gid, extra_groups=[],
                                text=True, capture_output=True, check=True, timeout=5)
        evidence = json.loads(result.stdout)
    print(json.dumps(evidence), flush=True)
    return evidence == {'uid': account.pw_uid, 'public_readable': True, 'private_denied': True,
                        'fds_added': 8, 'fds_after_close_minus_before': 0}


if __name__ == '__main__':
    if len(sys.argv) == 3:
        print(json.dumps(probe(Path(sys.argv[1]), Path(sys.argv[2]))))
    else:
        raise SystemExit(0 if check() else 1)
