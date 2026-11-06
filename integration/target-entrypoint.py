"""Run the real Target backend plus an SSH sandbox inside this lab container."""
import os
from pathlib import Path
import signal
import subprocess
import time

secrets = Path('/secrets')
secrets.mkdir(exist_ok=True)
key = secrets / 'id_ed25519'
if not key.exists():
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
subprocess.run(['ssh-keygen', '-A'], check=True)
home = Path('/home/lab')
(home / '.ssh').mkdir(mode=0o700, exist_ok=True)
authorized = home / '.ssh/authorized_keys'
authorized.write_text(key.with_suffix('.pub').read_text())
authorized.chmod(0o600)
sandbox = home / 'pbl4-lab'
sandbox.mkdir(exist_ok=True)
subprocess.run(['chown', '-R', 'lab:lab', str(home)], check=True)
sample = sandbox / 'sample.txt'
sample.write_text('PBL4 INTEGRATION LAB - SYNTHETIC SAMPLE ONLY\n')
os.chown(sample, 0, 0)
sample.chmod(0o644)
hostkey = Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()
# Trust the host key generated locally, without a network keyscan.
known = secrets / 'known_hosts'
known.write_text(os.environ['SERVER_IP'] + ' ' + ' '.join(hostkey[:2]) + '\n')
Path('/etc/ssh/sshd_config').write_text('''Port 22
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowUsers lab
UsePAM no
PidFile /run/sshd.pid
Subsystem sftp internal-sftp
''')
children = []
stopping = False


def stop(*_):
    global stopping
    stopping = True


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
try:
    children.append(subprocess.Popen(['/usr/sbin/sshd', '-D', '-e']))
    children.append(subprocess.Popen(['node', 'dist/main.js']))
    while not stopping and all(p.poll() is None for p in children):
        time.sleep(0.2)
    failed = not stopping
finally:
    for child in children:
        if child.poll() is None:
            child.terminate()
    for child in children:
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
raise SystemExit(1 if failed else 0)
