"""Test-only Target: real OpenSSH, real file permissions and a plain HTTP probe.

Not the partner's Target implementation. No fabricated kernel metrics.
"""
import http.server
import os
from pathlib import Path
import signal
import subprocess

secret = Path('/secrets')
secret.mkdir(exist_ok=True)
key = secret / 'id_ed25519'
if not key.exists():
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
subprocess.run(['ssh-keygen', '-A'], check=True)
home = Path('/home/lab')
(home / '.ssh').mkdir(mode=0o700, exist_ok=True)
(home / '.ssh/authorized_keys').write_text(key.with_suffix('.pub').read_text())
(home / '.ssh/authorized_keys').chmod(0o600)
(home / 'pbl4-lab').mkdir(exist_ok=True)
subprocess.run(['chown', '-R', 'lab:lab', str(home)], check=True)
sample = home / 'pbl4-lab/sample.txt'
sample.write_text('PBL4 SYNTHETIC DATA\ncustomer=example-only\n')
os.chown(sample, 0, 0)
sample.chmod(0o644)
hostkey = Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()
(secret / 'known_hosts').write_text(os.environ.get('SERVER_IP', '172.29.44.20') + ' ' + ' '.join(hostkey[:2]) + '\n')
config = Path('/etc/ssh/sshd_config')
config.write_text('''Port 22
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
UsePAM no
PidFile /run/sshd.pid
Subsystem sftp internal-sftp
''')
sshd = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e'])


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"status":"ok","fixture":true}'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def stop(*args):
    sshd.terminate()
    raise SystemExit(0)


signal.signal(signal.SIGTERM, stop)
http.server.ThreadingHTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
