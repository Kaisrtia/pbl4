import socket
import urllib.request
from pathlib import Path

assert Path('/secrets/known_hosts').is_file()
with socket.create_connection(('127.0.0.1', 22), timeout=2):
    pass
with urllib.request.urlopen('http://127.0.0.1:8000/api/system/health', timeout=2) as response:
    assert response.status == 200
