"""S4: only the dedicated lab sample.txt; actual Target -> receiver HTTP."""
import sys
from common import main, connect, remote_json, result

REMOTE = r'''
import hashlib
import http.client
import os
import stat
from pathlib import Path
from urllib.parse import urlsplit
root = Path(CONFIG["sandbox"]).resolve(strict=True)
if root.name != "pbl4-lab":
    raise ValueError("Invalid lab root")
sample = root / "sample.txt"
try:
    fd = os.open(sample, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("Sample must be a regular file")
        data = handle.read(4097)
    if not 1 <= len(data) <= 4096:
        raise ValueError("Sample size outside lab bounds")
except PermissionError:
    print(json.dumps({"status":"READ_DENIED","bytes":0}))
else:
    url = urlsplit(CONFIG["receiver"]["url"])
    connection = http.client.HTTPConnection(url.hostname, url.port, timeout=3)
    try:
        connection.request("POST", url.path, body=data, headers={
            "Authorization":"Bearer " + CONFIG["receiver"]["token"],
            "Content-Type":"application/octet-stream"})
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError("Receiver rejected transfer")
        ack = json.loads(response.read(4096))
        digest = hashlib.sha256(data).hexdigest()
        if ack.get("sha256") != digest or ack.get("bytes") != len(data):
            raise RuntimeError("Receiver acknowledgement mismatch")
        print(json.dumps({"status":"RECEIVED","bytes":len(data),"sha256":digest}))
    finally:
        connection.close()
'''


def execute(config):
    client = connect(config)
    try:
        evidence = remote_json(client, REMOTE, {"sandbox": config["ssh"]["sandbox"], "receiver": config["receiver"]}, timeout=7)
        if evidence["status"] == "READ_DENIED":
            return result("Target denied reading the dedicated sample; no transfer occurred", evidence, outcome="BLOCKED")
        return result("Sample received with matching byte count and SHA-256", evidence)
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main("S4", execute))
