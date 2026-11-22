"""Read-only ARP health check for the two endpoints of the PBL4 Compose lab."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys


def docker(*args):
    return subprocess.run(["docker", *args], check=True, capture_output=True,
                          text=True, timeout=10).stdout.strip()


def endpoint(service):
    ids = docker("ps", "--no-trunc", "--filter", "label=com.docker.compose.project=pbl4-integration",
                 "--filter", f"label=com.docker.compose.service={service}", "--format", "{{.ID}}").splitlines()
    if len(ids) != 1:
        raise ValueError(f"Expected one running {service} in pbl4-integration")
    networks = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", ids[0]))
    if set(networks) != {"pbl4-integration_lab"}:
        raise ValueError(f"Unexpected networks for {service}")
    net = networks["pbl4-integration_lab"]
    if not all(net.get(key) for key in ("EndpointID", "NetworkID", "IPAddress", "MacAddress")):
        raise ValueError(f"Incomplete Docker endpoint metadata for {service}")
    return {"container": ids[0], "endpoint": net["EndpointID"], "network": net["NetworkID"],
            "ip": net["IPAddress"], "mac": net["MacAddress"].lower()}


def peer_status(table, peer):
    rows = [line.split() for line in table.splitlines()[1:]]
    matches = [row for row in rows if row and row[0] == peer["ip"]]
    if len(matches) != 1 or len(matches[0]) != 6:
        return "UNKNOWN"
    _, hardware, flags, mac, _, _ = matches[0]
    if int(hardware, 16) != 1 or not (int(flags, 16) & 2):
        return "UNKNOWN"
    return "MATCH" if mac.lower() == peer["mac"] else "MISMATCH"


def snapshot():
    identities = {role: endpoint(role) for role in ("client", "target")}
    if identities["client"]["network"] != identities["target"]["network"]:
        raise ValueError("Endpoints belong to different networks")
    caches = {}
    for role, peer in (("client", "target"), ("target", "client")):
        table = docker("exec", identities[role]["container"], "cat", "/proc/net/arp")
        caches[role] = peer_status(table, identities[peer])
    if any(endpoint(role) != identity for role, identity in identities.items()):
        raise ValueError("Endpoint identity changed during collection")
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "endpoints": identities, "caches": caches}


def compare(before, after):
    if (datetime.fromisoformat(before["timestamp"]) >= datetime.fromisoformat(after["timestamp"])
            or before["endpoints"] != after["endpoints"]
            or before["caches"] != {"client": "MATCH", "target": "MATCH"}):
        return "INCONCLUSIVE"
    if "MISMATCH" in after["caches"].values():
        return "MISMATCH"
    if after["caches"] == {"client": "MATCH", "target": "MATCH"}:
        return "BOTH_MATCH_BASELINE"
    return "INCONCLUSIVE"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, help="Earlier JSON snapshot from this lab")
    args = parser.parse_args()
    try:
        current = snapshot()
        if args.baseline:
            current["comparison"] = compare(json.loads(args.baseline.read_text()), current)
        print(json.dumps(current))
    except subprocess.CalledProcessError as error:
        sys.exit(error.stderr.strip() or "Docker could not read endpoint state")
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError, KeyError) as error:
        sys.exit(str(error))
