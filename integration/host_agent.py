"""W2-T2 telemetry collector for the Client and Target containers."""
import argparse
from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time


def tcp_counts(proc):
    states = {"01": "tcp_established", "03": "tcp_syn_recv", "06": "tcp_time_wait"}
    counts = dict.fromkeys(states.values(), 0)
    for name in ("tcp", "tcp6"):
        try:
            lines = (proc / "net" / name).read_text().splitlines()
        except FileNotFoundError:
            if name == "tcp6":
                continue
            raise
        for line in lines[1:]:
            state = states.get(line.split()[3])
            if state:
                counts[state] += 1
    return counts


def neighbors(proc, roles, timestamp):
    entries = []
    for line in (proc / "net/arp").read_text().splitlines()[1:]:
        ip, hardware, flags, mac, _, iface = line.split()
        if int(hardware, 16) == 1 and int(flags, 16) & 2:
            entries.append({"ip": ip, "mac": mac.lower(), "iface": iface,
                            "role": roles.get(ip, "OTHER"), "updated_at": timestamp})
    return entries


def process_metrics(proc):
    nodes = {}
    parents = {}
    busiest = None
    visible_fds = 0
    for directory in sorted(proc.glob("[0-9]*")):
        try:
            fields = dict(line.split(":", 1) for line in
                          (directory / "status").read_text(errors="replace").splitlines() if ":" in line)
            pid = int(directory.name)
            name = fields["Name"].strip()
            nodes[pid] = {"pid": pid, "name": name, "cmd": name,
                          "user": fields["Uid"].split()[0], "children": []}
            parents[pid] = int(fields["PPid"])
            count = len(os.listdir(directory / "fd"))
            visible_fds += count
            if busiest is None or count > busiest[0]:
                busiest = (count, pid)
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue  # Process exited or its descriptors belong to another UID.

    roots = []
    for pid, node in nodes.items():
        parent = nodes.get(parents[pid])
        (parent["children"] if parent else roots).append(node)
    metrics = {"process_count": len(nodes)}
    if busiest:
        count, pid = busiest
        metrics.update(open_fds=count, fd_pid=pid, visible_fds_total=visible_fds)
        try:
            for line in (proc / str(pid) / "limits").read_text().splitlines():
                if line.startswith("Max open files") and line.split()[3].isdigit():
                    metrics["max_fds"] = int(line.split()[3])
                    break
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
    return metrics, roots


def resource_metrics(cgroup, now, previous):
    metrics = {}
    try:
        metrics["ram_used_mb"] = round(int((cgroup / "memory.current").read_text()) / 2**20, 2)
    except (FileNotFoundError, PermissionError):
        pass
    try:
        counters = dict(line.split() for line in (cgroup / "cpu.stat").read_text().splitlines())
        usage = int(counters["usage_usec"])
    except (FileNotFoundError, PermissionError, KeyError):
        return metrics, None
    if previous:
        elapsed, used = now - previous[0], usage - previous[1]
        if elapsed > 0 and used >= 0:
            metrics["cpu_percent"] = round(used / (elapsed * 10000), 2)
    return metrics, (now, usage)


def collect(node, client_ip, target_ip, peer_mac, previous, proc=Path("/proc"),
            cgroup=Path("/sys/fs/cgroup")):
    timestamp = datetime.now(timezone.utc).isoformat()
    metrics, tree = process_metrics(proc)
    metrics.update(tcp_counts(proc))
    resources, previous = resource_metrics(cgroup, time.monotonic(), previous)
    metrics.update(resources)
    target = node == "target-server"
    rows = neighbors(proc, {client_ip: "CLIENT", target_ip: "TARGET_SERVER"}, timestamp)
    sample = {"node": node, "ip": target_ip if target else client_ip, "timestamp": timestamp,
              "metrics": metrics, "pstree": tree, "arp_neighbors": rows}
    # The hub treats every arp_table row as a verdict. Raw observations have no verdict.
    peer_ip = client_ip if target else target_ip
    verified = [dict(row, expected_mac=peer_mac.lower(), spoofed=row["mac"] != peer_mac.lower())
                for row in rows if peer_mac and row["ip"] == peer_ip]
    if verified:
        sample["arp_table"] = verified
    return sample, previous


def publish(sample):
    connection = http.client.HTTPConnection("godview", 4000, timeout=3)
    try:
        connection.request("POST", "/api/telemetry/host", json.dumps(sample),
                           {"Content-Type": "application/json"})
        status = connection.getresponse().status
        if status != 200:
            raise RuntimeError(f"God-View returned HTTP {status}")
    finally:
        connection.close()


def run(node, stop, latest):
    client_ip, target_ip = os.environ["CLIENT_IP"], os.environ["SERVER_IP"]
    peer_mac = os.environ.get("HOST_AGENT_PEER_MAC")
    previous = None
    while not stop.is_set():
        try:
            sample, previous = collect(node, client_ip, target_ip, peer_mac, previous)
            publish(sample)
            with tempfile.NamedTemporaryFile(dir=latest.parent, delete=False, mode="w") as out:
                temporary = Path(out.name)
                try:
                    json.dump(sample, out)
                    out.flush()
                    temporary.replace(latest)
                finally:
                    temporary.unlink(missing_ok=True)
        except (OSError, ValueError, http.client.HTTPException, RuntimeError) as error:
            print(f"Host telemetry ({node}): {error}", file=sys.stderr, flush=True)
        stop.wait(5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("node", choices=("client", "target-server"))
    args = parser.parse_args()
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    run(args.node, stop, Path("/tmp/pbl4-host-telemetry.json"))
