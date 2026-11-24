"""Check two consecutive God-View acknowledgements inside one lab container."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time


def check(role):
    ip = os.environ["CLIENT_IP" if role == "client" else "SERVER_IP"]
    latest = Path("/tmp/pbl4-host-telemetry.json")
    started = datetime.now(timezone.utc)
    previous = started
    seen = 0
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if latest.exists():
            sample = json.loads(latest.read_text())
            stamp = datetime.fromisoformat(sample["timestamp"])
            if stamp > previous:
                metrics = sample["metrics"]
                assert (sample["node"], sample["ip"]) == (role, ip)
                assert all(metrics[key] >= 0 for key in ("tcp_established", "tcp_syn_recv", "tcp_time_wait"))
                assert metrics["visible_fds_total"] >= metrics["open_fds"] > 0
                assert metrics["process_count"] > 0 and sample["pstree"]
                assert isinstance(sample["arp_neighbors"], list)
                seen += 1
                previous = stamp
                if seen == 2:
                    assert metrics["cpu_percent"] >= 0 and metrics["ram_used_mb"] > 0
                    print(f"PASS {role} {ip}: two acknowledged samples, latest {sample['timestamp']}")
                    return
        time.sleep(1)
    raise SystemExit(f"{role}: timed out waiting for two fresh acknowledgements")


if __name__ == "__main__":
    check(sys.argv[1])
