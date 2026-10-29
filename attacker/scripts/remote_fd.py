"""Runs ONLY on Target through an authenticated SSH session.

Opens /dev/null in a separate process, never alters inherited RLIMIT_NOFILE.
The controller supplies CONFIG; completion is bounded and cancellation is via
the per-run stop marker. This file is sent as Python source, not installed.
"""
import errno
import json
import os
import resource
import time

root = CONFIG["work"]
fds = []
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
hit_limit = False
cancelled = False
try:
    for _ in range(CONFIG["max_fds"]):
        if os.path.exists(root + "/cancel"):
            cancelled = True
            break
        try:
            fds.append(os.open("/dev/null", os.O_RDONLY))
        except OSError as exc:
            if exc.errno != errno.EMFILE:
                raise
            hit_limit = True
            break
    opened = len(fds)
    deadline = time.monotonic() + CONFIG["hold_sec"]
    while time.monotonic() < deadline:
        if os.path.exists(root + "/cancel"):
            cancelled = True
            break
        time.sleep(0.05)
finally:
    for fd in fds:
        os.close(fd)
    with open(root + "/done", "w") as handle:
        handle.write("closed")
print(json.dumps({"opened_fds": opened, "requested_fds": CONFIG["max_fds"],
                  "soft_limit": soft, "hard_limit": hard, "hit_emfile": hit_limit,
                  "cancelled": cancelled, "target_service_impact": "NOT_ASSESSED"}))
