"""Recreate the two lab endpoints and report elapsed time through service health."""
import json
import subprocess
import sys
import time

from arp_cache import snapshot as arp_snapshot


def reset(compose, *, env=None):
    start = time.monotonic()
    subprocess.run([*compose, "up", "-d", "--no-deps", "--force-recreate",
                    "--wait", "--wait-timeout", "120", "target", "client"], check=True, env=env)
    elapsed = time.monotonic() - start
    print(f"Network/OS reset to Compose baseline, services healthy in {elapsed:.3f}s")
    print(f"W6 three-second deadline: {'PASS' if elapsed <= 3 else 'MISSED'}")
    return elapsed


def reset_and_verify(compose, *, env=None):
    elapsed = reset(compose, env=env)
    project = subprocess.check_output([*compose, "ps", "--format", "{{.Project}}", "target"],
                                      text=True, timeout=10, env=env).strip()
    if not project or len(project.splitlines()) != 1:
        raise ValueError("Could not identify the running target project")
    endpoints = arp_snapshot(project)
    print(json.dumps({'peer_cache_after': endpoints['caches']}), flush=True)
    return elapsed, endpoints


def reset_result(elapsed, caches):
    if 'MISMATCH' in caches.values():
        return 1
    if caches != {'client': 'MATCH', 'target': 'MATCH'}:
        return 2
    return int(elapsed > 3)


if __name__ == "__main__":
    try:
        elapsed, endpoints = reset_and_verify(sys.argv[1:])
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        sys.exit(f"Network/OS reset verification failed: {error}")
    sys.exit(reset_result(elapsed, endpoints['caches']))
