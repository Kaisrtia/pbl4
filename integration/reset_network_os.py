"""Recreate the two lab endpoints and report elapsed time through service health."""
import subprocess
import sys
import time


def reset(compose, *, env=None):
    start = time.monotonic()
    subprocess.run([*compose, "up", "-d", "--no-deps", "--force-recreate",
                    "--wait", "--wait-timeout", "120", "target", "client"], check=True, env=env)
    elapsed = time.monotonic() - start
    print(f"Network/OS reset to Compose baseline, services healthy in {elapsed:.3f}s")
    print(f"W6 three-second deadline: {'PASS' if elapsed <= 3 else 'MISSED'}")
    return elapsed


if __name__ == "__main__":
    reset(sys.argv[1:])
