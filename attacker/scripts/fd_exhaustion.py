"""S3: bounded FD pressure on a separate Target process over real SSH."""
import sys
import time
from pathlib import Path
from common import main, connect, result, event, remote_json


def execute(config):
    p = config["parameters"]
    if type(p.get("max_fds")) is not int or not 8 <= p["max_fds"] <= 256 or type(p.get("hold_sec")) is not int or not 1 <= p["hold_sec"] <= 8:
        raise ValueError("Invalid FD limits")
    client = connect(config)
    sftp = None
    work = None
    remote_started = False
    output = None
    try:
        sftp = client.open_sftp()
        sftp.get_channel().settimeout(1)
        root = sftp.normalize(config["ssh"]["sandbox"])
        if not root.endswith("/pbl4-lab"):
            raise ValueError("Invalid lab sandbox")
        work = root + "/run-" + config["run_id"]
        sftp.mkdir(work, mode=0o700)
        config["cleanup_pending"] = True
        event(config, "progress", stage="TARGET_FD_START", measurements={"requested_fds": p["max_fds"], "hold_sec": p["hold_sec"]})
        remote_started = True
        measured = remote_json(client, Path(__file__).with_name("remote_fd.py").read_text(), {**p, "work": work}, timeout=p["hold_sec"] + 4)
        output = result("Target FD probe completed; EMFILE is a process limit observation, not proof of whole-service protection", measured,
                        outcome="BLOCKED" if measured["hit_emfile"] else "OBSERVED")
        return output
    finally:
        if work and sftp:
            try:
                if remote_started:
                    with sftp.open(work + "/cancel", "w") as file:
                        file.write("stop")
                    deadline = time.monotonic() + 2
                    while True:
                        try:
                            sftp.stat(work + "/done")
                            break
                        except FileNotFoundError:
                            if time.monotonic() >= deadline:
                                raise TimeoutError("Remote cleanup acknowledgement missing")
                            time.sleep(0.05)
                for name in ["cancel", "done"]:
                    try:
                        sftp.remove(work + "/" + name)
                    except FileNotFoundError:
                        pass
                sftp.rmdir(work)
                config["cleanup_pending"] = False
            except Exception:
                config["cleanup_pending"] = True
        if output is not None:
            output["cleanup_pending"] = config["cleanup_pending"]
        if sftp:
            sftp.close()
        client.close()


if __name__ == "__main__":
    sys.exit(main("S3", execute))
