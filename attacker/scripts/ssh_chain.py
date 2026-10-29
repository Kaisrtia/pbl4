"""Real SSH with scoped lab artifacts; no authorized_keys or system-log changes."""
import socket
import sys
from common import main, connect, event, result, check_stop, remote_json


def execute(config):
    stages = []
    def record(stage, **data):
        stages.append({"stage": stage, **data})
        event(config, "progress", stage=stage, measurements=data)

    with socket.create_connection((config["target"]["ip"], config["target"]["ssh_port"]), timeout=3) as sock:
        banner = sock.recv(256).decode(errors="replace").strip()
    record("1_RECON", ssh_banner=banner, note="An open SSH port is not proof of a vulnerability")
    check_stop()
    client = connect(config)
    sftp = None
    work = None
    try:
        transport = client.get_transport()
        record("2_AUTH_CONFIGURATION", auth_method="password" if config["ssh"].get("password_file") else "key",
               note="One configured lab credential; no brute force or inferred sshd configuration",
               server_version=transport.remote_version)
        identity = remote_json(client, "import os\nprint(json.dumps({'uid':os.getuid(),'gid':os.getgid()}))\n")
        record("3_INITIAL_ACCESS", **identity)
        sftp = client.open_sftp()
        sftp.get_channel().settimeout(2)
        root = sftp.normalize(config["ssh"]["sandbox"])
        if not root.endswith("/pbl4-lab"):
            raise ValueError("Target sandbox must resolve to a dedicated pbl4-lab directory")
        work = root + "/run-" + config["run_id"]
        sftp.mkdir(work, mode=0o700)
        config["cleanup_pending"] = True
        with sftp.open(work + "/reconnect-marker.txt", "w") as file:
            file.write(config["run_id"])
        with sftp.open(work + "/audit-copy.txt", "w") as file:
            file.write("Synthetic audit copy for run " + config["run_id"])
        sftp.close()
        sftp = None
        client.close()
        check_stop()
        client = connect(config)
        sftp = client.open_sftp()
        sftp.get_channel().settimeout(2)
        with sftp.open(work + "/reconnect-marker.txt") as file:
            marker = file.read(128).decode()
        if marker != config["run_id"]:
            raise RuntimeError("Reconnect marker mismatch")
        record("4_RECONNECT", marker_verified=True,
               note="Re-authentication with the same credential; persistence mechanics are represented by a lab marker, not a backdoor")
        check_stop()
        sftp.remove(work + "/audit-copy.txt")
        record("5_AUDIT_COPY_REMOVAL", removed=True,
               note="Only this run's synthetic audit copy was removed; controller evidence and system logs remain")
        return result("SSH sequence completed; stages 4/5 are explicitly scoped lab surrogates", {"stages": stages})
    finally:
        if work:
            try:
                if sftp is None:
                    sftp = client.open_sftp()
                    sftp.get_channel().settimeout(2)
                for name in ["audit-copy.txt", "reconnect-marker.txt"]:
                    try:
                        sftp.remove(work + "/" + name)
                    except FileNotFoundError:
                        pass
                sftp.rmdir(work)
                config["cleanup_pending"] = False
            except Exception:
                config["cleanup_pending"] = True
        if sftp:
            sftp.close()
        client.close()


if __name__ == "__main__":
    sys.exit(main("S1", execute))
