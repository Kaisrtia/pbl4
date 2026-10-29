"""Worker protocol: one input JSON, NDJSON events, explicit cancellation."""
import json
import signal
import socket
import sys
import time
from pathlib import Path

STOPPED = False


class Cancelled(Exception):
    pass


class PrerequisiteError(Exception):
    pass


def request_stop(_signal, _frame):
    global STOPPED
    STOPPED = True


def check_stop():
    if STOPPED:
        raise Cancelled()


def event(config, kind, **values):
    print(json.dumps({"run_id": config["run_id"], "type": kind, **values}), flush=True)


def result(summary, measurements=None, outcome="OBSERVED", cleanup_pending=False):
    return {"summary": summary, "measurements": measurements or {},
            "outcome": outcome, "cleanup_pending": cleanup_pending}


def connect(config):
    check_stop()
    try:
        import paramiko
    except ImportError as exc:
        raise PrerequisiteError("Install requirements.txt (Paramiko missing)") from exc
    ssh = config["ssh"]
    if not Path(ssh["known_hosts"]).is_file():
        raise PrerequisiteError("Verified SSH known_hosts file is missing")
    client = paramiko.SSHClient()
    client.load_host_keys(ssh["known_hosts"])
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    kwargs = dict(hostname=config["target"]["ip"], port=config["target"]["ssh_port"],
                  username=ssh["username"], timeout=3, banner_timeout=3, auth_timeout=3,
                  allow_agent=False, look_for_keys=False)
    password_file = ssh.get("password_file")
    if password_file:
        if not Path(password_file).is_file():
            raise PrerequisiteError("SSH password file is missing")
        kwargs["password"] = Path(password_file).read_text().rstrip("\r\n")
    else:
        if not Path(ssh["key_file"]).is_file():
            raise PrerequisiteError("SSH private key file is missing")
        kwargs["key_filename"] = ssh["key_file"]
    try:
        client.connect(**kwargs)
    except Exception:
        client.close()
        raise
    return client


def remote_json(client, program, parameters=None, timeout=12, cancellable=True):
    """Only repository-owned Python programs, never commands received from the API."""
    stdin, stdout, stderr = client.exec_command("python3 -u -", timeout=3)
    channel = stdout.channel
    code = "import json\nCONFIG=json.loads(" + repr(json.dumps(parameters or {})) + ")\n" + program
    data = b""
    errors = b""
    try:
        stdin.write(code)
        stdin.flush()
        channel.shutdown_write()
        deadline = time.monotonic() + timeout
        while True:
            if cancellable:
                check_stop()
            if channel.recv_ready():
                data += channel.recv(8192)
            if channel.recv_stderr_ready():
                errors += channel.recv_stderr(8192)
            if len(data) + len(errors) > 32768:
                raise RuntimeError("Remote response too large")
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if time.monotonic() > deadline:
                raise TimeoutError("Remote lab operation timed out")
            time.sleep(0.03)
        if channel.recv_exit_status() != 0:
            raise RuntimeError("Remote lab operation failed; inspect Target logs")
        return json.loads(data.decode().strip())
    finally:
        channel.close()


def main(scenario, execute):
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    config = None
    exit_code = 0
    try:
        config = json.loads(sys.stdin.read(16384))
        if config.get("schema_version") != "1.0" or config.get("scenario") != scenario:
            raise ValueError("Invalid worker request")
        import uuid
        uuid.UUID(config["run_id"])
        socket.inet_aton(config["target"]["ip"])
        config["cleanup_pending"] = False
        event(config, "ready", scenario=scenario)
        output = execute(config)
    except Cancelled:
        output = result("Stopped on request", outcome="INCONCLUSIVE", cleanup_pending=bool(config.get("cleanup_pending")))
    except Exception as exc:
        # Never echo passwords, SSH exception contents or sample payloads.
        try:
            import paramiko
            authentication_rejected = isinstance(exc, paramiko.AuthenticationException)
        except ImportError:
            authentication_rejected = False
        if authentication_rejected:
            output = result("SSH rejected the configured lab credential; subsequent steps were not executed",
                            {"authentication": "REJECTED", "remaining_steps": "NOT_EXECUTED"}, outcome="BLOCKED")
        else:
            exit_code = 3 if isinstance(exc, PrerequisiteError) else 2 if isinstance(exc, ValueError) else 1
            message = str(exc) if isinstance(exc, PrerequisiteError) else f"{type(exc).__name__}: lab operation failed"
            if config:
                event(config, "error", message=message)
            else:
                print(message, file=sys.stderr)
            output = result(message, outcome="INCONCLUSIVE", cleanup_pending=bool(config and config.get("cleanup_pending")))
    if config:
        output["cleanup_pending"] = output["cleanup_pending"] or config.get("cleanup_pending", False)
        event(config, "result", result=output)
    return exit_code
