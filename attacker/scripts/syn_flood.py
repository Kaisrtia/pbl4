"""Bounded raw SYN worker. No TCP-connect or estimated-count fallback."""
import socket
import sys
import time
from common import main, event, result, check_stop, PrerequisiteError


def execute(config):
    try:
        from scapy.all import IP, TCP, conf, RandShort
    except ImportError as exc:
        raise PrerequisiteError("Install requirements.txt (Scapy missing)") from exc
    pps = config["parameters"].get("pps", 50)
    duration = config["parameters"].get("duration_sec", 5)
    if type(pps) is not int or not 1 <= pps <= 150 or type(duration) is not int or not 1 <= duration <= 15:
        raise ValueError("Invalid SYN limits")
    try:
        test = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        test.close()
        sender = conf.L3socket()
    except PermissionError as exc:
        raise PrerequisiteError("Raw SYN requires CAP_NET_RAW; no substitute traffic was sent") from exc
    sent = 0
    started = time.monotonic()
    next_report = started + 1
    try:
        while sent < pps * duration and time.monotonic() - started < duration:
            check_stop()
            packet = IP(dst=config["target"]["ip"]) / TCP(sport=int(RandShort()), dport=config["target"]["http_port"], flags="S")
            sender.send(packet)
            sent += 1
            now = time.monotonic()
            if now >= next_report:
                event(config, "progress", stage="SYN_SEND", measurements={"send_calls_succeeded": sent})
                next_report = now + 1
            time.sleep(max(0, started + sent / pps - time.monotonic()))
    finally:
        sender.close()
    return result("Raw SYN send operations completed; Target/Client evidence is required to assess impact", {
        "send_calls_succeeded": sent, "duration_sec": round(time.monotonic() - started, 3),
        "traffic_mode": "RAW_SYN", "target_received": None, "syn_recv_peak": None,
        "firewall_drops": None, "defense_effectiveness": "NOT_ASSESSED",
        "note": "Local kernel may send RST to unsolicited SYN-ACK; do not infer SYN backlog saturation from send count",
    })


if __name__ == "__main__":
    sys.exit(main("S2", execute))
