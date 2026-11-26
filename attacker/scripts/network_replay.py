"""Play a timed, fictional endpoint trace through the NDJSON worker protocol."""
import json
import signal
import sys
from threading import Event


def replay(request, emit, wait):
    params = request["parameters"]
    scenario = request["scenario"]
    arp = scenario == "S5"
    measurements = {"source": "fixture"}
    count = 0
    emit("ready", scenario=scenario)
    emit("progress", stage="Bắt đầu bản ghi mẫu", sample="ARP_MATCH" if arp else "TCP_ESTABLISHED")
    for second in range(1, params["duration_sec"] + 1):
        if wait(1):
            return "INCONCLUSIVE", "Đã dừng phát lại.", measurements
        if arp and params["observe"] and (second - 1) % params["interval_sec"] == 0:
            count += 1
            emit("progress", stage="Mẫu ARP", elapsed_sec=second, peer_binding="MISMATCH")
        if not arp and second >= 2 and (second - 2) % params["cooldown_sec"] == 0 and count < params["max_rst"]:
            count += 1
            emit("progress", stage="Mẫu ACK và RST", elapsed_sec=second, sample_index=count)
    if arp:
        measurements.update(observed_samples=count, final_client_cache="MATCH", final_target_cache="MATCH")
        emit("progress", stage="Kết thúc bản ghi ARP", client_cache="MATCH", target_cache="MATCH")
        return "OBSERVED", "Hai bảng ARP trong bản ghi mẫu đã trở về ban đầu.", measurements
    measurements.update(rst_samples=count, session_interruption_verified=False)
    if count:
        return "OBSERVED", "Bản ghi mẫu có ACK và RST. Tác động lên phiên chưa được xác minh.", measurements
    return "INCONCLUSIVE", "Cửa sổ phát lại kết thúc trước ACK đầu tiên.", measurements


def main():
    stopped = Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopped.set())
    request = json.load(sys.stdin)
    if request["scenario"] not in ("S5", "S6") or request["schema_version"] != "1.0":
        raise ValueError("Unsupported fixture")
    def emit(kind, **fields):
        print(json.dumps({"run_id": request["run_id"], "type": kind, **fields}), flush=True)
    outcome, summary, measurements = replay(request, emit, stopped.wait)
    emit("result", result={"outcome": outcome, "summary": summary,
                           "measurements": measurements, "cleanup_pending": False})


if __name__ == "__main__":
    main()
