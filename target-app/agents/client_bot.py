#!/usr/bin/env python3
"""
Client Bot Traffic Generator (Task W3-T3 - PBL4)
Người phụ trách: Hoàng Trung (TV3) - Target App & Tấn công L7

Mục đích:
- Giả lập hành vi người dùng định kỳ (duyệt sản phẩm, đăng nhập, gửi ping).
- Làm 'con mồi' (victim traffic) cho thành viên Minh Trí (TV2) thực hiện các kịch bản:
  + MitM Sniffing (S5): Bắt mật khẩu/token đăng nhập qua gói tin HTTP/TCP plaintext.
  + TCP RST Injection (W3-T2): Tiêm gói tin RST phá vỡ kết nối TCP ping liên tục.
- Cập nhật trạng thái sống về probe file phục vụ Docker Healthcheck và kiểm thử tích hợp.
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ClientBot")

# Biến cờ dừng tiến trình
STOPPED = False


def handle_shutdown(signum, frame):
    global STOPPED
    logger.info("Nhận tín hiệu dừng (SIGINT/SIGTERM). Đang kết thúc Client Bot...")
    STOPPED = True


signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)


class ClientBot:
    def __init__(
        self,
        base_url: str,
        interval: float,
        username: str,
        password: str,
        probe_file: str,
    ):
        self.base_url = base_url.rstrip("/")
        self.interval = interval
        self.username = username
        self.password = password
        self.probe_file = probe_file
        self.access_token: str | None = None
        self.session_id = f"client-bot-session-{int(time.time())}"
        self.iteration_count = 0

    def write_probe_status(
        self, ok: bool, status_code: int = 200, latency_ms: float = 0.0, error: str = ""
    ):
        """Ghi nhận bản tin probe phục vụ Docker healthcheck và verify.mjs"""
        if not self.probe_file:
            return

        probe_data = {
            "ok": ok,
            "status_code": status_code,
            "latency_ms": round(latency_ms, 2),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "client_bot": {
                "username": self.username,
                "session_id": self.session_id,
                "authenticated": self.access_token is not None,
                "iterations": self.iteration_count,
            },
        }
        if error:
            probe_data["error"] = error

        tmp_path = f"{self.probe_file}.tmp"
        try:
            Path(tmp_path).write_text(json.dumps(probe_data, indent=2))
            os.replace(tmp_path, self.probe_file)
        except Exception as e:
            logger.debug("Không thể ghi file probe (%s): %s", self.probe_file, e)

    def request(
        self,
        endpoint: str,
        method: str = "GET",
        body: dict | None = None,
        use_auth: bool = False,
        timeout: float = 4.0,
    ) -> tuple[int, dict | str | None, float]:
        """Gửi HTTP request và đo đạc độ trễ phản hồi"""
        url = f"{self.base_url}{endpoint}"
        headers = {
            "User-Agent": "PBL4-ClientBot/1.0 (ElectroShop Victim Agent)",
            "Accept": "application/json",
            "x-session-id": self.session_id,
        }
        if use_auth and self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"

        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        start_time = time.perf_counter()

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                content_type = resp.headers.get("Content-Type", "")
                raw_body = resp.read().decode("utf-8")
                parsed = json.loads(raw_body) if "application/json" in content_type else raw_body
                return resp.status, parsed, elapsed_ms
        except urllib.error.HTTPError as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            raw_body = e.read().decode("utf-8")
            try:
                parsed = json.loads(raw_body)
            except Exception:
                parsed = raw_body
            return e.code, parsed, elapsed_ms
        except urllib.error.URLError as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            raise ConnectionError(f"URLError: {e.reason}") from e

    def step_browse_products(self):
        """Bước 1: Duyệt danh mục linh kiện phần cứng ElectroShop"""
        status, data, latency = self.request("/api/products")
        if status == 200 and isinstance(data, dict):
            products_count = len(data.get("data", []))
            logger.info(
                "[BOT-BROWSE] Duyệt sản phẩm: %d linh kiện tìm thấy (HTTP %d, %.1f ms)",
                products_count,
                status,
                latency,
            )
        else:
            logger.warning("[BOT-BROWSE] Không thể duyệt sản phẩm: HTTP %d", status)

    def step_login(self):
        """Bước 2: Đăng nhập tài khoản thường (gửi mật khẩu qua HTTP - mồi ngon cho MitM Sniffing)"""
        login_payload = {
            "username": self.username,
            "password": self.password,
        }
        status, data, latency = self.request(
            "/api/auth/login", method="POST", body=login_payload
        )

        if status == 200 and isinstance(data, dict):
            self.access_token = data.get("access_token")
            token_preview = (
                f"{self.access_token[:15]}..." if self.access_token else "none"
            )
            logger.info(
                "[BOT-LOGIN] Đăng nhập thành công với user '%s' [Token: %s] (HTTP %d, %.1f ms)",
                self.username,
                token_preview,
                status,
                latency,
            )
        else:
            logger.warning(
                "[BOT-LOGIN] Đăng nhập thất bại cho user '%s': HTTP %d (%s)",
                self.username,
                status,
                data,
            )

    def step_browse_categories_and_cart(self):
        """Bước 3: Lấy danh mục và kiểm tra giỏ hàng người dùng"""
        # Duyệt categories
        status, data, latency = self.request("/api/products/categories")
        if status == 200 and isinstance(data, dict):
            cats = len(data.get("data", {}).get("categories", []))
            logger.info(
                "[BOT-CATEGORY] Lấy %d danh mục linh kiện (HTTP %d, %.1f ms)",
                cats,
                status,
                latency,
            )

        # Xem giỏ hàng
        status_cart, data_cart, latency_cart = self.request(
            "/api/cart", use_auth=True
        )
        if status_cart == 200 and isinstance(data_cart, dict):
            items = data_cart.get("data", {}).get("total_items", 0)
            logger.info(
                "[BOT-CART] Giỏ hàng hiện có: %d món (HTTP %d, %.1f ms)",
                items,
                status_cart,
                latency_cart,
            )

    def step_keepalive_ping(self) -> tuple[bool, int, float]:
        """Bước 4: Ping liên tục duy trì kết nối TCP (mục tiêu cho đòn TCP RST Injection)"""
        now_ms = int(time.time() * 1000)
        status, data, latency = self.request(
            f"/api/system/ping?t={now_ms}&echo=integration-client"
        )
        if status == 200 and isinstance(data, dict):
            logger.info(
                "[BOT-PING] Ping mạng OK (Độ trễ: %.1f ms, Server IP: %s)",
                latency,
                data.get("client_ip", "unknown"),
            )
            return True, status, latency
        else:
            logger.warning("[BOT-PING] Ping phản hồi bất thường: HTTP %d", status)
            return False, status, latency

    def run_cycle(self):
        """Thực hiện một chu kỳ duyệt web trọn vẹn"""
        self.iteration_count += 1
        logger.info(
            "--- [VÒNG LẶP #%d] Bắt đầu phiên duyệt web của Client Bot ---",
            self.iteration_count,
        )

        try:
            # 1. Duyệt danh mục sản phẩm
            self.step_browse_products()

            # 2. Đăng nhập hệ thống (bắn credentials qua network)
            self.step_login()

            # 3. Xem danh mục và giỏ hàng
            self.step_browse_categories_and_cart()

            # 4. Gửi Ping đo độ trễ & duy trì kết nối TCP
            ok, status, latency = self.step_keepalive_ping()

            # Ghi nhận trạng thái probe thành công
            self.write_probe_status(ok=ok, status_code=status, latency_ms=latency)
        except ConnectionError as err:
            logger.error(
                "[BOT-ALERT] Mất kết nối tới Target Server: %s (Có thể do tấn công DoS hoặc mạng gặp sự cố)",
                err,
            )
            self.write_probe_status(ok=False, status_code=503, error=str(err))
        except Exception as err:
            logger.error("[BOT-ERROR] Lỗi không xác định trong chu kỳ: %s", err)
            self.write_probe_status(ok=False, status_code=500, error=str(err))

    def start(self, once: bool = False):
        """Chạy vòng lặp định kỳ mỗi 3-5 giây"""
        logger.info(
            "Khởi động Client Bot (Target: %s, Chu kỳ: %.1fs, User: %s)",
            self.base_url,
            self.interval,
            self.username,
        )

        while not STOPPED:
            cycle_start = time.time()
            self.run_cycle()

            if once:
                logger.info("Chế độ chạy 1 lần (--once) hoàn thành.")
                break

            # Tính toán thời gian nghỉ giữa các chu kỳ
            elapsed = time.time() - cycle_start
            sleep_time = max(0.5, self.interval - elapsed)
            time.sleep(sleep_time)


def parse_args():
    parser = argparse.ArgumentParser(
        description="PBL4 Client Bot Traffic Generator (Task W3-T3)"
    )
    parser.add_argument(
        "--target-url",
        default=os.environ.get("TARGET_APP_URL", "http://localhost:8000"),
        help="URL máy chủ mục tiêu (mặc định: http://localhost:8000 hoặc ENV TARGET_APP_URL)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=float(os.environ.get("CLIENT_INTERVAL_SEC", "3.5")),
        help="Khoảng cách giữa các chu kỳ (giây, mặc định: 3.5s)",
    )
    parser.add_argument(
        "--username",
        default=os.environ.get("CLIENT_USERNAME", "engineer_user"),
        help="Tài khoản đăng nhập giả lập (mặc định: engineer_user)",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("CLIENT_PASSWORD", "pass123"),
        help="Mật khẩu đăng nhập giả lập (mặc định: pass123)",
    )
    parser.add_argument(
        "--probe-file",
        default=os.environ.get("PROBE_FILE_PATH", "/tmp/client-probe.json"),
        help="Đường dẫn file ghi kết quả probe cho Docker Healthcheck (mặc định: /tmp/client-probe.json)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Chỉ chạy 1 chu kỳ duy nhất rồi thoát (dùng cho test/verification)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    bot = ClientBot(
        base_url=args.target_url,
        interval=args.interval,
        username=args.username,
        password=args.password,
        probe_file=args.probe_file,
    )
    bot.start(once=args.once)
