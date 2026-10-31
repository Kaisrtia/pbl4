# Target Server — ElectroShop Backend & L7 Defense Testbed

> **Phụ trách:** Hoàng Trung (TV3) — *Target App & Kịch bản Tấn công / Phòng thủ L7*  
> **Dự án:** PBL4 — Hệ thống Mô phỏng & Giám sát Tấn công Mạng & Hệ điều hành (God-View)  
> **Framework:** NestJS 12 (TypeScript, Node.js 26)  
> **Cơ sở dữ liệu:** SQLite WAL Mode (`node:sqlite`)  
> **Tài liệu API tương tác (Swagger UI):** `http://localhost:8000/api/docs`

---

## 1. Giới thiệu tổng quan

**Target Server** đóng vai trò là ứng dụng máy chủ mục tiêu trong mô hình thử nghiệm phòng thủ mạng 3 lớp (Defense-in-Depth). Hệ thống cung cấp hai nhóm chức năng cốt lõi:

1. **Nghiệp vụ Cửa hàng Điện tử (ElectroShop):** Cung cấp toàn bộ REST API phục vụ giao diện người dùng mua sắm linh kiện phần cứng, bo mạch vi điều khiển (MCU), cảm biến và module nguồn.
2. **Môi trường Mô phỏng Tấn công & Phòng thủ Tầng Ứng dụng (Layer 7 / L3 Shield):** Được thiết kế có chủ đích (by design) để hỗ trợ bật/tắt khiên chắn L3, cho phép đo lường hiệu năng và kiểm chứng khả năng phòng thủ trước các đòn tấn công:
   - **SQL Injection:** Khai thác bypass đăng nhập khi khiên tắt; tự động bảo vệ bằng Prepared Statement khi khiên bật.
   - **L7 DoS / CPU Flooding:** Gửi yêu cầu tính toán CPU nặng hàng trăm nghìn vòng băm SHA-256; kích hoạt `DynamicRateLimitGuard` chặn mã 429 khi khiên bật.
   - **Path Traversal:** Tấn công đọc trộm tài liệu hệ thống; bị chặn đứng bởi bộ lọc `InputSanitization` khi khiên bật.
   - **Rò rỉ tài liệu mật:** Bảo vệ bản thiết kế tuyệt mật (Confidential Blueprint) khi khiên bật; mô phỏng rò rỉ dữ liệu khi khiên tắt.

---

## 2. Danh mục API Endpoints

Hệ thống hỗ trợ Swagger UI trực quan tại `http://localhost:8000/api/docs`. Dưới đây là bảng tổng hợp các endpoint chính:

| Phân nhóm | Phương thức | Endpoint | Mô tả chức năng |
| :--- | :--- | :--- | :--- |
| **Authentication** | `POST` | `/api/auth/login` | Đăng nhập tài khoản, khai thác SQLi (`admin' --`) khi khiên tắt, cấp JWT 30 ngày |
| **Defense Control** | `GET` | `/api/defense/status` | Lấy trạng thái hiện tại của Khiên L3 Master và các cờ con |
| | `POST` | `/api/defense/toggle` | Đảo trạng thái Khiên L3 (Nút **Lab Control** trên giao diện) |
| | `POST` | `/api/defense/set` | Thiết lập cờ phòng thủ cụ thể (`anti_sqli`, `rate_limit`, `input_sanitization`) |
| **Products** | `GET` | `/api/products/categories` | Lấy danh mục kèm số lượng sản phẩm cho các Filter Pills trên Navbar |
| | `GET` | `/api/products` | Lấy danh sách linh kiện (hỗ trợ lọc `category`, tìm kiếm `search`, sắp xếp `sort`) |
| | `GET` | `/api/products/sku/:sku` | Xem chi tiết linh kiện theo mã SKU (ví dụ: `MCU-ARD-R4`) |
| | `GET` | `/api/products/:id` | Xem chi tiết linh kiện theo ID số |
| **Cart** | `GET` | `/api/cart` | Lấy danh sách giỏ hàng & tổng số lượng món (Badge `[2]` trên Navbar) |
| | `POST` | `/api/cart` | Thêm linh kiện vào giỏ hàng (click nút **Thêm giỏ**) |
| | `PATCH` | `/api/cart/items/:id` | Cập nhật số lượng linh kiện trong giỏ |
| | `DELETE` | `/api/cart/items/:id` | Xóa một linh kiện khỏi giỏ hàng |
| | `DELETE` | `/api/cart` | Xóa sạch toàn bộ giỏ hàng |
| **Documents** | `GET` | `/api/documents` | Lấy danh sách Datasheets công khai (mặc định ẩn tài liệu mật) |
| | `GET` | `/api/documents/:id` | Lấy metadata chi tiết của một tài liệu kỹ thuật |
| | `GET` | `/api/documents/:id/download` | Tải file Datasheet / Blueprint (chặn 403 khi khiên L3 bật) |
| **Reports (DoS)** | `GET` | `/api/reports/analytics` | Tác vụ CPU nặng tiêu tốn chu kỳ tính toán SHA-256 (hỗ trợ tham số `iterations`) |
| **Files (Traversal)** | `GET` | `/api/files/download` | Tải file công khai (mô phỏng lỗ hổng Path Traversal `?name=../../etc/passwd`) |
| **System** | `GET` | `/api/system/health` | Kiểm tra trạng thái máy chủ `online` và uptime |
| | `GET` | `/api/system/ping` | Đo độ trễ phản hồi (latency ms) trước và sau khi bị tấn công |

---

## 3. Cài đặt & Khởi chạy

### 3.1. Yêu cầu môi trường
- **Node.js:** phiên bản `>= 22.x` (khuyến nghị Node.js 26 có sẵn module `node:sqlite`).
- **npm:** phiên bản `>= 10.x`.

### 3.2. Cấu hình biến môi trường
Sao chép file mẫu `.env.example` thành `.env`:
```bash
cp .env.example .env
```
Các thông số cấu hình chính trong `.env`:
```env
PORT=8000
NODE_ENV=development
CORS_ORIGIN=*
JWT_SECRET=pbl4_devsec_super_secret_jwt_key_2026!
JWT_EXPIRES_IN=30d
DATABASE_PATH=./data/devsec.sqlite
RATE_LIMIT_WINDOW_MS=5000
RATE_LIMIT_MAX_REQUESTS=10
GODVIEW_TELEMETRY_URL=http://localhost:4000/api/telemetry
```

### 3.3. Khởi chạy máy chủ
```bash
# Cài đặt thư viện phụ thuộc
npm install

# Khởi chạy chế độ phát triển (Hot reload)
npm run start:dev

# Biên dịch mã nguồn production
npm run build

# Khởi chạy production
npm run start:prod
```

Sau khi khởi chạy thành công, truy cập:
- API Root: `http://localhost:8000/api`
- Swagger UI: `http://localhost:8000/api/docs`

---

## 4. Kiểm thử tự động (Unit & E2E Testing)

Dự án tích hợp bộ kiểm thử tự động sử dụng **Vitest** và **Supertest**, bao gồm 20 kịch bản E2E kiểm chứng trọn vẹn mọi hành vi tấn công và phòng thủ:

```bash
# Chạy Unit Tests
npm test

# Chạy toàn bộ 20 kịch bản kiểm thử E2E (End-to-End)
npm run test:e2e
```

**Các kịch bản được tự động kiểm chứng:**
1. Health check & Ping latency.
2. Tắt khiên $\rightarrow$ Khai thác bypass SQLi thành công với `admin' --`.
3. Bật khiên $\rightarrow$ Chặn đứng cùng payload SQLi với mã lỗi 401.
4. Đăng nhập chuẩn xác & xác thực thời hạn JWT đúng 30 ngày ($2.592.000$ giây).
5. Mô phỏng tải nặng L7 DoS & chặn Rate Limiting.
6. Chặn tấn công Path Traversal `../../etc/passwd` bằng mã 400.
7. Lọc danh mục linh kiện ElectroShop và tìm kiếm sản phẩm.
8. Thao tác giỏ hàng (thêm, cập nhật số lượng, xóa món, xóa sạch giỏ).
9. Tải tài liệu Datasheet và chặn rò rỉ tài liệu tuyệt mật khi khiên L3 bật.

---

## 5. Cấu trúc thư mục mã nguồn

```text
src/
├── common/
│   └── interceptors/telemetry.interceptor.ts   # Bắn log telemetry sang trạm God-View
├── config/
│   └── env.config.ts                           # Nạp và chuẩn hóa cấu hình từ .env
├── database/
│   ├── database.module.ts
│   └── database.service.ts                     # Engine SQLite WAL + Seed Data
├── modules/
│   ├── auth/                                   # Xác thực, JWT 30d & SQLi testbed
│   ├── defense/                                # Khiên L3 Master & DynamicRateLimitGuard
│   ├── products/                               # Danh mục & linh kiện ElectroShop
│   ├── cart/                                   # Quản lý giỏ hàng & badge [2]
│   ├── documents/                              # Tài liệu kỹ thuật & Blueprint bảo mật
│   ├── reports/                                # Tác vụ CPU nặng (L7 DoS simulation)
│   ├── files/                                  # Tải file & Path Traversal simulation
│   └── system/                                 # Health check & Ping latency
└── main.ts                                     # Khởi tạo NestJS, Swagger UI & CORS
```
