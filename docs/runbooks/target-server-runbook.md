# Kịch Bản Vận Hành & Thực Nghiệm Máy Chủ Mục Tiêu (Target Server Runbook)

> **Người thực hiện:** Hoàng Trung (TV3) — *Target App & L7 Defense Testbed*  
> **Mục đích:** Hướng dẫn từng bước cách khởi chạy, kiểm thử tự động và thực nghiệm demo các kịch bản tấn công/phòng thủ L7 trước hội đồng chấm đồ án PBL4.

---

## 1. Yêu cầu tiên quyết & Chuẩn bị môi trường

1. **Cài đặt môi trường:**
   - Node.js version $\ge 22.x$ (khuyến nghị Node.js 26 có sẵn `node:sqlite`).
   - Công cụ gửi yêu cầu: Trình duyệt web, cURL, hoặc giao diện Swagger UI.
2. **Di chuyển vào thư mục máy chủ:**
   ```powershell
   cd target-app/server
   ```
3. **Thiết lập biến môi trường:**
   ```powershell
   cp .env.example .env
   ```
4. **Cài đặt các gói thư viện:**
   ```powershell
   npm install
   ```

---

## 2. Khởi chạy máy chủ Target Server

```powershell
# Chạy chế độ phát triển
npm run start:dev
```
- Khi máy chủ khởi động thành công, màn hình sẽ hiển thị:
  ```text
  Target Server is running on: http://localhost:8000/api
  Interactive Swagger UI at: http://localhost:8000/api/docs
  SQLite database connected at [./data/devsec.sqlite] (WAL mode enabled)
  ```

---

## 3. Cách 1: Kiểm thử tự động bằng Vitest (Dành cho nghiệm thu code)

Chỉ cần chạy một lệnh duy nhất:
```powershell
npm run test:e2e
```
- Hệ thống sẽ tự động khởi động server trong RAM và duyệt qua **toàn bộ 20 kịch bản kiểm thử**.
- Kết quả mong đợi: `20 passed (100% xanh)`.

---

## 4. Cách 2: Kịch bản Thực nghiệm Thủ công (Dành cho Demo trước Hội đồng)

### Kịch bản A: Khai thác SQL Injection Bypass & Kích hoạt Phòng thủ

#### Bước 1: Đảm bảo Khiên L3 đang TẮT
```powershell
curl -X POST http://localhost:8000/api/defense/set -H "Content-Type: application/json" -d "{\"l3_master\": false, \"anti_sqli\": false}"
```

#### Bước 2: Bắn payload SQL Injection để đăng nhập lậu không cần mật khẩu
```powershell
curl -X POST http://localhost:8000/api/auth/login -H "Content-Type: application/json" -d "{\"username\": \"admin' --\", \"password\": \"mat_khau_bat_ky\"}"
```
- **Kết quả quan sát:**
  - Trả về mã **HTTP 200 OK**.
  - Server trả về thông tin user `admin` kèm cảnh báo an ninh màu vàng:
    `"⚠️ [CẢNH BÁO AN NINH] Đăng nhập thành công qua lỗ hổng SQL Injection (Khiên L3 đang tắt)!"`

#### Bước 3: Gạt công tắc BẬT Khiên L3 (Nút "Lab Control")
```powershell
curl -X POST http://localhost:8000/api/defense/toggle -H "Content-Type: application/json" -d "{}"
```
- **Kết quả quan sát:** `current_state.anti_sqli = true`.

#### Bước 4: Bắn lại đúng payload SQL Injection trên
```powershell
curl -X POST http://localhost:8000/api/auth/login -H "Content-Type: application/json" -d "{\"username\": \"admin' --\", \"password\": \"mat_khau_bat_ky\"}"
```
- **Kết quả quan sát:**
  - Server lập tức trả về mã **HTTP 401 Unauthorized**.
  - Prepared Statement tham số hóa câu truy vấn, đòn tấn công bị vô hiệu hóa hoàn toàn!

---

### Kịch bản B: Tấn công L7 DoS & Khiên Giới hạn Tần suất (Rate Limiting)

#### Bước 1: Đảm bảo Khiên Rate Limit đang BẬT
```powershell
curl -X POST http://localhost:8000/api/defense/set -H "Content-Type: application/json" -d "{\"l3_master\": true, \"rate_limit\": true}"
```

#### Bước 2: Gửi dồn dập các request tính toán nặng CPU
Chạy vòng lặp PowerShell bắn liên tục 15 request trong 2 giây:
```powershell
1..15 | ForEach-Object {
    curl.exe -s -o /dev/null -w "%{http_code}`n" "http://localhost:8000/api/reports/analytics?iterations=50000"
}
```
- **Kết quả quan sát:**
  - 10 request đầu tiên trả về mã **200 OK**.
  - Từ request thứ 11 trở đi, server lập tức ngắt luồng và trả về mã **HTTP 429 Too Many Requests**.
  - Phản hồi chứa cờ: `shield: "L3_RATE_LIMIT_ACTIVE"`. CPU máy chủ được bảo vệ an toàn!

---

### Kịch bản C: Tấn công Leo thang thư mục (Path Traversal)

#### Bước 1: Khiên L3 TẮT $\rightarrow$ Đọc trộm file
```powershell
curl -X POST http://localhost:8000/api/defense/set -H "Content-Type: application/json" -d "{\"l3_master\": false, \"input_sanitization\": false}"
curl "http://localhost:8000/api/files/download?name=sample_report.txt"
```

#### Bước 2: Bắn payload Path Traversal khi Khiên L3 BẬT
```powershell
curl -X POST http://localhost:8000/api/defense/set -H "Content-Type: application/json" -d "{\"l3_master\": true, \"input_sanitization\": true}"
curl -i "http://localhost:8000/api/files/download?name=../../etc/passwd"
```
- **Kết quả quan sát:**
  - Server trả về mã **HTTP 400 Bad Request**.
  - Thông báo: `"L3 Sanitization Shield: Tên file chứa ký tự điều hướng thư mục bất hợp pháp!"`.

---

### Kịch bản D: Tải Tài Liệu Tuyệt Mật (Blueprint Exfiltration)

#### Bước 1: Khiên BẬT
```powershell
curl -i "http://localhost:8000/api/documents/5/download"
```
- **Kết quả:** Trả về mã **HTTP 403 Forbidden** (`L3_CONFIDENTIAL_POLICY_ACTIVE`).

#### Bước 2: Khiên TẮT
```powershell
curl -X POST http://localhost:8000/api/defense/set -H "Content-Type: application/json" -d "{\"l3_master\": false, \"input_sanitization\": false}"
curl "http://localhost:8000/api/documents/5/download"
```
- **Kết quả:** Tải thành công file Blueprint bảo mật chứa Flag:
  `FLAG{PBL4_PATH_TRAVERSAL_AND_CONFIDENTIAL_DOC_LEAKED}`.

---

## 5. Làm sạch môi trường sau Thực nghiệm (Reset Lab)

Để khôi phục trạng thái giỏ hàng và cơ sở dữ liệu về mặc định ban đầu:
```powershell
# Xóa file sqlite cũ để hệ thống tự động khởi tạo và seed lại dữ liệu sạch
rm ./data/devsec.sqlite*
```
Sau đó khởi động lại server, database sẽ tự động được tạo mới với đầy đủ 4 tài khoản, 3 danh mục, 6 linh kiện và 2 món giỏ hàng mẫu.
