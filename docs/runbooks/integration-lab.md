# Lab tích hợp bốn node

Bản đề xuất tích hợp cho nhánh `feature/integration-lab`, dựa trên `develop`
`91d2cbf`. Dùng **backend Target thật**, God-View thật và Attacker S1–S4 hiện có.
Client hiện là HTTP ping probe; chưa thay thế Client bot đăng nhập/tải file của Trung.

Demo hai máy: xem [hướng dẫn hotspot điện thoại](demo-two-machines-hotspot.md).

## Khởi chạy

Yêu cầu Docker Engine + Compose v2 (`--wait`), Python 3 để tạo cấu hình,
Node.js >=22 để chạy script kiểm chứng trên host. Container Target/God-View dùng
Node.js 26. Chạy từ thư mục gốc repo:

```bash
./scripts/integration-lab.sh init
./scripts/integration-lab.sh up
./scripts/integration-lab.sh status
./scripts/integration-lab.sh test
```

`init` tạo `integration/.env.local` với token/JWT secret ngẫu nhiên, quyền 0600;
không ghi đè cấu hình đã có. Chỉ chia sẻ `.env.example`, không chia sẻ `.env.local`
hoặc volume credentials. Token để mở Attacker UI nằm tại `LAB_ATTACKER_TOKEN`
trong file local. Mỗi thành viên chạy `init` trên máy mình.

| Node | IP nội bộ mặc định | URL trên máy chạy Docker |
|---|---|---|
| Client | 172.30.44.10 | Không publish; gửi ping mỗi 3 giây |
| Target | 172.30.44.20 | http://127.0.0.1:18000/api/docs |
| Attacker | 172.30.44.66 | http://127.0.0.1:19090 |
| God-View | 172.30.44.99 | http://127.0.0.1:14000 |

Mạng `172.30.44.0/24` được chọn vì `172.20.0.0/24` đang dùng bởi lab
`pbl4-security`. Giữ nguyên hậu tố .10/.20/.66/.99. Có thể đổi subnet, cả bốn IP
và các cổng host trong `integration/.env.local` trước khi chạy. Các cổng nội bộ
vẫn là Target 8000, God-View 4000, Attacker 9000/9001 và SSH Target 22.

Compose project luôn là `pbl4-integration`, không dùng `container_name` cố định,
mạng bridge riêng, mặc định chỉ publish lên loopback. Lệnh `lan <IPv4>` đổi
`LAB_BIND_IP` sang đúng địa chỉ Wi-Fi của máy chủ để máy thứ hai truy cập; lệnh
`local` đưa về loopback. Chạy lại `up` sau khi đổi. Không mount Docker socket,
filesystem host hoặc dùng `privileged`/host network. Attacker chỉ thêm `NET_RAW`;
chưa thêm quyền hoặc cấu hình phòng thủ L1/L2 cho các bài sau.

## Kiểm chứng và xem bằng chứng

Script `test` kiểm tra Client → Target → God-View, trạng thái L3 đúng và đặt cùng
giá trị hai lần không bị đảo lại, từ chối traversal khi L3 bật; sau đó chạy:

- S1: chuỗi SSH trong sandbox.
- S2: 5 SYN/giây trong 1 giây, kiểm tra số lần gửi; không kết luận Target ngập backlog.
- S3: 32 file descriptor trong 1 giây, tiến trình Python riêng.
- S4: truyền tệp mẫu tổng hợp và so SHA-256 với receiver.

Mỗi run phải `COMPLETED`, không còn `cleanup_pending`, và sự kiện tương ứng phải
đến God-View. Script khôi phục các cờ L3 ban đầu trong `finally`.
Không chạy script trong lúc một thành viên đang điều khiển thực nghiệm cùng lab.

Trên God-View, phần **ATTACKER · REAL RUN EVENTS** hiển thị `run_id` và JSON bằng
chứng. HTTP log có bảng riêng. TCP meters vẫn được đánh dấu **SIMULATED**;
Quick Demo chỉ tạo log có nhãn `[DEMO]`, không gửi request tấn công đến Target.

```bash
./scripts/integration-lab.sh logs
./scripts/integration-lab.sh down
```

`down` chỉ dừng/xóa container và network của project này; giữ SQLite, journal
Attacker và SSH credential trong named volumes. Đây chưa phải reset lab một chạm.
Để xóa dữ liệu của riêng lab tích hợp khi thực sự cần khởi tạo lại:

```bash
docker compose --project-name pbl4-integration --env-file integration/.env.local -f compose.integration.yaml down --volumes
```

Lịch sử God-View lưu trong RAM, mất khi restart. SSH key được sinh trong volume
riêng; `known_hosts` được tạo từ host key trong Target, không tắt xác minh host.
Không publish SSH ra host. Target được bổ sung OpenSSH + Python qua Docker wrapper,
không sửa API nghiệp vụ của Trung.

## Kiểm thử module

```bash
npm --prefix god-view/backend ci
npm --prefix god-view/backend run build
npm --prefix god-view/backend test
npm --prefix attacker ci
npm --prefix attacker run build
npm --prefix attacker test
npm --prefix attacker run test:python
npm --prefix target-app/server ci
npm --prefix target-app/server run build
npm --prefix target-app/server test
```

E2E Target nên chạy từ `target-app/server` với DB riêng và telemetry không trỏ
về một lab đang dùng:

```bash
cd target-app/server
DATABASE_PATH=:memory: GODVIEW_TELEMETRY_URL=http://127.0.0.1:1/api/telemetry npm run test:e2e
```

Lint Target có lỗi tồn tại từ `91d2cbf` do cấu hình TypeScript/oxlint (`moduleResolution`
và `baseUrl`); bản tích hợp không sửa cấu hình này. Chưa có agent kernel/OS,
ARP/RST, phòng thủ L1/L2, hoặc kiểm thử hiệu quả phòng thủ mạng. Không dùng build
thành công hoặc chỉ số mô phỏng làm bằng chứng nghiệm thu toàn bộ đồ án.
