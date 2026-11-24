# Lab tích hợp bốn node

Bản đề xuất tích hợp cho nhánh `feature/integration-lab`, dựa trên `develop`
`9730163` (đã gồm PR #8 và #9). Dùng **backend Target thật**, God-View thật và Attacker S1–S4 hiện có.
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
| Target | 172.30.44.20 | http://127.0.0.1:18000/; Swagger tại /api/docs |
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

### W2-T2 · Kiểm tra mẫu từ Client và Target

Compose khởi chạy một agent Python trong mỗi container `client` và `target`.
Sau mỗi lần lấy mẫu, agent gửi JSON tới `POST /api/telemetry/host` của God-View
rồi chờ 5 giây. Khi hub trả HTTP 200, agent thay thế file mẫu gần nhất trong
container. Nếu hub tạm ngừng, file giữ timestamp cũ và agent thử lại ở chu kỳ sau.

Nghiệm thu trên Docker dùng cgroup v2, chạy từ thư mục gốc. Bài kiểm tra bật
ba service và đợi **hai mẫu mới** được God-View tiếp nhận cho từng node.

```bash
./scripts/integration-lab.sh init
./scripts/integration-lab.sh telemetry-test
```

Để xem chi tiết mẫu sau khi hai dòng `PASS` xuất hiện:

```bash
lab=(docker compose --env-file integration/.env.local -f compose.integration.yaml)
for service in client target; do
  "${lab[@]}" exec -T "$service" python3 -c 'import json; s=json.load(open("/tmp/pbl4-host-telemetry.json")); print(s["node"], s["ip"], s["timestamp"], s["metrics"])'
done
```

Cả `client` và `target-server` cần có timestamp tăng giữa hai lần đọc và IP
khớp cấu hình lab. Kiểm tra từng mẫu riêng vì hub hiện dùng chung trạng thái
hiển thị cho cả hai node và chưa hiển thị CPU/RAM. Có thể đối chiếu trực tiếp
với `"${lab[@]}" exec -T target cat /proc/net/arp` trong cùng cửa sổ lấy mẫu.

| Trường | Cách đọc |
|---|---|
| `tcp_syn_recv`, `tcp_established`, `tcp_time_wait` | Số socket ở từng trạng thái trong namespace mạng của node, bao gồm IPv6 khi có. |
| `cpu_percent`, `ram_used_mb` | Mức dùng cgroup v2 của container. CPU tính từ hai lần đọc liên tiếp, 100% tương ứng một lõi. RAM dùng đơn vị MiB. Trường thiếu khi nguồn đo chưa sẵn sàng. |
| `open_fds`, `fd_pid`, `max_fds` | Số FD, PID và giới hạn mềm của tiến trình có nhiều FD đọc được nhất. `visible_fds_total` là tổng số FD đọc được trong namespace. |
| `pstree` | Quan hệ PID/PPID, tên tiến trình và UID. Trường `cmd` chỉ chứa tên tiến trình để tương thích với UI. |
| `arp_neighbors` | Các ánh xạ Ethernet đã phân giải trong cache. Nếu đã biết MAC thật từ nguồn độc lập, đặt `LAB_CLIENT_MAC` hoặc `LAB_TARGET_MAC` trong cấu hình lab. Agent phía đối diện sẽ bổ sung `arp_table` với kết quả so khớp khi có entry của peer. Cần cập nhật MAC tham chiếu nếu Docker tạo lại endpoint. |

Test ngoại tuyến của agent:

```bash
python3 -m unittest discover -v -s integration -p 'test_host_agent.py'
```

#### Biên bản nghiệm thu Docker ngày 24/11/2026

Lệnh `telemetry-test` kết thúc với mã 0. God-View trả HTTP 200 cho hai mẫu
mới liên tiếp từ mỗi node. Thời điểm mẫu cuối dưới đây dùng UTC.

```text
PASS client 172.30.44.10: two acknowledged samples, latest 2026-11-24T03:42:36.462467+00:00
PASS target-server 172.30.44.20: two acknowledged samples, latest 2026-11-24T03:42:42.878923+00:00
```

Bài kiểm tra đối chiếu danh tính node, thời điểm, số socket TCP, CPU/RAM,
FD, cây tiến trình và định dạng danh sách ARP. Việc xác minh MAC của peer
hoặc hiệu lực khiên L1/L2 cần phép đo riêng.

### Các module khác

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

Lint Target có lỗi tồn tại từ `9730163` (đã gồm PR #8 và #9) do cấu hình TypeScript/oxlint (`moduleResolution`
và `baseUrl`); bản tích hợp không sửa cấu hình này. Việc nghiệm thu hiệu quả
phòng thủ mạng cần bằng chứng runtime riêng.

## ElectroShop tích hợp

Target phục vụ frontend và API cùng cổng 18000; Docker tự build Tailwind và
đóng gói font biểu tượng. Chạy backend trực tiếp ngoài Docker cần build client trước:

```bash
npm ci --ignore-scripts --prefix target-app/client
npm run build --prefix target-app/client
cd target-app/server
npm run start:dev
```

Mở cổng backend (mặc định 8000). `TARGET_CLIENT_DIR` cho phép đổi thư mục static;
mặc định `../client` tính từ cwd server. Không dùng Live Server riêng cho demo LAN.
Giỏ thuộc phiên trình duyệt, checkout chỉ dùng giỏ phiên đó; JWT xác định chủ đơn.
Test tích hợp tạo đơn sandbox có địa chỉ `Integration verification (synthetic)`
và giữ lại trong lịch sử để đối chiếu. Không xóa dữ liệu demo có sẵn.

## TV2 · Quan sát, bật khiên và reset mạng/HĐH

Chạy từ thư mục gốc sau khi khởi tạo cấu hình lab. `./scripts/integration-lab.sh monitor`
mở bốn khung Tmux trên host Linux để xem service, mẫu Client, mẫu Target và
trạng thái phòng thủ. Dùng Ctrl-b rồi d để rời màn hình. Các khung chỉ đọc số liệu.

| Lệnh của `./scripts/integration-lab.sh` | Tác dụng trong lab |
|---|---|
| `defense-status` | Đọc entry ARP của Client tại Target, rule SYN trong INPUT và chain riêng, sysctl, giới hạn cgroup, UID và giới hạn FD của tiến trình Node. |
| `shields l1` | Compose gán MAC cố định cho Client và truyền cùng MAC vào Target. Target đặt entry ARP permanent và cài bộ lọc SYN theo cổng dịch vụ khi khởi động. |
| `shields l2` | Docker đặt SYN cookies, giới hạn 1 CPU, RAM 512 MiB, 128 PID và nofile 1024 cho cả giới hạn mềm và cứng. Web app chạy với UID www-data, shell nologin; SSH lab dùng tài khoản riêng. |
| `shields both` | Áp dụng cả hai lớp. |
| `shields off` | Trở về cấu hình Compose cơ sở. Các giá trị mặc định của kernel, kể cả SYN cookies, có thể vốn đã bật. |
| `reset-network-os` | Tạo lại riêng Target và Client theo cấu hình cơ sở, đóng tiến trình và phiên kết nối cũ, tạo namespace mạng mới. Cần God-View đang chạy và image đã build. |

Chọn lại một chế độ bằng lệnh `shields` sau khi dùng `up` của Compose cơ sở.
Đổi chế độ có thể tạo lại container và gián đoạn phiên đang mở. SQLite, credentials
và nội dung trong named volumes tồn tại qua reset. Khi dùng L2, thư mục dữ liệu và
các file SQLite hiện có được cấp cho UID dịch vụ để ghi WAL. Reset không hoàn tác
quyền sở hữu trong volume, không reset dữ liệu L7 và không xóa lịch sử của hub.

**Cách đọc số liệu W5.** Lưu `defense-status` trước và sau đổi chế độ. Với L1,
đối chiếu MAC permanent và cả rule chuyển từ INPUT vào chain. Với L2, đối chiếu
giới hạn thực tế của Node trong `/proc` và giá trị cgroup v2. Thông báo khởi động
của một script chỉ xác nhận thao tác đã chạy. Đánh giá hiệu lực cần số đo runtime.

Để kiểm tra cấu hình đang chạy, dùng `./scripts/integration-lab.sh defense-status --expect both`
(hoặc `l1`, `l2`). Trường `checks` ghi từng điều kiện. Lệnh trả mã 1 nếu thiếu
một điều kiện của khiên được chọn. Kiểm tra này chỉ đọc cấu hình và số liệu tại Target.

**Thời gian W6.** Lệnh reset đo từ lúc gửi lệnh Compose đến khi cả hai service
healthy. Nó in thời gian thực tế và `PASS` hoặc `MISSED` cho mục tiêu 3 giây.
Thời gian dựng container và chu kỳ healthcheck được tính vào phép đo. Trong
5 giây khởi động, Docker kiểm tra Target và Client mỗi 500 ms. Sau khi healthy,
chu kỳ thường là 3 giây cho Target và 5 giây cho Client. Cấu hình này cần
Docker Engine 25 trở lên và Compose hỗ trợ `start_interval`. Vẫn cần đo trên
lab để kết luận reset đạt hay vượt 3 giây.

Lưu mẫu bằng `./scripts/integration-lab.sh defense-status > before.json` khi
lab đang ở cấu hình gốc và lấy `after.json` bằng cùng lệnh sau reset. Chạy
`python3 integration/compare_defense.py before.json after.json` để so sánh
rule SYN, ARP permanent phía Target, sysctl, cgroup, UID và giới hạn FD.
`MATCH` (mã 0) chỉ xác nhận các cấu hình đã đo. `MISMATCH` (1) liệt kê
giá trị trước/sau. `INCONCLUSIVE` (2) báo mẫu thiếu hoặc khác cặp IP.
Mẫu cũ thiếu `lab_endpoints` cần lấy lại. PID mới và cache ARP động hết hạn
là bình thường. Thời gian reset được đánh giá riêng.

Để kiểm tra W5/W6 trong project Compose dùng một lần, chạy
`python3 integration/check_shield_cycle.py`. Có thể chọn subnet riêng chưa
dùng bằng `--subnet`. Công cụ chỉ khởi động God-View, Target và Client,
xuất bản cổng trên loopback và dọn project thử sau khi kết thúc. Từng chế độ
L1, L2 và cả hai đều được kiểm tra bên trong Target. Ở chế độ một khiên,
các thiết lập của khiên còn lại phải khớp mẫu gốc. Dòng JSON cuối sau reset
ghi thời gian đến khi hai endpoint healthy và từng sai khác còn lại trên
Target. Mã 0 yêu cầu cả cấu hình khớp lẫn thời gian không quá 3 giây.
