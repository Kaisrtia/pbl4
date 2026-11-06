# Demo hai máy qua Wi-Fi hotspot điện thoại

Nhánh sử dụng: **`feature/integration-lab`**. Không dùng `develop` trước khi PR
tích hợp được merge. Hướng dẫn này dành cho máy A chạy Linux/Docker Engine;
máy B có thể dùng Windows, macOS hoặc Linux và chỉ cần trình duyệt.

## 1. Phân vai và chuẩn bị

| Thiết bị | Vai trò |
|---|---|
| Điện thoại | Phát Wi-Fi hotspot có mật khẩu cho hai máy |
| Máy A — máy chủ lab | Chạy Docker: Client, Target, Attacker, God-View |
| Máy B — máy trình diễn | Mở God-View, Attacker Lab và Swagger của máy A |

Hai máy vật lý chia sẻ giao diện qua Wi-Fi. Các node tấn công/mục tiêu vẫn nằm
trong mạng Docker trên A, không chia Attacker sang B. Không đổi IP mục tiêu
Attacker sang địa chỉ điện thoại hoặc máy B.

Trên A cần Git, Docker Engine + Compose v2 có `--wait`, Python 3 và Node.js
>=22 cho script kiểm chứng. Kiểm tra:

```bash
git --version
docker version
docker compose version
python3 --version
node --version
```

Lần build đầu cần Internet để tải image và dependencies; nên build trước buổi
demo. Máy B không cần cài Node, Docker hoặc clone repo. Dùng hotspot riêng của
nhóm, chỉ kết nối những máy tham gia demo; API God-View/Target hiện chưa có
đăng nhập quản trị, Attacker có API token.

## 2. Kết nối hai máy vào cùng hotspot

1. Bật điểm truy cập cá nhân trên điện thoại và đặt mật khẩu.
2. Kết nối **cả A và B** vào đúng tên Wi-Fi đó.
3. Tạm tránh VPN thay đổi đường đi mạng trong lúc demo; giữ điện thoại và A
   không ngủ/tắt hotspot.
4. Trên A, tìm IPv4 của card Wi-Fi:

```bash
ip -4 -brief address
ip route
```

Ví dụ trên máy kiểm thử: card `wlo1` có `172.20.10.2/28`, gateway điện thoại
`172.20.10.1`. Khi đó **IP máy A là `172.20.10.2`**, không phải gateway.
Địa chỉ có thể thay đổi mỗi lần kết nối; luôn thay ví dụ trong hướng dẫn bằng
IP thực tế của A. Không lấy IP `docker0`, `br-*`, `127.0.0.1`, hoặc dải Docker
`172.30.44.*` để nhập trên B.

## 3. Lấy đúng code trên máy A

Nếu chưa có repo, clone vào thư mục mới:

```bash
git clone --branch feature/integration-lab --single-branch https://github.com/Kaisrtia/pbl4.git pbl4-demo
cd pbl4-demo
```

Nếu đã có repo và không có thay đổi chưa commit:

```bash
git status --short
git fetch origin
git switch feature/integration-lab
git pull --ff-only origin feature/integration-lab
```

Nếu repo hiện tại có công việc dở dang, dùng cách clone sang `pbl4-demo` để
không ảnh hưởng. Trên cùng một máy chỉ chạy một project `pbl4-integration`.

## 4. Khởi tạo cấu hình và mở đúng địa chỉ Wi-Fi

Chạy tại thư mục gốc repo trên A:

```bash
./scripts/integration-lab.sh init
./scripts/integration-lab.sh lan 172.20.10.2
./scripts/integration-lab.sh up
./scripts/integration-lab.sh status
./scripts/integration-lab.sh urls
```

Thay `172.20.10.2` bằng IP A ở bước 2. Lệnh `lan` kiểm tra IP riêng hợp lệ và
có thể bind trên máy, sau đó ghi `LAB_BIND_IP` vào `integration/.env.local`.
Nó không đổi IP nội bộ các container. `up` áp dụng cấu hình và chờ đủ bốn node
healthy. Nếu chỉ chạy `lan` mà không chạy lại `up`, các cổng chưa đổi.

Kết quả mong đợi của `status`: `godview`, `target`, `attacker`, `client` đều
`healthy`. `urls` in ra ba địa chỉ, ví dụ:

```text
God-View: http://172.20.10.2:14000
Attacker: http://172.20.10.2:19090
Target Swagger: http://172.20.10.2:18000/api/docs
```

Sau khi bind vào IP Wi-Fi, dùng các URL này **trên cả A và B**; URL localhost
cũ không còn là địa chỉ được publish. Không đổi thành HTTPS vì lab dùng HTTP.

## 5. Kiểm tra trước khi trình diễn

Trên A:

```bash
./scripts/integration-lab.sh test
```

Script chạy luồng Client → Target → God-View, kiểm tra L3 và S1–S4 với tham số
nhỏ. Cuối log phải có `PASS: integration lab`. Đợi script kết thúc trước khi
bấm chạy thủ công trên B; controller chỉ cho một run hoạt động tại một thời điểm.

Trên B mở trình duyệt và thử lần lượt:

```text
http://172.20.10.2:14000/api/health
http://172.20.10.2:18000/api/system/health
http://172.20.10.2:19090/health
```

Cả ba phải trả JSON thành công. Sau đó mở ba tab giao diện từ lệnh `urls`.
God-View phải hiện `CONNECTED :14000`; bảng HTTP có
`/api/system/ping?echo=integration-client`, IP Client `172.30.44.10`.

Nếu trang health trên A chạy nhưng B không mở được, xem mục 9 trước khi demo.
Chỉ thử thành công từ A chưa đủ xác nhận hotspot cho phép hai máy kết nối.

## 6. Kết nối Attacker trên máy B

1. Người dùng A lấy **riêng giá trị** `LAB_ATTACKER_TOKEN` từ
   `integration/.env.local`. Có thể xem bằng lệnh sau trong terminal riêng:

   ```bash
   sed -n 's/^LAB_ATTACKER_TOKEN=//p' integration/.env.local
   ```

2. Nhập giá trị đó vào ô **API token** trên Attacker Lab của B. Không nhập tiền
   tố `LAB_ATTACKER_TOKEN=` hoặc `Bearer`. Không đưa token vào GitHub/tài liệu.
3. Bấm **Kết nối**. Mong đợi: `Đã kết nối · Real workers`.
4. Bấm **Kiểm tra kết nối Target**. Các trường
   `target_ssh_reachable`, `target_http_reachable`, `known_hosts_present`,
   `credential_present` phải là `true`.
5. Header của Attacker phải chỉ Target nội bộ `172.30.44.20` (hoặc IP đã cấu hình
   cho lab), không phải IP hotspot của A.

Token chỉ nằm trong bộ nhớ trang; reload Attacker cần nhập lại. Nếu B chỉ quan
sát, người A có thể điều khiển Attacker trên trình duyệt A; B không cần token.

## 7. Kịch bản trình diễn khoảng 10–15 phút

### 7.1. Luồng bình thường — 1 phút

- Mở God-View trên B, chỉ log ping thật từ Client đến Target.
- Giải thích IP bốn node là IP Docker; B là máy quan sát/điều khiển qua Wi-Fi.
- Không dùng nút Quick Demo làm bằng chứng request thật: chúng được ghi rõ
  `SYNTHETIC LOGS · NO TARGET REQUEST`.

### 7.2. S4: truyền tệp mẫu — 2 phút

1. Trong Attacker chọn **S4 · Truyền tệp mẫu**, bấm **Chạy kịch bản**.
2. Đợi trạng thái `COMPLETED`, xem `cleanup_pending: false`.
3. Mở God-View, xuống **ATTACKER · REAL RUN EVENTS**, chọn dòng S4 COMPLETED
   có cùng `run_id`.
4. Chỉ `result.outcome: OBSERVED`, `measurements.bytes` và SHA-256 trùng với
   `receiver_receipt.sha256`. Đây là tệp mẫu tổng hợp trong sandbox.

### 7.3. S1 và S3: thao tác trong sandbox — 2–3 phút

- Chọn **S1 · Chuỗi SSH lab**, chạy và chờ COMPLETED. Đây là SSH hợp lệ và thao
  tác tệp lab; không giới thiệu là đã cài backdoor hay khai thác reverse shell.
- Chọn **S3 · Giới hạn file descriptor**, đặt `max_fds=32`, `hold_sec=1`.
  Chạy, xem số FD mở thật và trạng thái cleanup. Đây là tiến trình Python riêng,
  không chứng minh Web App đã hết FD hoặc bị sập.
- Mỗi lần chỉ một run; đối chiếu cùng `run_id` giữa hai giao diện.

### 7.4. S2: SYN có giới hạn — 1 phút

- Chọn **S2 · SYN có giới hạn**, đặt `pps=5`, `duration_sec=1`.
- Chạy và xem `send_calls_succeeded > 0`, sự kiện S2 đến God-View.
- Chỉ kết luận worker đã gửi SYN; số gửi không chứng minh Target nhận đủ,
  backlog tràn hoặc phòng thủ mạng có tác dụng. TCP meter trên UI còn SIMULATED.

### 7.5. Khiên L3 trên Target thật — 3 phút

1. Trên God-View, nếu khiên ACTIVE thì bấm **DISABLE L3 DEFENSE** để đưa về
   BYPASSED. Nếu UNKNOWN, bấm **CHECK TARGET STATE** và xử lý kết nối trước.
2. Mở tab Swagger `http://172.20.10.2:18000/api/docs`.
3. Trong nhóm **Authentication**, mở `POST /api/auth/login`, bấm **Try it out**.
   Nhập JSON mẫu của bài thử nghiệm và bấm **Execute**:

   ```json
   { "username": "admin' --", "password": "demo-only" }
   ```

4. Khi L3 tắt: mong đợi HTTP **200**, `sqli_bypassed: true`.
5. Quay lại God-View, bấm **ENABLE L3 DEFENSE**, chờ ACTIVE.
6. Trở lại Swagger, gửi đúng JSON trên lần nữa: mong đợi HTTP **401**.
7. Đối chiếu HTTP log `/api/auth/login` và mã 200/401 trên God-View. Không đưa
   JWT/token trong response lên ảnh báo cáo công khai. Nếu bấm liên tục gây 429,
   đợi hơn 5 giây rồi gửi lại một lần.
8. Có thể mở `GET /api/defense/status` trong Swagger để đối chiếu
   `flags.l3_master` với UI. Thiếu `defense_action` trong log thì UI ghi `unknown`;
   dùng response và trạng thái Target làm bằng chứng.

L3 bảo vệ ứng dụng HTTP, không phải cơ chế chặn SSH/SYN/FD của S1–S4.

## 8. Kết thúc và khởi chạy lại

- Đợi run kết thúc hoặc bấm **Yêu cầu dừng**, chờ STOPPED và kiểm tra cleanup.
- Trên A chạy `./scripts/integration-lab.sh down` để đóng lab. Lệnh này giữ dữ
  liệu trong named volumes; không ảnh hưởng project Docker khác.
- Muốn chuyển về demo chỉ trên A:

  ```bash
  ./scripts/integration-lab.sh local
  ./scripts/integration-lab.sh up
  ./scripts/integration-lab.sh urls
  ```

- Lần sau đổi hotspot hoặc nhận IP mới: chạy lại `lan <IP mới>` rồi `up`.
  Không cần tạo lại token nếu vẫn dùng file cấu hình cũ.
- `RESET STATE` trên God-View chỉ xóa buffer hiển thị, không reset SQLite,
  firewall, worker hay toàn lab. Restart God-View làm mất lịch sử RAM; journal
  Attacker vẫn còn.

## 9. Xử lý sự cố

| Triệu chứng | Cách kiểm tra/xử lý |
|---|---|
| B mở localhost nhưng không thấy | Localhost trên B là chính B; dùng IP Wi-Fi của A từ `urls` |
| `Cannot use LAN address` | Kiểm tra lại IPv4 Wi-Fi trên A; không nhập IP B/gateway; Wi-Fi phải còn kết nối |
| A mở được nhưng B timeout | Cùng SSID, đúng IP/HTTP, A không sleep; xem firewall và tính năng cách ly thiết bị của hotspot |
| Điện thoại cách ly các thiết bị | Nếu có tùy chọn AP/client isolation, kiểm tra cấu hình hotspot; nếu không cho phép kết nối giữa client thì đổi điện thoại hoặc dùng router chung. Không cần port-forward Internet |
| Cổng bị chiếm | Sửa `LAB_GODVIEW_PORT`, `LAB_TARGET_PORT`, `LAB_ATTACKER_PORT` trong file local, chạy lại `up`, lấy URL mới |
| Docker báo subnet overlap | Đổi `LAB_SUBNET` và cả bốn `LAB_*_IP` sang subnet trống, `down` rồi `up`; không xóa mạng lab khác |
| Attacker báo 401 | Nhập token đúng của A, không dùng token tự tạo trên B; reload cần nhập lại |
| Target không healthy | Chạy `./scripts/integration-lab.sh logs`, kiểm tra lỗi build/SQLite/OpenSSH |
| God-View báo UNKNOWN/502 | Kiểm tra Target healthy; không coi UNKNOWN là khiên đã bật hoặc tắt |
| Attacker hoàn tất nhưng chưa hiện ở God-View | Xem `Telemetry đang chờ`, chờ chu kỳ retry khoảng 2 giây; kiểm tra God-View/logs |
| Lỗi port bind sau khi đổi Wi-Fi | Lấy IP mới, chạy `lan <IP mới>` và `up` |

Trên B Windows có thể kiểm tra TCP bằng PowerShell:

```powershell
Test-NetConnection 172.20.10.2 -Port 14000
Test-NetConnection 172.20.10.2 -Port 19090
Test-NetConnection 172.20.10.2 -Port 18000
```

Trên A Linux, kiểm tra `./scripts/integration-lab.sh status` và
`ss -ltn | rg '14000|18000|19090'`. Nếu máy có firewall, quản trị viên chỉ cần
cho phép ba cổng TCP này từ IP máy B trên mạng hotspot; không tắt toàn bộ firewall.
Không thay đổi firewall máy một cách tự động trong các script lab.

## 10. Phạm vi đã kiểm chứng

Bản tích hợp đã build, chạy đủ bốn node và kiểm tra S1–S4, đồng bộ L3, HTTP
telemetry và Socket.IO. Chế độ LAN được kiểm tra qua địa chỉ Wi-Fi của máy A.
Kết nối từ **máy B thật qua hotspot của bạn** cần xác nhận ở bước 5; hành vi
cách ly client tùy điện thoại. Chưa có agent kernel/OS, ARP/RST, phòng thủ L1/L2
hoặc demo chia container trên hai host vật lý.
