# Hợp đồng tích hợp God-View — bản đề xuất v1

## Nguyên cần review

### Attacker → God-View

- `POST /api/events/attack`, JSON theo `shared/schemas/attacker-event.schema.json`.
- Cổng nội bộ **4000**. Compose đặt URL rõ ràng, không phụ thuộc mặc định 8080 cũ
  trong Attacker hoặc `.env.example` ở root.
- Trả 200 khi hợp lệ; 400 khi sai schema hoặc `payload.run_id` không khớp envelope
  của `WORKER_EVENT`. Không chuyển sự kiện Attacker thành HTTP log giả.
- Lưu 300 sự kiện gần nhất trong RAM. Gửi lại `event_id` đang còn trong buffer trả
  `duplicate: true`, không broadcast lại. Đây là dedupe có giới hạn, không phải
  lưu trữ bền vững hoặc bảo đảm exactly-once qua restart.
- `GET /api/events/attack?run_id=<id>` → `{count, capacity, events}`.
- Socket.IO phát `ATTACK_EVENT` chứa nguyên envelope. `INITIAL_STATE` có thêm
  `attack_events`, `nodes`. Các sự kiện HTTP `GOD_VIEW_UPDATE` giữ nguyên.
- UI hiển thị 50 sự kiện Attacker mới nhất, mở từng dòng để xem JSON. Không tự
  kết luận `COMPLETED` có nghĩa là vượt qua phòng thủ; xem `payload.result`
  trong sự kiện và kết quả API run của Attacker.

### Thông báo cho TV1 về sự kiện S5 và S6

Schema sự kiện `1.0` bổ sung `S5` và `S6` vào trường `scenario`. Bản God-View
đang chạy cần nạp schema mới để tiếp nhận hai giá trị này. Các consumer có
danh sách scenario cố định cũng cần cập nhật. Thay đổi này áp dụng cho đường
nhận sự kiện. API khởi chạy của controller hiện hỗ trợ S1–S4.

| Bằng chứng nhận được | Cách đọc trên God-View |
|---|---|
| S5 có số lần gửi repair và `cleanup_pending: true` | Giữ trạng thái chờ xác minh. Việc xác nhận khôi phục cần bản ghi ARP thực tế từ cả client và server trước và sau lần chạy, đối chiếu IP–MAC của peer ở mỗi đầu. Thiếu bản ghi ở một đầu thì kết quả vẫn chưa xác minh. |
| S6 có `matching_client_acks_seen: 0` và `outcome: "INCONCLUSIVE"` | Worker chưa ghi nhận ACK phù hợp trong cửa sổ quan sát. |
| S6 có `outcome: "OBSERVED"` và `rst_send_calls_succeeded` dương | Worker ghi nhận thao tác gửi. Để xác nhận tác động cần bằng chứng reset từ socket phía client trong cùng lần chạy. |

Client trong Compose tích hợp đánh dấu HTTP status của ping bằng
`status_source: "http"`. Khi có exception, probe ghi `status_source: "client"`,
mã 503 cục bộ và lý do thuộc danh sách cố định. `ECONNRESET` ghi nhận lỗi
reset mà runtime trả về. `TIMEOUT`, `SOCKET_ERROR` và `CLIENT_ERROR` để ngỏ
nguyên nhân. Đối chiếu timestamp trong log client với cửa sổ của run.
Probe chỉ có số chu kỳ `iteration`, chưa gắn với `run_id`. Ngay cả khi hai
mốc thời gian khớp, bằng chứng này vẫn chưa xác định nguồn gây reset.

Để kiểm tra cache ở hai đầu, chạy từ thư mục gốc khi lab đang hoạt động.
Lệnh đầu lưu mốc trước thử nghiệm. Lệnh thứ hai đọc lại cả hai cache sau
thử nghiệm và đối chiếu với mốc đã lưu.

```sh
python3 integration/arp_cache.py > /tmp/pbl4-arp-before.json
python3 integration/arp_cache.py --baseline /tmp/pbl4-arp-before.json
```

Công cụ chỉ đọc metadata của Docker và bảng ARP trong hai container.
`BOTH_MATCH_BASELINE` cho biết ở cả hai lần đọc, mỗi peer có ánh xạ hoàn
chỉnh khớp MAC do Docker cung cấp. Kết quả mô tả hai thời điểm lấy mẫu.
Nếu mốc ban đầu hợp lệ và một ánh xạ sau đó sai, kết quả là `MISMATCH`.
Thiếu bằng chứng để đối chiếu cho kết quả `INCONCLUSIVE`. Công cụ xuất
JSON riêng để lưu cùng hồ sơ run. Cờ `cleanup_pending` trong sự kiện gốc
vẫn ghi nhận đánh giá của worker.

### Trạng thái khiên L3

Target là nguồn xác nhận trạng thái. God-View giữ API phía frontend:

| Lệnh God-View | Lệnh chuyển đến Target | Trường đọc |
|---|---|---|
| `GET /api/defense/status` | `GET /api/defense/status` | `flags.l3_master` |
| `POST /api/defense/toggle {}` | `POST /api/defense/toggle {}` | `current_state.l3_master` |
| `POST /api/defense/toggle {"enabled":true/false}` | `POST /api/defense/set` với cả bốn cờ cùng giá trị | `current_state.l3_master` |

Response God-View giữ `defense_l3_app` và `proxied_to_target`. Khi Target lỗi,
timeout hoặc trả payload sai: HTTP 502, trạng thái `null`, UI hiện UNKNOWN;
không đảo trạng thái local thay Target. Socket `TOGGLE_DEFENSE` dùng cùng cơ chế
và gửi `DEFENSE_ERROR` cho bên gọi khi không xác nhận được. UI dùng explicit set,
không tự retry toggle qua socket để tránh đảo hai lần.

God-View đọc Target khi browser kết nối, gọi GET status và tự poll mỗi 1 giây.
Thay đổi trực tiếp qua ElectroShop/Swagger được phát `DEFENSE_TOGGLED` đến
các dashboard đang kết nối; lỗi Target chuyển state về null. Các request đọc/ghi
được xếp hàng để tránh poll chậm ghi đè toggle mới. ElectroShop đọc toàn bộ cờ
mỗi 2 giây; dashboard God-View chỉ hiển thị master, chưa hiển thị từng cờ con.

### Phần vẫn là demo

TCP metrics có `source: "simulated"` và UI ghi rõ SIMULATED. Quick Demo ghi
`metadata.synthetic=true`, `metadata.source="demo"` và tiền tố `[DEMO]` ở endpoint.
Agent ARP/TCP/CPU/RAM/FD/process và schema snapshot cần Minh Trí + Nguyên chốt
ở W2-T2; không coi số meter hiện tại là số đo kernel.

## Trung cần review

- Giữ API Target hiện tại; xem bảng mapping khiên ở trên.
- Image tích hợp dùng Node.js 26, SQLite trong `/data/target.sqlite`, public files
  giữ trong image. `GODVIEW_TELEMETRY_URL=http://godview:4000/api/telemetry`.
- Docker wrapper thêm OpenSSH/Python và user `lab`, key-only, cấm root SSH.
- Sandbox `/home/lab/pbl4-lab`, `sample.txt` chỉ chứa dữ liệu tổng hợp; key và
  `known_hosts` tự sinh trong volume dùng riêng cho lab. S1/S3/S4 không cần sửa
  logic backend hoặc mở command-injection endpoint.
- Client probe gọi `/api/system/ping?echo=integration-client` mỗi 3 giây, lưu
  latency đo phía Client. Trung có thể thay bằng bot login/download theo W3-T3
  sau khi thống nhất tần suất và tài khoản test.
- L3 chỉ bảo vệ endpoint ứng dụng. Không coi khiên L3 là cơ chế chặn SSH/SYN/FD;
  phòng thủ mạng/OS sẽ là phần bổ sung riêng của Minh Trí.

## Những điểm cần cả nhóm xác nhận trước khi merge

1. Dùng endpoint Attacker riêng và buffer/Socket event như trên.
2. Giữ API Target làm chuẩn, sửa adapter God-View để tương thích.
3. Chọn subnet theo máy; IP hậu tố cố định, host port và container port tách biệt.
4. Review phạm vi Docker SSH sandbox và cách thay Client probe bằng bot đầy đủ.

Hướng dẫn chạy: [integration-lab.md](../../runbooks/integration-lab.md).
