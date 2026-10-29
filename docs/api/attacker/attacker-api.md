# Attacker API v1 — đề xuất tích hợp cho God-View

Base mặc định `http://172.20.0.66:9000`. Mọi `/api/v1/*` dùng
`Authorization: Bearer <ATTACKER_API_TOKEN>` khi token được cấu hình. Bind ngoài
loopback bắt buộc token >=16 ký tự. `/health` và static UI không yêu cầu token.
Chỉ backend God-View giữ token; không nhúng token vào bundle frontend.

| Method/path | Nội dung |
| --- | --- |
| GET `/health` | Liveness của controller, không khẳng định Target sẵn sàng |
| GET `/api/v1/scenarios` | Danh mục và tham số mặc định |
| GET `/api/v1/config` | Cấu hình công khai, trạng thái telemetry; không trả SSH secret |
| GET `/api/v1/preflight` | TCP reachability tới HTTP/SSH và kiểm tra file credential tồn tại; không chứng minh đăng nhập/kết nối ngược |
| POST `/api/v1/runs` | Khởi tạo, trả 202 cùng `run_id`; 409 nếu đang có lần chạy |
| GET `/api/v1/runs` | Tối đa 100 lần gần nhất |
| GET `/api/v1/runs/{run_id}` | Trạng thái, kết quả, lỗi và cleanup_pending |
| POST `/api/v1/runs/{run_id}/stop` | 202 khi STOPPING; 200 nếu đã kết thúc. Gọi lại không tạo tác dụng phụ |
| GET `/api/v1/events?run_id=...` | Event gần đây trong bộ nhớ (500 toàn controller); bản đầy đủ trong JSONL |

Ví dụ POST start:

```json
{"scenario":"S2","parameters":{"pps":50,"duration_sec":5}}
```

S1/S4: parameters `{}`. S3: `{"max_fds":128,"hold_sec":3}`.
Không nhận target tùy ý, đường dẫn script, credential hoặc shell command từ API.
Target được cấu hình lúc khởi động. Trường lạ/kiểu sai/ngoài giới hạn trả 400.
Unauthorized: 401; run không tồn tại: 404; lỗi nội bộ: 500.

## Vòng đời và kết quả

`STARTING -> RUNNING -> COMPLETED`; dừng: `STOPPING -> STOPPED`;
lỗi/deadline: `FAILED`. Có thể FAILED ngay từ STARTING.
`COMPLETED` chỉ có nghĩa worker đã thực hiện quy trình và xuất kết quả hợp lệ.
`result.outcome`: `OBSERVED`, `BLOCKED` (có bằng chứng từ chối), `INCONCLUSIVE`.
Không dùng trạng thái COMPLETED làm kết luận vượt qua phòng thủ.

`cleanup_pending` độc lập với state. STOPPED xác nhận worker local đã thoát;
cleanup_pending=true nghĩa cleanup remote chưa được xác nhận. Watchdog tổng
45 giây và grace stop 5 giây. Mất God-View không ngăn thời hạn/dừng worker.
Không tự retry POST start khi mất response: đọc danh sách runs để tránh chạy lặp.

## Telemetry push

Default POST `http://172.20.0.99:8080/api/events/attack`; cấu hình bằng
`GODVIEW_TELEMETRY_URL`. Schema: `shared/schemas/attacker-event.schema.json`.
Đây là **đề xuất cần Nguyên chốt**, không khẳng định God-View hiện đã hỗ trợ.

```json
{
  "schema_version":"1.0",
  "event_id":"8ce23061-e0e9-43cc-a73a-d220565f6a56",
  "run_id":"ab7eb340-9d2b-49f0-a823-d5294cad7bc5",
  "timestamp":"2026-10-29T09:00:00.000Z",
  "source_node":"ATTACKER",
  "source_ip":"172.20.0.66",
  "target_ip":"172.20.0.20",
  "scenario":"S2",
  "event_type":"RUN_STATE",
  "execution_mode":"real",
  "payload":{"state":"RUNNING"}
}
```

WORKER_EVENT payload dùng `run_id`, `type` (ready/progress/result/error), stage,
measurements hoặc result tương ứng. Thay đổi state gửi ngay khi outbox được xử lý;
progress S2 tối đa khoảng một lần/giây. Bộ gửi kiểm tra outbox mỗi 2 giây, timeout
1.5 giây/request, retry cùng event_id; consumer phải loại trùng và dựa vào timestamp.
Không đồng nhất thời điểm nhận với thời điểm xảy ra. JSONL là nguồn phục hồi.

God-View ghép run_id với quan sát độc lập của Target và Client. Attacker không
tự sinh SYN_RECV/firewall drop/CPU/FD của dịch vụ khác. Schema cho Target/Client
và lệnh bắt đầu cửa sổ đo thuộc thỏa thuận tiếp theo giữa ba thành viên.

UI attacker không điều khiển phòng thủ. Ba nhóm phòng thủ cần endpoint phía
Target và trạng thái đã xác minh; God-View quản lý luồng điều khiển đó.
