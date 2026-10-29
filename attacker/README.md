# Attacker: S1–S4 trong mô hình Docker bốn node

Controller TypeScript, worker Python, CLI và giao diện điều khiển riêng của TV2.
Một lần chạy tại một thời điểm, `run_id` duy nhất, kết quả thực tế và log JSONL.
Không thay đổi `target-system/` hoặc `god-view/` của partner.

## Kịch bản và giới hạn thực tế

| Bài | Thực thi | Kết luận được phép |
| --- | --- | --- |
| S1 | Kết nối SSH thật, một credential cấu hình sẵn, lấy UID/GID, tạo marker trong sandbox, đóng/mở lại SSH, xóa bản sao audit do chính lần chạy tạo | Xác nhận đăng nhập/reconnect và quyền thao tác tệp lab. Bước 4/5 là surrogate có ghi nhãn, **không phải** backdoor, leo quyền hoặc xóa log hệ thống |
| S2 | Scapy gửi raw SYN, tối đa 150 lần gửi/giây trong 15 giây, không giả nguồn | Số lần gửi thành công tại máy attacker. Không suy ra số gói đến Target, SYN_RECV hay hiệu quả phòng thủ. Kernel phía attacker có thể trả RST cho SYN-ACK |
| S3 | Python riêng trên Target qua SSH mở tối đa 256 FD trong 8 giây, dùng RLIMIT được thừa kế | Số FD mở được, soft/hard limit, có gặp EMFILE hay không. Không tự kết luận Web App bị ảnh hưởng hoặc được bảo vệ |
| S4 | Target đọc duy nhất `sample.txt` trong sandbox (1–4096 byte), gửi HTTP ngược về receiver và đối chiếu SHA-256 | Đã nhận đúng mẫu hoặc hệ điều hành từ chối đọc. Lỗi kết nối không tự được quy là firewall chặn |

S3/S4 là phiên riêng với điều kiện đã có credential lab hợp lệ; không giả vờ
kế thừa quyền từ lần S1 trước. Không brute force, không phụ thuộc API host-agent
chưa được partner triển khai. Đọc [hợp đồng Target](../docs/api/attacker/target-contract.md).

## Chạy phát triển

Node.js >=22, Python >=3.11. Từ `attacker/`:

```sh
npm ci
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
# Sửa .env: PYTHON_BIN=.venv/bin/python và cấu hình Target/SSH thực tế.
npm run build
npm start
```

Mở `http://127.0.0.1:9000`. Nhập token nếu đã cấu hình, bấm Kết nối.
UI không tự dựng kết quả khi API lỗi. Không có công tắc giả điều khiển phòng thủ.
Biến môi trường shell có ưu tiên; `attacker/.env` ưu tiên trước `.env` thư mục gốc.
Không commit `.env`, khóa SSH, mật khẩu hoặc thư mục `.data/`.

```sh
npm run cli -- preflight
npm run cli -- start S2 '{"pps":50,"duration_sec":5}'
npm run cli -- list
npm run cli -- status <run_id>
npm run cli -- stop <run_id>
```

## Docker của nhóm

`attacker/compose.yaml` chỉ định nghĩa node attacker, nối mạng ngoài
`DOCKER_NETWORK_NAME` (mặc định `cybersec-net`). Compose của nhóm phải tạo mạng
và ba node còn lại. Các IP/cổng mặc định lấy theo `.env.example` repo mới.
Tên mạng trong tài liệu kiến trúc cũ đang là `isolated-net`; nhóm cần thống nhất,
code dùng biến môi trường chứ không cố định tên đó.

Chuẩn bị thư mục secret chứa private key `id_ed25519`, file `known_hosts`
đã xác minh với Trung. Với SSH password lab, mount thêm file và cấu hình
`LAB_SSH_PASSWORD_FILE`; chỉ thử đúng một credential mỗi lần chạy.

```sh
export ATTACKER_API_TOKEN="$(openssl rand -hex 24)"
export LAB_SECRETS_DIR=/absolute/path/to/lab-secrets
docker compose --env-file .env -f attacker/compose.yaml up --build -d
```

Lệnh trên chạy từ gốc repo, cần có `.env` được chuẩn bị từ mẫu. Backend God-View
gọi controller bằng `http://172.20.0.66:9000` và Bearer token. UI trong trình duyệt
gọi qua backend God-View; controller không mở CORS tùy ý. S4 nhận trên cổng 9001
trong mạng Docker, không cần công bố cổng đó ra host. Worker cần `NET_RAW` cho S2,
không cần `NET_ADMIN` để sửa mạng/host firewall.

## Kiểm thử riêng, không dùng code partner

```sh
cd attacker
npm test
npm run test:python
docker compose -p pbl4-attacker-test -f tests/compose.yaml build
npm run test:integration
```

Fixture dựng **bốn container** trong mạng riêng `172.29.44.0/24`, host port
19000 (controller), 18080 (collector) để không đụng lab nhóm `172.20.0.0/24`.
Target dùng OpenSSH thật, FD limit thật, file permission thật. Client phát
HTTP probe độc lập. Collector chỉ nhận event, không giả làm dashboard hoàn chỉnh.
Token cố định trong Compose test chỉ dành cho fixture. Khóa SSH được tạo trong
Docker volume và xóa khi kết thúc test; không chép sang repo.

Test integration tự dọn container/network/volume có project name riêng.
Đặt `KEEP_LAB=1` để giữ fixture và mở `http://127.0.0.1:19000` kiểm tra giao diện.
Khi xong: `docker compose -p pbl4-attacker-test -f tests/compose.yaml down -v`.

Mock protocol cho test chạy/dừng nằm ở `tests/fixtures/worker.mjs`; không có
mock fallback trong controller sản phẩm. Dữ liệu Target/Client vẫn cần tích hợp
và ghép `run_id` ở God-View của nhóm trước khi dùng làm kết luận đồ án.

## Dữ liệu và khôi phục

`.data/<run_id>.jsonl` lưu sự kiện trước khi gửi; `.run.json` lưu trạng thái cuối.
Outbox retry cùng `event_id`, tối đa 500 event chờ; khi đầy, event cũ vẫn ở JSONL
nhưng bị loại khỏi hàng gửi tự động và bộ đếm drop tăng. God-View cần loại trùng.
Controller restart đánh dấu lần đang chạy là FAILED/cleanup_pending, không tự
chạy lại. Chỉ STARTING/RUNNING/STOPPING là trạng thái hoạt động.

Khi dừng, chờ worker xác nhận cleanup tối đa 5 giây rồi buộc dừng nhóm tiến trình.
Nếu Target mất kết nối, `cleanup_pending=true` và cần đối chiếu sandbox với Trung.
S3 có thời hạn giữ FD độc lập <=8 giây; marker `run-<id>` có thể cần dọn thủ công
sau khi xác nhận tiến trình đã thoát. Không dùng lệnh xóa toàn bộ sandbox.

Chuyển LAN sau này: đổi IP/cổng/known_hosts/đường callback S4. Kiểm thử lại S2
và vị trí đo; không coi số liệu Docker một máy tương đương LAN hai máy.
