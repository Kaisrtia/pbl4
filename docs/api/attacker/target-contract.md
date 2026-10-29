# Điều kiện Target cho S1–S4 — cần thống nhất với TV1

Attacker hiện dùng SSH thật, không yêu cầu các endpoint `/lab/s1/*` giả lập của
gói ZIP cũ. Tất cả điều kiện dưới đây là đề xuất tích hợp, chưa là code của TV1.

| Điều kiện | Giá trị mặc định / yêu cầu |
| --- | --- |
| IP / HTTP | `SERVER_IP=172.20.0.20`, `SERVER_PORT=8000` |
| SSH trong container | `TARGET_SSH_PORT=22` (không nhầm với cổng publish host) |
| Tài khoản | `lab`, không root, credential riêng của lab |
| SSH host key | TV1 cung cấp public host key qua kênh nhóm đã tin cậy; lưu known_hosts đúng IP và cổng |
| Xác thực | Public key; có thể dùng một password lab qua file secret cho đối chứng S1, không dò danh sách mật khẩu |
| Sandbox | `/home/lab/pbl4-lab`, directory có thật, user lab có thể tạo thư mục con run-UUID |
| Mẫu S4 | `sample.txt` tại sandbox, file thường không symlink, 1–4096 byte, dữ liệu giả |
| Python trên Target | Python 3.11+, standard library; cho phép chạy Python qua SSH và SFTP |
| Kết nối ngược S4 | Target -> HACKER_IP:9001; receiver phát token dùng riêng cho mỗi run |
| Giới hạn S3 | Cấu hình RLIMIT_NOFILE thực tế của phiên SSH/tiến trình; không bắt worker tự bật phòng thủ |

## Bài thực nghiệm cần phối hợp

- S1: lượt xác thực hợp lệ và lượt bị từ chối. Bước 4 dùng marker để kiểm tra
  reconnect; bước 5 chỉ xóa bản sao audit của run. Không tuyên bố đã kiểm thử
  persistence thật, leo quyền hay xóa log hệ thống. Những nội dung đó cần đặc tả
  riêng nếu giảng viên yêu cầu.
- S2: đối chiếu pcap/bộ đếm Target, SYN_RECV/cookies/drop và độ trễ Client. Số
  lần gửi từ attacker không chứng minh gói đến hoặc backlog đã tràn. Giữ đường
  telemetry hoạt động để phân biệt mất quan sát với dịch vụ bị lỗi.
- S3: lượt limit thấp để thấy EMFILE và lượt limit đủ cao. Python probe là
  tiến trình riêng, không phải Web App; cần Client đo độc lập trước/trong/sau
  nếu muốn kết luận về khả năng phục vụ.
- S4: baseline có quyền đọc và egress; lượt từ chối quyền đọc; lượt chặn đúng
  kênh gửi ra. Timeout được báo lỗi/không kết luận, không tự gán firewall chặn.

## Trách nhiệm dừng/khôi phục

Worker S3 ghi cancel vào `run-UUID/cancel`, chờ `done` xác nhận đóng FD rồi xóa
đúng thư mục run. Nếu mất SSH, worker remote tự hết hold tối đa 8 giây; controller
báo cleanup_pending nếu chưa xác minh. Partner kiểm tra tiến trình và thư mục run
trước khi dọn. Không xóa nguyên sandbox hoặc log host.

S1 không thay authorized_keys, dịch vụ khởi động, quyền tài khoản hoặc log hệ
thống. S4 không lưu dữ liệu nhận trên attacker, chỉ giữ số byte/hash.

Ba lớp phòng thủ do Target áp dụng, God-View điều khiển và xác minh; attacker
không tự đổi firewall/sysctl. Rate limiting Web App không áp dụng cho SSH;
giới hạn FD là RLIMIT_NOFILE, không thay thế bằng một nhãn cgroups.
