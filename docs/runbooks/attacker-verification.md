# Kiểm chứng attacker — 29/10/2026

Thực hiện trên nhánh `codex/attacker-docker-scenarios`, lab test riêng,
không sử dụng Target/God-View của partner. Các lệnh tái hiện nằm trong
[attacker README](../../attacker/README.md).

## Phạm vi kiểm chứng

- TypeScript build và kiểm thử controller/API: validation, chống chạy chồng,
  xử lý NDJSON chia chunk, lỗi worker/missing executable, graceful/forced stop,
  watchdog, crash recovery, telemetry offline/retry và API auth.
- Python: cú pháp, request sai, dependency/SSH config thiếu không thành công giả.
- Docker bốn node: S1 SSH thật và reconnect; S2 raw SYN tốc độ thấp; S3 mở FD
  trên Target; S4 gửi mẫu và so hash với receiver.
- Đối chứng thực: chmod tệp mẫu để từ chối đọc, hạ soft RLIMIT của sshd để
  phiên con chạm EMFILE, bỏ authorized_keys lab để từ chối đăng nhập.
- Dừng S3 giữa thời gian giữ FD; xác nhận STOPPED, cleanup_pending=false và
  không còn thư mục run trên Target.
- God-View fixture nhận đúng schema và run_id; Client riêng đo HTTP thật.
- UI được kiểm tra qua trình duyệt: kết nối controller, chạy S4, hiển thị
  COMPLETED/OBSERVED và byte/hash thực nhận, không tự dựng số liệu.

## Chưa được khẳng định bởi các kiểm thử này

- Hiệu quả firewall/SYN Cookies hoặc việc SYN Flood làm dịch vụ chậm/sập.
- Phòng thủ Web App lớp ứng dụng của partner.
- Persistence/backdoor thật hoặc xóa log hệ thống trong S1.
- Tích hợp dashboard God-View hoàn chỉnh của nhóm và demo qua LAN hai máy.

Fixture có credential và network riêng; không dùng credential fixture cho
demo của nhóm. Không cần chạy bằng quyền root trên máy host; quyền mạng raw
chỉ được cấp cho container attacker trong test.
