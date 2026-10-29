# Phạm vi TV2: S1–S4 trên Docker bốn node

Giữ cách triển khai/phân công của repo mới nhưng dùng bốn kịch bản đã chọn:
SSH lab, raw SYN có giới hạn, FD probe trên Target, truyền tệp mẫu.
Không tự thêm ARP MITM/TCP RST chỉ vì tài liệu kiến trúc tổng quan liệt kê chúng.

Mã nguồn, giới hạn, lệnh chạy và kiểm thử nằm tại [attacker/README.md](../../attacker/README.md).
API cho God-View: [attacker-api.md](../api/attacker/attacker-api.md).
Điều kiện bàn giao Target: [target-contract.md](../api/attacker/target-contract.md).

## Tái sử dụng từ ZIP

Giữ ý tưởng worker SYN/FD, bộ nhận hash, CLI/UI và đo theo từng phiên. Controller,
worker protocol, nhận kết quả và UI integration được xây lại vì bản ZIP trộn
số liệu mock với quan sát thật và stop chưa quản lý tiến trình thực thi.
Không sao chép logic giả lập firewall/drop, suy số gói khi worker lỗi, hoặc UI
tự dựng kết quả. Fixture dùng OpenSSH/permission/FD thật nằm trong tests của
attacker; không ghi đè code của hai thành viên còn lại.

## Hai mức xác nhận

1. Kiểm thử attacker: chạy/dừng, lỗi, protocol, SSH, FD, truyền mẫu, raw send,
   telemetry; thực hiện được bằng fixture riêng.
2. Nghiệm thu toàn hệ thống: cần Target/Client thật của nhóm, cấu hình phòng thủ
   đã xác minh và God-View ghép evidence theo run_id. Test fixture không thay thế
   việc chứng minh hiệu quả phòng thủ hoặc các yêu cầu học thuật chưa triển khai.
