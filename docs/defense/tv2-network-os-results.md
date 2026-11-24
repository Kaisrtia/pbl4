# Báo cáo kỹ thuật TV2 · Mạng và hệ điều hành

## Nguồn số liệu

Agent W2 đọc bảng ARP và trạng thái socket trong namespace mạng của mỗi
container. PID, quan hệ cha–con, số FD và giới hạn mềm được lấy từ procfs.
CPU là chênh lệch thời gian sử dụng giữa hai mẫu của cùng cgroup; RAM là
`memory.current` của container. Số FD lớn nhất của một PID phải được đối chiếu
với giới hạn của chính PID đó. Tổng FD toàn namespace trả lời một câu hỏi khác.

Ngày 24/11/2026, Client và Target đều gửi được ít nhất hai mẫu liên tiếp tới
God-View trong Docker lab. Hub dùng trạng thái hiển thị chung, nên khi so sánh
hai node cần dùng timestamp và mẫu đã được HTTP 200 ở từng đầu.
[Biên bản W2](../runbooks/integration-lab.md#biên-bản-nghiệm-thu-docker-ngày-24112026)

## Cơ chế phòng thủ

L1 ghim ánh xạ IP–MAC của Client trên Target bằng đúng MAC cấu hình cho Docker
endpoint. Phạm vi bảo vệ là cache phía Target. Rule INPUT chuyển SYN mới của
cổng HTTP vào chain có giới hạn tốc độ. Bộ đếm của rule, số SYN_RECV và khả năng
phục vụ HTTP là ba phép đo riêng. Việc thấy rule chưa đủ chứng minh tải đã bị chặn.

L2 áp giới hạn cgroup cho cả Target, gồm cả app, SSH và telemetry agent. Giới
hạn FD áp theo tiến trình; đạt giới hạn của một PID không đồng nghĩa toàn bộ
kernel hết FD. App dùng tài khoản dịch vụ UID khác root và shell nologin. Shell
nologin giới hạn đường đăng nhập thông thường; quyền truy cập file và khả năng
chạy tiến trình vẫn do UID, quyền filesystem và các giới hạn kernel quyết định.

## Tiến độ theo bằng chứng

| Tuần | Bằng chứng hiện có | Giới hạn kết luận |
|---|---|---|
| W1 | Compose LAN và lệnh quan sát bốn khung Tmux. | Chưa có biên bản demo đầy đủ ba kịch bản mạng. |
| W2 | Hai agent đã chạy trong lab và God-View trả HTTP 200 cho cả hai. | Hub chưa lưu lịch sử kernel tách biệt theo node. |
| W3 | S2 có biên bản gửi và nhận sự kiện; schema S5/S6 đã được tích hợp. | Chưa có bằng chứng backlog đầy hoặc phiên TCP bị ngắt bởi worker. |
| W4 | Biên bản S3 ghi nhận một tiến trình mở 32 FD và cleanup. S1 có kết quả SSH. Test procfs trên Linux xác nhận PID con, UID, tăng đúng 8 FD và PID biến mất sau khi thoát. | Các phép đo này chỉ bao phủ một phần đầu ra OS. |
| W5 | Hai lượt Docker độc lập đi từ cấu hình gốc qua L1, L2 và cả hai. Mỗi lượt đạt 4/4, 6/6 và 10/10 phép kiểm tra tương ứng. | Đã đo cấu hình có hiệu lực trên Target. Hiệu quả dưới tải chưa được đo. |
| W6 | Ba lượt sau khi sửa client-bot đạt 2,695 s, 2,735 s và 2,703 s. Mỗi lượt Client và Target đều healthy và các mục cấu hình Target khớp baseline. | Kết quả đo trên máy lab này với image đã build. |

[Biên bản S1–S4](../runbooks/integration-handoff.md#kết-quả-đã-kiểm-chứng) ·
[Thao tác khiên và reset](../runbooks/integration-lab.md#tv2--quan-sát-bật-khiên-và-reset-mạnghđh)

## Phép đo W5/W6 ngày 24/11/2026

Chạy `python3 integration/check_shield_cycle.py` trên Docker Engine 29.10.0,
Compose 5.8.0, mỗi lượt dùng project và volume tạm riêng. Baseline được lấy
trước khi bật khiên. Với L2, Node 26 ban đầu có giới hạn FD thực tế 2048/2048
khi Compose đặt 1024/2048. Đặt cả hai giới hạn ở 1024 cho kết quả 1024/1024
qua procfs. Mẫu L1 xác nhận ARP permanent đúng MAC Client trên Target và các
rule SYN. Phép so sau reset bao gồm cả UID và giới hạn FD.

Trong lượt 4,233 s, sự kiện Docker cho thấy riêng giai đoạn từ tín hiệu dừng
đến khi Client dừng mất khoảng 1,59 s. Client-bot nay hủy request hoặc timer đang chờ khi nhận
SIGTERM/SIGINT. Hai lượt trước thay đổi mất 4,233 s và 4,211 s. Sau thay đổi,
ba lượt liên tiếp đạt mốc 3 giây. Cả ba lượt cũng đạt đủ 4 phép kiểm L1,
6 phép kiểm L2 và 10 phép kiểm khi bật đồng thời hai lớp.
