# Báo cáo kỹ thuật TV2 · Mạng và hệ điều hành

**Minh Trí · TV2 · PBL4 · 24/11/2026**

Câu hỏi thực nghiệm là liệu trạng thái của mạng và hệ điều hành có quan sát
được từ hai đầu kết nối, và sau khi bật khiên có thể trở lại cấu hình gốc
trong 3 giây hay không. Phần đo dùng Linux, Docker Engine 29.10.0 và Compose
5.8.0. Lượt kiểm tra cuối đạt **2,710 giây** tính đến khi Client và Target
đều healthy. Sau đó, các mục cấu hình Target được so sánh đều khớp mẫu ban đầu.

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
| W1 | Đã chạy LAN và bốn khung Tmux, đối chiếu MAC ở cả hai đầu và ghi số liệu nền TCP. [Biên bản W1](../runbooks/integration-lab.md#w1-t2--demo-quan-sát-mạng-trên-bốn-khung-terminal) | Chưa có biên bản demo đầy đủ ba kịch bản mạng. |
| W2 | Hai agent đã chạy trong lab và God-View trả HTTP 200 cho cả hai. | Hub chưa lưu lịch sử kernel tách biệt theo node. |
| W3 | S2 có biên bản gửi và nhận sự kiện. God-View đã phát và lưu đúng sự kiện mẫu S5/S6 qua Socket.IO. | Catalog trên nhánh này chỉ đăng ký S1–S4. Chưa có lượt chạy S5/S6 từ controller. |
| W4 | Biên bản S3 ghi nhận một tiến trình mở 32 FD và cleanup. S1 có kết quả SSH. Test procfs trên Linux xác nhận PID con, UID, tăng đúng 8 FD và PID biến mất sau khi thoát. | Đã kiểm tra quyền file của UID 33 trên fixture Docker. Chưa có bằng chứng reverse shell hoặc cạn tài nguyên hệ thống. |
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


## Quyền truy cập tệp và vòng đời FD

Trong project Docker tạm, khi hai khiên đang bật, bộ kiểm tra tạo hai tệp
cùng chứa bốn byte dữ liệu mẫu. Cả hai do root sở hữu. Tiến trình kiểm tra
chạy với UID 33 (www-data), cùng UID đã quan sát trên tiến trình Node của
Target. Thư mục cha cho phép đi qua, nên khác biệt quyền đọc nằm ở mode của tệp.

| Phép đo trong Target | Kết quả ngày 24/11/2026 |
|---|---|
| Đọc tệp mode 0644 | Đọc đúng bốn byte mẫu |
| Đọc tệp mode 0600 | Kernel trả PermissionError |
| Giữ đồng thời tám lượt mở tệp | Số FD của chính tiến trình tăng 8 |
| Đóng các tệp rồi đếm lại | Chênh lệch so với ban đầu bằng 0 |

Ở lớp mạng, test hợp đồng dùng sự kiện mẫu S5 có cleanup đang chờ, S6 thiếu
bằng chứng và S6 đã ghi nhận thao tác gửi. God-View giữ các trường bằng chứng
qua phát trực tiếp và lịch sử. Bài kiểm này đo đường truyền dữ liệu của hub.
Việc kết luận khôi phục ARP cần đọc cache ở cả hai đầu. Với TCP, bộ đếm RST
có thể tăng ngay trong lưu lượng nền. Xác nhận một phiên bị ngắt cần bằng
chứng tại endpoint cho chính phiên đó.

## Trình tự trình bày trước hội đồng

| Thời gian | Thao tác và câu hỏi cần trả lời |
|---|---|
| Phút 0–1 | Giới thiệu Client, Target và God-View trên LAN Docker. Giải thích vì sao hai đầu phải tự gửi mẫu kernel. |
| Phút 1–2 | Mở bốn khung Tmux bằng `./scripts/integration-lab.sh monitor` khi lab đang chạy. Chỉ vị trí IP, MAC peer, timestamp và số socket SYN_RECV ở từng đầu. |
| Phút 2–4 | Chạy `python3 integration/check_shield_cycle.py` từ thư mục gốc với Docker đang chạy và subnet 172.30.214.0/24 còn trống. Khi image đã build, dùng thời gian khởi động để giải thích sự khác nhau giữa một rule đã cài và hiệu lực dưới tải. |
| Phút 4–5 | Chỉ kết quả UID, quyền đọc file và FD. Giải thích vì sao cùng UID vẫn có kết quả khác nhau với hai mode tệp. |
| Phút 5–6 | Đọc `reset_seconds`, `deadline_met` và `differences_after_reset` của lượt vừa chạy. Nếu vượt 3 giây, ghi đúng số đo của lần đó. |

Bài kiểm khiên tự dùng project, volume và cổng loopback riêng. Tmux quan sát
lab chính. Khi trình bày số đo của project tạm, đọc output của lệnh kiểm
tra ở cửa sổ riêng. Nếu máy trình chiếu thiếu Docker, có thể dùng bảng kết quả
đã đo trong báo cáo và ghi rõ đây là lần chạy ngày 24/11/2026.
