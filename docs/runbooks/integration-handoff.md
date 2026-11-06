# Gửi Nguyên và Trung review bản tích hợp

Ngày kiểm tra: 06/11/2026. Nhánh local: `feature/integration-lab`, nền `develop`
`91d2cbf`. Chưa merge vào nhánh chung.

## Tin nhắn đề xuất gửi nhóm

> Mình đã dựng bản tích hợp bốn node chạy riêng, không đụng bộ lab cũ. Client gọi
> Target thật, God-View nhận log và sự kiện Attacker; S1–S4 đã chạy qua. Đã sửa
> adapter khiên L3 để UI đọc đúng trạng thái Target. Mình gửi source/cấu hình mẫu
> và hướng dẫn chạy để hai bạn review. Mỗi bạn tự chạy `init` sinh cấu hình local,
> không dùng chung token hoặc SSH key.
>
> Nguyên review endpoint `/api/events/attack`, Socket `ATTACK_EVENT`, phần hiển thị
> theo run_id và mapping API khiên. Trung review Docker wrapper Target, SSH sandbox
> và Client ping probe. Mã nghiệp vụ Target và worker Attacker được giữ nguyên.
> Sau khi hai bạn chạy thử và chốt hợp đồng, mình sẽ đưa thay đổi qua PR để merge.

## Nội dung gửi

- `compose.integration.yaml` và `integration/.env.example`: cấu hình chung.
- [Hướng dẫn chạy và dừng](integration-lab.md).
- [Hợp đồng API, phạm vi review cho từng người](../api/god-view/integration-contract.md).
- Toàn bộ source của bản tích hợp hoặc archive `pbl4-integration-review.zip`.

Archive là snapshot source, không kèm `.git`, `.env.local`, credentials,
database, journal runtime, `node_modules` hoặc images Docker. Giải nén vào thư mục
riêng để review, chạy `./scripts/integration-lab.sh init`, rồi `up` và `test`.
Nếu hai bạn đang dùng chung một máy, lab này có project name cố định
`pbl4-integration`: không chạy hai bản tích hợp đồng thời trên cùng Docker daemon.

## Kết quả đã kiểm chứng

| Hạng mục | Kết quả |
|---|---|
| Build Attacker, Target, God-View | Đạt cả local và Docker |
| Attacker | 12 controller/API tests + 3 Python tests đạt |
| Target | 1 unit test + 21 E2E tests đạt, E2E dùng DB riêng |
| God-View | 4 nhóm kiểm tra hợp đồng + test bao ngoài đạt (Node báo 5 tests) |
| Client → Target → God-View | Ping thật và IP Client đúng trong log |
| L3 | Đặt true hai lần vẫn true; false tắt; traversal bị từ chối khi bật |
| S1 | SSH lab thật, hoàn tất, nhận sự kiện tại God-View |
| S2 | 5 SYN/giây trong 1 giây; có lần gửi thành công, nhận sự kiện |
| S3 | Mở 32 FD trong tiến trình riêng, cleanup xác nhận |
| S4 | Truyền mẫu thật, SHA-256 khớp receiver |
| Target offline/response sai | Hub trả lỗi, không báo bật/tắt khiên thành công giả |
| Browser | Kết nối Socket.IO, hiển thị run S4 COMPLETED và JSON byte/hash thật; không ghi nhận lỗi console |

Các run kiểm chứng trên Target tích hợp:

```text
S1 80b591b2-3e9c-41a8-9f80-6e05d4f306a4
S2 b201c4ef-438a-4fb5-8d6f-3efbd192c618
S3 34f2da38-bb9a-4c77-a4fe-d3e113ed1f5b
S4 8dbcedc1-e73f-4b25-bdc1-d39076aa1e3a
S4 kiểm tra UI sau build cuối: 4979832a-c17f-40c4-b99b-3d2045f19fd5
```

## Phần còn lại

TCP meter vẫn mô phỏng và được dán nhãn rõ. Chưa có agent kernel/OS, bot
login/download đầy đủ, ARP/RST, L1/L2, reset một chạm hoặc bằng chứng backlog
tràn/chặn SYN. Target chưa gửi `defense_action` trong HTTP telemetry thì bảng
hiển thị `unknown`, không suy diễn từ trạng thái khiên hiện tại.
Lỗi lint Target có trước bản tích hợp vẫn cần xử lý riêng.
