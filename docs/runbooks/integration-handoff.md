# Gửi Nguyên và Trung review bản tích hợp

Ngày kiểm tra: 06/11/2026. Nhánh local: `feature/integration-lab`, nền `develop`
`9730163` (PR #8, #9). Chưa merge vào nhánh chung.

## Tin nhắn đề xuất gửi nhóm

> Mình đã dựng bản tích hợp bốn node chạy riêng, không đụng bộ lab cũ. Client gọi
> Target thật, God-View nhận log và sự kiện Attacker; S1–S4 đã chạy qua. Đã sửa
> adapter khiên L3 để UI đọc đúng trạng thái Target. Mình gửi source/cấu hình mẫu
> và hướng dẫn chạy để hai bạn review. Mỗi bạn tự chạy `init` sinh cấu hình local,
> không dùng chung token hoặc SSH key.
>
> Nguyên review endpoint `/api/events/attack`, Socket `ATTACK_EVENT`, phần hiển thị
> theo run_id và mapping API khiên. Trung review Docker wrapper Target, SSH sandbox
> và Client ping probe. Trung review thêm frontend cùng origin, danh mục, phiên giỏ
> và checkout chỉ mua đúng giỏ đang hiển thị. Nguyên review poll đồng bộ khiên
> hai chiều với ElectroShop. Worker Attacker giữ nguyên.
> Sau khi hai bạn chạy thử và chốt hợp đồng, mình sẽ đưa thay đổi qua PR để merge.

## Nội dung gửi

- `compose.integration.yaml` và `integration/.env.example`: cấu hình chung.
- [Hướng dẫn chạy và dừng](integration-lab.md).
- [Demo hai máy qua hotspot điện thoại](demo-two-machines-hotspot.md).
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
| Target | 1 unit test + 27 E2E tests đạt, E2E dùng DB riêng |
| God-View | 5 nhóm kiểm tra hợp đồng + test bao ngoài đạt (Node báo 6 tests) |
| Client → Target → God-View | Ping thật và IP Client đúng trong log |
| L3 | Đặt true hai lần vẫn true; false tắt; traversal bị từ chối khi bật |
| S1 | SSH lab thật, hoàn tất, nhận sự kiện tại God-View |
| S2 | 5 SYN/giây trong 1 giây; có lần gửi thành công, nhận sự kiện |
| S3 | Mở 32 FD trong tiến trình riêng, cleanup xác nhận |
| S4 | Truyền mẫu thật, SHA-256 khớp receiver |
| ElectroShop | Build CSS/icon tại Target; lọc danh mục, đăng nhập, checkout, badge 0 và lịch sử đã thử trên browser qua IP Wi-Fi A |
| Giỏ hai phiên | Test xác nhận checkout không gom/xóa giỏ phiên khác cùng tài khoản |
| Đồng bộ khiên | Test Socket.IO nhận thay đổi trực tiếp, offline và phục hồi; browser ElectroShop tự cập nhật không reload |
| Target offline/response sai | Hub trả lỗi, không báo bật/tắt khiên thành công giả |
| Browser | Kết nối Socket.IO, hiển thị run S4 COMPLETED và JSON byte/hash thật; không ghi nhận lỗi console |
| Chế độ LAN | S1–S4 và L3 đạt qua IP Wi-Fi của A; cần thử health từ B để xác nhận hotspot |

## Điều chỉnh kế hoạch sau bàn giao Trung

- Đã đưa ElectroShop + JWT/profile/checkout/order history từ develop vào nhánh demo.
- Hoàn thiện demo ứng dụng trước: lọc danh mục → đăng nhập → giỏ riêng → checkout → lịch sử.
- Demo khiên giữa ElectroShop và God-View đã có đồng bộ tự động; không cần reload thủ công.
- Đã đóng gói CSS/icon trong Target, ảnh có fallback khi hotspot không có Internet.
- Vẫn dùng bốn node trên máy A, máy B là trình duyệt. Chưa xác nhận kết nối vật lý từ B;
  cả nhóm cần chạy bước health trên B trước buổi demo.
- Sau nghiệm thu hai máy, review PR tích hợp vào develop; kế hoạch kernel/OS, L1/L2,
  Client bot đầy đủ và các bài ARP/RST vẫn là công việc tiếp theo, chưa hoàn tất.
- Tài liệu kế hoạch gốc `docs/plan.pdf` giữ nguyên; điều chỉnh triển khai ghi tại đây.

## Phần còn lại

TCP meter vẫn mô phỏng và được dán nhãn rõ. Chưa có agent kernel/OS, bot
login/download đầy đủ, ARP/RST, L1/L2, reset một chạm hoặc bằng chứng backlog
tràn/chặn SYN. Target chưa gửi `defense_action` trong HTTP telemetry thì bảng
hiển thị `unknown`, không suy diễn từ trạng thái khiên hiện tại.
Lỗi lint Target có trước bản tích hợp vẫn cần xử lý riêng.
