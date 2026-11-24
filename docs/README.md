# Hướng Dẫn Cơ Cấu Tài Liệu Dự Án (Documentation Guide)
**Dự án:** PBL4 - Hệ Thống Mô Phỏng & Giám Sát Tấn Công Mạng & Hệ Điều Hành (God-View)  
**Tài liệu tham chiếu:** [docs/plan.pdf](plan.pdf) (Bảng phân công nhiệm vụ chi tiết 6 tuần đã duyệt)

---

## 1. Mục đích của thư mục `docs/`

Thư mục `docs/` là **Single Source of Truth (Chân lý duy nhất)** lưu trữ toàn bộ thông số kỹ thuật (specs), tài liệu thiết kế kiến trúc, kịch bản tấn công - phòng thủ, hướng dẫn thực nghiệm (runbook) và báo cáo học thuật của dự án PBL4.

Mọi thành viên và các **AI Agent** khi thực hiện task bắt buộc phải tra cứu, cập nhật và đồng bộ tài liệu tương ứng tại đây trước khi chỉnh sửa mã nguồn.

---

## 2. Sơ đồ cây thư mục tài liệu

```text
docs/
├── README.md                     # File này: Hướng dẫn cơ cấu và ý nghĩa các thư mục tài liệu
├── plan.pdf                      # Kế hoạch 6 tuần chính thức cập nhật (Master Plan)
├── plan(old).pdf                 # Kế hoạch ban đầu (lưu vết tham chiếu lịch sử)
│
├── architecture/                 # Kiến trúc tổng thể hệ thống & sơ đồ mạng Docker
│   └── system-architecture.md    # Đặc tả 4 container, dải IP tĩnh 172.20.0.0/24 và luồng Telemetry
│
├── api/                          # Đặc tả giao diện lập trình ứng dụng (API Specs)
│   ├── target-server/            # Đặc tả API Web Store & điểm cắm lỗ hổng (target-server-api.md, openapi.json)
│   ├── god-view/                 # Đặc tả API nhận Telemetry & WebSocket stream (god-view-api.md)
│   └── attacker/                 # Đặc tả API điều khiển module tấn công (attacker-api.md, target-contract.md)
│
├── attacks/                      # Chi tiết các kịch bản tấn công (L2, L4, L7, OS) & Kill Chain
│   └── attacker-s1-s4.md         # Danh mục kịch bản S1-S6 (SSH, SYN, FD, Exfil, ARP, RST) & Kill Chain
│
├── defense/                      # Cơ chế phòng thủ 3 lớp (Defense-in-Depth) & Kiểm thử chéo
│   ├── layer1-network-defense.md # Phòng thủ Lớp 1 (Mạng): Static ARP, iptables SYN limit
│   ├── layer2-os-defense.md      # Phòng thủ Lớp 2 (HĐH): tcp_syncookies, ulimit, cgroups, nologin
│   └── layer3-application-defense.md # Phòng thủ Lớp 3 (Ứng dụng): Prepared Statement, Rate Limit, Sanitization
│
├── pcap-analysis/                # Báo cáo phân tích gói tin mạng (Wireshark) & Cơ chế nhân Linux
│   └── .gitkeep                  # Bóc tách cờ TCP (SYN, ACK, RST), ARP reply, giải thích SYN backlog
│
├── runbooks/                     # Hướng dẫn thao tác thực nghiệm & Kịch bản demo trước hội đồng
│   ├── target-server-runbook.md  # Kịch bản demo Target Server & Khiên L3 (26 tests, SQLi, DoS, Traversal, CmdInj)
│   └── attacker-verification.md  # Kịch bản kiểm chứng Attacker Controller & Docker 4-node fixture
│
└── reports/                      # Báo cáo đồ án tổng kết PBL4 & Slide thuyết trình bảo vệ
    ├── bao-cao-chuyen-sau-god-view-ui.md   # Báo cáo chuyên sâu TV1 (God-View SIEM, Canvas 60FPS, 3-Layer Funnel, 1-Touch Reset)
    ├── bao-cao-tv2-mang-va-he-dieu-hanh.pdf # Báo cáo chuyên sâu TV2 (Mạng L2/L4 & Nhân Hệ điều hành)
    ├── bao-cao-chuyen-sau-l7-target-app.md # Báo cáo chuyên sâu TV3 (Kiến trúc Target App & Tấn công/Phòng thủ L7)
    └── slide-outline-va-kich-ban-bao-ve.md # Đề cương 12 Slide thuyết trình, Kịch bản Live Demo Kill Chain & Q&A Phản biện
```

---

## 3. Ý nghĩa chi tiết và phân công trách nhiệm từng thư mục

### 3.1. `docs/architecture/` (Kiến trúc hệ thống)
* **Ý nghĩa:** Tài liệu nền móng của dự án. Quy định sơ đồ mạng Docker 4 container (`isolated-net` subnet `172.20.0.0/24`), IP tĩnh của từng node, cấu hình sysctl nhân Linux và luồng truyền thông điệp JSON Schema giữa các agent.
* **Người phụ trách:** **Hoàng Trung (TV3)** kết hợp với cả nhóm.
* **Tài liệu:** [system-architecture.md](architecture/system-architecture.md).

### 3.2. `docs/api/` (Đặc tả API phân tán)
* **Ý nghĩa:** Chứa tài liệu đặc tả REST API và WebSocket của từng node độc lập:
  - `target-server/`: Mô tả các API người dùng ElectroShop và các điểm cắm lỗ hổng (SQLi, Command Injection, Path Traversal, DoS). **Hoàng Trung (TV3)** phụ trách. [target-server-api.md](api/target-server/target-server-api.md).
  - `god-view/`: Mô tả API nhận Telemetry, kênh phát WebSocket thời gian thực và API điều khiển phòng thủ. **Hạnh Nguyên (TV1)** phụ trách. [god-view-api.md](api/god-view/god-view-api.md).
  - `attacker/`: Mô tả API điều khiển module tấn công (start, stop, status). **Minh Trí (TV2)** phụ trách. [attacker-api.md](api/attacker/attacker-api.md).

### 3.3. `docs/attacks/` (Kịch bản tấn công)
* **Ý nghĩa:** Lưu trữ toàn bộ tài liệu nghiên cứu và hướng dẫn thực thi các đòn tấn công mạng và hệ điều hành:
  - Tầng Mạng (L2/L4): ARP Spoofing + MitM Sniffing (S5), TCP SYN Flood (S2), TCP RST Injection (S6).
  - Tầng OS & Host: Khai thác Reverse Shell (S1), File Descriptor Exhaustion (S3), Đọc trộm file mẫu (S4).
  - Kịch bản liên hoàn (**Kill Chain** - Tuần 6): Do thám $\rightarrow$ Chiếm quyền OS $\rightarrow$ Đánh cắp dữ liệu $\rightarrow$ Bão SYN Flood $\rightarrow$ Thử thách phòng thủ.
* **Người phụ trách:** **Minh Trí (TV2)**. [attacker-s1-s4.md](attacks/attacker-s1-s4.md).

### 3.4. `docs/defense/` (Cơ chế phòng thủ 3 lớp — Defense-in-Depth)
* **Ý nghĩa:** Tài liệu kỹ thuật về cơ chế "Phòng thủ chiều sâu" với 3 tầng khiên chắn độc lập:
  - **Lớp 1 (Mạng):** Static ARP, iptables/firewall lọc bão SYN. **Minh Trí (TV2)** phụ trách. [layer1-network-defense.md](defense/layer1-network-defense.md).
  - **Lớp 2 (HĐH):** `tcp_syncookies=1`, giới hạn tài nguyên `ulimit`/`cgroups`, vô hiệu hóa shell `nologin`. **Minh Trí (TV2)** phụ trách. [layer2-os-defense.md](defense/layer2-os-defense.md).
  - **Lớp 3 (Ứng dụng):** Prepared Statement chống SQLi, Dynamic Rate Limiting, Input Sanitization chống Path Traversal & Command Injection. **Hoàng Trung (TV3)** phụ trách. [layer3-application-defense.md](defense/layer3-application-defense.md).
  - **Bảng điều khiển 3 Khiên trên Web UI:** **Hạnh Nguyên (TV1)** phụ trách.

### 3.5. `docs/pcap-analysis/` (Phân tích gói tin mạng & Cơ chế nhân HĐH)
* **Ý nghĩa:** Sản phẩm học thuật chuyên sâu nộp ở Tuần 6:
  - Chụp và bóc tách từng trường trong gói tin pcap (Wireshark): Các cờ TCP (SYN, ACK, RST), ARP reply giả mạo.
  - Giải thích cơ chế nhân Linux (Kernel TCP/IP stack): Hàng đợi SYN backlog queue, Accept queue, thuật toán sinh cookie khi bị SYN Flood.
* **Người phụ trách:** **Minh Trí (TV2)**.

### 3.6. `docs/runbooks/` (Kịch bản thực nghiệm & Demo)
* **Ý nghĩa:** Bản hướng dẫn thao tác từng bước dành cho buổi thuyết trình trước hội đồng và giảng viên chấm đồ án:
  - Lệnh khởi động toàn bộ hệ thống (`docker compose up`).
  - Trình tự bấm các nút trên giao diện God-View để kích hoạt tấn công và quan sát hiệu ứng trực quan.
  - Trình tự bật các lớp khiên chắn và chứng minh gói tin bị chặn lại.
  - Lệnh làm sạch môi trường sau demo (`./scripts/reset-lab.sh`).
* **Người phụ trách:** Cả nhóm. [target-server-runbook.md](runbooks/target-server-runbook.md), [attacker-verification.md](runbooks/attacker-verification.md).

### 3.7. `docs/reports/` (Báo cáo & Slide thuyết trình)
* **Ý nghĩa:** Nơi lưu trữ các tài liệu chính thức nộp cho nhà trường: Báo cáo đồ án tổng kết PBL4 (Word/PDF) và Slide PowerPoint bảo vệ.
* **Người phụ trách:** Cả nhóm.

---

## 4. Quy tắc đóng góp tài liệu

1. **Định dạng:** Tất cả tài liệu viết bằng Markdown (`.md`), sử dụng Mermaid cho sơ đồ kiến trúc và chuỗi sự kiện.
2. **Quy tắc phân nhánh:** Khi chỉ viết/sửa tài liệu, tạo nhánh `docs/<ten-tai-lieu>` từ `develop` và mở PR theo quy định tại [CONTRIBUTING.md](../CONTRIBUTING.md).
3. **Ảnh & File đính kèm:** Ảnh chụp màn hình hoặc sơ đồ đặt trong thư mục `images/` hoặc lưu trực tiếp cùng thư mục tương ứng.
