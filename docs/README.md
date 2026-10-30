# Hướng Dẫn Cơ Cấu Tài Liệu Dự Án (Documentation Guide)
**Dự án:** PBL4 - Hệ Thống Mô Phỏng & Giám Sát Tấn Công Mạng & Hệ Điều Hành (God-View)  
**Tài liệu tham chiếu:** Kế hoạch thực hiện 6 tuần & phân chia nhiệm vụ

---

## 1. Mục đích của thư mục `docs/`

Thư mục `docs/` là trung tâm lưu trữ toàn bộ thông số kỹ thuật (specs), tài liệu thiết kế kiến trúc, kịch bản tấn công - phòng thủ, hướng dẫn thực thi (runbook) và báo cáo học thuật của dự án trong suốt quá trình 6 tuần thực hiện đồ án PBL4.

Mọi thành viên trong nhóm khi thực hiện task đều có trách nhiệm tra cứu, cập nhật và đồng bộ tài liệu tương ứng tại đây.

---

## 2. Sơ đồ cây thư mục tài liệu

```text
docs/
├── README.md                     # File này: Hướng dẫn cơ cấu và ý nghĩa các thư mục tài liệu
├── plan.pdf                      # File kế hoạch 6 tuần cập nhật và phân công chi tiết
├── plan(old).pdf                 # Kế hoạch ban đầu (lưu vết tham chiếu)
│
├── architecture/                 # Kiến trúc tổng thể hệ thống & sơ đồ mạng Docker
│   └── system-architecture.md    # Đặc tả 4 container, dải IP tĩnh và luồng Telemetry
│
├── api/                          # Đặc tả giao diện lập trình ứng dụng (API Specs)
│   ├── target-server/            # API Web Store mục tiêu (Login, Ping, Download, Heavy Endpoint)
│   ├── god-view/                 # API tiếp nhận Telemetry & WebSocket stream lên Dashboard
│   └── attacker/                 # API điều khiển kích hoạt các kịch bản tấn công từ xa
│
├── attacks/                      # Chi tiết các kịch bản tấn công (L2, L4, L7, OS) & Kill Chain
│   └── .gitkeep
│
├── defense/                      # Cơ chế phòng thủ 3 lớp (Defense-in-Depth) & Thử nghiệm chéo
│   └── .gitkeep
│
├── pcap-analysis/                # Báo cáo phân tích gói tin mạng (Wireshark) & Cơ chế nhân HĐH
│   └── .gitkeep
│
├── runbooks/                     # Hướng dẫn thao tác thực nghiệm & Kịch bản demo cho hội đồng chấm
│   └── .gitkeep
│
└── reports/                      # Báo cáo đồ án tổng kết PBL4 & Slide thuyết trình bảo vệ
    └── .gitkeep
```

---

## 3. Ý nghĩa chi tiết và phân công trách nhiệm từng thư mục

### 3.1. `docs/architecture/` (Kiến trúc hệ thống)
* **Ý nghĩa:** Là tài liệu nền móng của dự án. Quy định sơ đồ mạng Docker 4 container (`isolated-net` subnet `172.20.0.0/24`), IP tĩnh của từng node, cấu hình sysctl nhân Linux và luồng truyền thông điệp JSON Schema giữa các agent.
* **Người phụ trách chính:** **Hoàng Trung (TV3)** kết hợp với cả nhóm.
* **Tài liệu hiện có:** [system-architecture.md](architecture/system-architecture.md).

### 3.2. `docs/api/` (Đặc tả API phân tán)
* **Ý nghĩa:** Chứa tài liệu đặc tả REST API và WebSocket của từng node độc lập, giúp các thành viên phát triển mã nguồn không bị xung đột format dữ liệu:
  - `target-server/`: Mô tả các API người dùng và các điểm cắm lỗ hổng L7 (Command Injection, Path Traversal, Brute-force). **Hoàng Trung (TV3)** phụ trách.
  - `god-view/`: Mô tả API nhận Telemetry, kênh phát WebSocket thời gian thực và API điều khiển phòng thủ. **Hạnh Nguyên (TV1)** phụ trách.
  - `attacker/`: Mô tả API điều khiển module tấn công (start, stop, status). **Minh Trí (TV2)** phụ trách.

### 3.3. `docs/attacks/` (Kịch bản tấn công)
* **Ý nghĩa:** Lưu trữ toàn bộ tài liệu nghiên cứu và hướng dẫn thực thi các đòn tấn công mạng và hệ điều hành:
  - Tầng Mạng (L2/L4): ARP Spoofing + MitM Sniffing, TCP SYN Flood (hping3), TCP RST Injection (Scapy/tcpkill).
  - Tầng OS/L7: Khai thác Reverse Shell, đọc `/etc/passwd`, Heavy API DoS.
  - Kịch bản liên hoàn (**Kill Chain** - Tuần 6): Do thám $\rightarrow$ Chiếm quyền $\rightarrow$ Làm sập dịch vụ $\rightarrow$ Thử thách phòng thủ.
* **Người phụ trách chính:** **Minh Trí (TV2)**.

### 3.4. `docs/defense/` (Cơ chế phòng thủ 3 lớp)
* **Ý nghĩa:** Tài liệu kỹ thuật về cơ chế "Phòng thủ chiều sâu" (Defense-in-Depth) với 3 tầng khiên chắn độc lập:
  - Lớp 1 (Mạng): Static ARP, iptables/firewall.
  - Lớp 2 (HĐH): `tcp_syncookies=1`, giới hạn tài nguyên `ulimit`/`cgroups`, vô hiệu hóa shell `nologin`.
  - Lớp 3 (Ứng dụng): Middleware API Rate Limiting theo IP/User, Input Sanitization.
  - Báo cáo **Kiểm thử chéo (Cross-Layer Testing - Tuần 5)**: Minh chứng tại sao chỉ bật phòng thủ ở một lớp là không đủ.
* **Người phụ trách chính:** **Hoàng Trung (TV3)** & **Hạnh Nguyên (TV1)**.

### 3.5. `docs/pcap-analysis/` (Phân tích gói tin mạng & Cơ chế nhân HĐH)
* **Ý nghĩa:** Sản phẩm học thuật chuyên sâu nộp ở Tuần 6:
  - Chụp và bóc tách từng trường trong gói tin pcap (Wireshark): Các cờ TCP (SYN, ACK, RST), ARP reply giả mạo.
  - Giải thích cơ chế nhân Linux (Kernel TCP/IP stack): Hàng đợi SYN backlog queue, Accept queue, thuật toán sinh cookie khi bị SYN Flood.
* **Người phụ trách chính:** **Minh Trí (TV2)**.

### 3.6. `docs/runbooks/` (Kịch bản thực nghiệm & Demo)
* **Ý nghĩa:** Bản hướng dẫn thao tác từng bước dành cho buổi thuyết trình trước hội đồng và giảng viên chấm đồ án:
  - Lệnh khởi động toàn bộ hệ thống (`docker compose up`).
  - Trình tự bấm các nút trên giao diện God-View để kích hoạt tấn công và quan sát hiệu ứng trực quan.
  - Trình tự bật các lớp khiên chắn và chứng minh gói tin bị chặn lại.
  - Lệnh làm sạch môi trường sau demo (`./scripts/reset-lab.sh`).
* **Người phụ trách chính:** Cả nhóm.

### 3.7. `docs/reports/` (Báo cáo & Slide thuyết trình)
* **Ý nghĩa:** Nơi lưu trữ các tài liệu chính thức nộp cho nhà trường:
  - Kế hoạch 6 tuần gốc.
  - Báo cáo tổng kết đồ án PBL4 (Word/PDF).
  - Slide PowerPoint thuyết trình bảo vệ đồ án.
* **Người phụ trách chính:** Cả nhóm.

---

## 4. Quy tắc đóng góp tài liệu

1. **Định dạng:** Tất cả tài liệu viết bằng Markdown (`.md`), sử dụng Mermaid cho sơ đồ kiến trúc và chuỗi sự kiện.
2. **Quy tắc phân nhánh:** Khi chỉ viết/sửa tài liệu, tạo nhánh `docs/<ten-tai-lieu>` từ `develop` và mở PR theo quy định tại [CONTRIBUTING.md](../CONTRIBUTING.md).
3. **Ảnh & File đính kèm:** Ảnh chụp màn hình hoặc sơ đồ đặt trong thư mục `images/` hoặc lưu trực tiếp cùng thư mục tương ứng.
