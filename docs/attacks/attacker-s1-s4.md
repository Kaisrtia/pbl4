# Đặc Tả Kịch Bản Tấn Công Đa Tầng (Multi-Layer Attack Catalog & Scenarios)

> **Phụ trách:** Minh Trí (TV2) — *Tấn công & Hạ tầng Mạng + HĐH*  
> **Dự án:** PBL4 — Hệ thống Mô phỏng & Giám sát Tấn công Mạng & Hệ điều hành (God-View)  
> **Tài liệu tham chiếu:** [docs/plan.pdf](../../plan.pdf) (Task W1-T2, W3-T2, W4-T2, W6-ALL)  
> **Mã nguồn thực thi:** `attacker/scripts/` và `attacker/src/`

---

## 1. Tổng quan lộ trình kịch bản tấn công (Attack Roadmap)

Để đáp ứng đầy đủ yêu cầu học thuật của đề tài PBL4 và bảng kế hoạch chính thức [docs/plan.pdf](../../plan.pdf), hệ sinh thái tấn công được tổ chức thành **6 kịch bản độc lập (S1–S6)** và **1 kịch bản liên hoàn (Kill Chain)**:

```mermaid
flowchart TD
    subgraph Tầng Mạng (L2 / L4)
        S5["S5: ARP Spoofing + MitM<br/>(Giả mạo MAC & Bắt gói tin)"]
        S2["S2: TCP SYN Flood<br/>(Scapy Raw SYN làm tràn Backlog)"]
        S6["S6: TCP RST Injection<br/>(Tiêm cờ RST ngắt kết nối hợp lệ)"]
    end

    subgraph Tầng Hệ Điều Hành & Host
        S1["S1: SSH Lab Chain / Reverse Shell<br/>(Chiếm quyền điều khiển OS)"]
        S3["S3: File Descriptor Exhaustion<br/>(Mở cạn kiệt RLIMIT_NOFILE)"]
        S4["S4: Sample Data Exfiltration<br/>(Trích xuất tệp mẫu & so khớp SHA-256)"]
    end

    subgraph Tuần 6: Kịch Bản Liên Hoàn (Kill Chain)
        KC["KILL CHAIN LIÊN HOÀN:<br/>1. Do thám (S5 MitM / Port Scan)<br/>2. Chiếm quyền OS (S1 Shell / Command Injection)<br/>3. Đánh cắp dữ liệu (S4 Data Leak)<br/>4. Làm sập dịch vụ (S2 SYN Flood DoS)<br/>5. Thử thách cơ chế phòng ngự 3 lớp"]
    end

    S5 --> KC
    S2 --> KC
    S1 --> KC
    S3 --> KC
    S4 --> KC
    S6 --> KC
```

---

## 2. Chi tiết 6 Kịch Bản Tấn Công

### 2.1. Kịch bản S1: Chuỗi Thao Tác OS Qua SSH / Reverse Shell (Task W4-T2)
* **Mã nguồn:** `attacker/scripts/ssh_chain.py`
* **Mục tiêu:** Mô phỏng việc kẻ tấn công sau khi chiếm được quyền truy cập máy chủ (qua lỗ hổng Command Injection hoặc SSH lab credential) thực hiện:
  1. Kết nối vào hệ thống với user không đặc quyền (`lab`).
  2. Xác định định danh hệ điều hành (`uid`, `gid`, `groups`).
  3. Tạo marker file trong thư mục sandbox `/home/lab/pbl4-lab/run-<UUID>/`.
  4. Đóng và mở lại kết nối (xác nhận quyền duy trì truy cập - session persistence).
  5. Dọn dẹp bản sao audit do chính lần chạy tạo ra.
* **Đầu ra Telemetry:** Gửi sự kiện `RUN_STATE` và `WORKER_EVENT` về God-View (`state: COMPLETED`, `outcome: OBSERVED`).

---

### 2.2. Kịch bản S2: Bão Gói Tin TCP SYN Flood (Task W1-T2, W3-T2)
* **Mã nguồn:** `attacker/scripts/syn_flood.py`
* **Nguyên lý:** Sử dụng thư viện **Scapy** chế tạo các gói tin TCP thô (Raw IP/TCP Packet) có cờ `SYN = 1`, gửi liên tục tới cổng 8000 của Target Server với tốc độ cấu hình (50–150 pps trong 5–15 giây).
* **Mục tiêu học thuật:**
  - Bắn bão gói tin khiến số lượng kết nối ở trạng thái `SYN_RECV` tăng vọt trong bảng kết nối của kernel (`/proc/net/tcp` hoặc `ss -tan`).
  - Khi hàng đợi SYN Backlog bị lấp đầy, người dùng bình thường (Client) không thể bắt tay 3 bước (3-way handshake) và bị treo kết nối.
  - Kiểm chứng hiệu quả của **Khiên L2 (`net.ipv4.tcp_syncookies = 1`)**: Khi bật khiên, server vẫn phục vụ Client bình thường dù đang bị bão SYN dội vào.

---

### 2.3. Kịch bản S3: Làm Cạn Kiệt Bộ Mô Tả Tệp (File Descriptor Exhaustion - Task W4-T2)
* **Mã nguồn:** `attacker/scripts/fd_exhaustion.py` & `remote_fd.py`
* **Nguyên lý:** Khởi chạy tiến trình Python riêng trên Target Server qua SSH, liên tục mở các file mô tả (file descriptors) trong sandbox cho đến khi chạm trần giới hạn `RLIMIT_NOFILE`.
* **Mục tiêu học thuật:**
  - Chứng minh sự cố `EMFILE: too many open files`.
  - Phân tích sự khác biệt giữa giới hạn mềm (`soft limit`) và giới hạn cứng (`hard limit`) trong nhân Linux.
  - Khẳng định tầm quan trọng của việc cấu hình `ulimit` và `cgroups` cho từng service thay vì để mặc định toàn hệ thống.

---

### 2.4. Kịch bản S4: Trích Xuất Dữ Liệu Ngược (Sample Data Exfiltration - Task W4-T2)
* **Mã nguồn:** `attacker/scripts/sample_transfer.py` & `attacker/src/services/receiver.ts`
* **Nguyên lý:** Yêu cầu Target Server đọc tệp mẫu `sample.txt` (1–4096 bytes) trong sandbox, tạo kết nối HTTP ngược (egress) về cổng 9001 của Hacker Receiver kèm Token xác thực một lần.
* **Mục tiêu học thuật:**
  - Kiểm tra khả năng rò rỉ dữ liệu (Data Leakage) khi tường lửa không kiểm soát lưu lượng đi ra (outbound traffic).
  - Đối chiếu mã băm **SHA-256** giữa tệp gửi đi và tệp nhận được để chứng minh tính toàn vẹn của dữ liệu bị đánh cắp.

---

### 2.5. Kịch bản S5: Ngộ Độc ARP Cache & Bắt Gói Tin Đứng Giữa (ARP Spoofing + MitM - Task W3-T2)
* **Mã nguồn:** `attacker/scripts/arp_spoof.py` (Mở rộng từ Scapy)
* **Nguyên lý:**
  - Attacker phát các bản tin `ARP Reply` giả mạo không qua yêu cầu (Gratuitous ARP) tới Client (172.20.0.10) và Server (172.20.0.20):
    - Nói với Client: *"IP 172.20.0.20 có địa chỉ MAC của Hacker!"*
    - Nói với Server: *"IP 172.20.0.10 có địa chỉ MAC của Hacker!"*
  - Bật tính năng chuyển tiếp gói tin (`ip_forward = 1`) để đọc trộm (Sniff) các gói tin HTTP chứa tài khoản/mật khẩu không mã hóa của Client Bot.
* **Mục tiêu học thuật:** Kiểm chứng hiệu quả của **Khiên L1 (`arp -s` Static ARP)** trong việc ngăn chặn đòn giả mạo MAC.

---

### 2.6. Kịch bản S6: Tiêm Gói Tin TCP RST Ngắt Phiên (TCP RST Injection - Task W3-T2)
* **Mã nguồn:** `attacker/scripts/rst_injection.py` (Mở rộng từ Scapy)
* **Nguyên lý:** Attacker lắng nghe một phiên TCP hợp lệ đang diễn ra giữa Client và Target Server, trích xuất số thứ tự tuần tự `Sequence Number` hiện tại, và lập tức phát một gói tin mang cờ `RST = 1` hợp lệ tới Server.
* **Mục tiêu học thuật:** Kết nối của Client bị ngắt đột ngột (Connection reset by peer). Giao diện God-View ghi nhận sự cố gián đoạn dịch vụ tức thì.

---

## 3. Tích hợp Bắn Telemetry Về God-View

Mọi lần chạy kịch bản từ CLI hoặc API đều tự động đẩy bản tin chuẩn hóa về trạm trung tâm:
* **URL đẩy sự kiện:** `POST http://172.20.0.99:4000/api/events/attack`
* **Schema quy định:** `shared/schemas/attacker-event.schema.json`
* **Cơ chế Outbox:** Bản tin được ghi bền vững vào `.data/<run_id>.jsonl` trước khi gửi; nếu mất kết nối God-View, outbox tự động retry mỗi 2 giây mà không làm gián đoạn tiến trình chạy của worker.
