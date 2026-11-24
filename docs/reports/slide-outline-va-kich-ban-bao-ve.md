# ĐỀ CƯƠNG SLIDE THUYẾT TRÌNH & KỊCH BẢN TRÌNH DIỄN LIVE DEMO BẢO VỆ ĐỒ ÁN (W6-ALL & W6-T1)

> **Đề tài:** PBL4 — Hệ thống Mô phỏng & Giám sát Tấn công Mạng & Hệ điều hành theo thời gian thực (God-View SIEM)  
> **Nhóm thực hiện:**  
> - **TV1 — Hạnh Nguyên:** Giao diện Thượng Đế (God-View SIEM Hub & Real-Time Visualization UI/UX)  
> - **TV2 — Minh Trí:** Tấn công & Phòng thủ Hạ tầng Mạng (L2/L4) & Nhân Hệ điều hành (OS/Kernel)  
> - **TV3 — Hoàng Trung:** Máy chủ Ứng dụng Mục tiêu (ElectroShop Target App) & Tấn công/Phòng thủ Tầng Ứng dụng (L7)

---

## PHẦN 1: CẤU TRÚC BỘ SLIDE THUYẾT TRÌNH (12 SLIDES)

### Slide 1: Trang bìa (Title Slide)
* **Tiêu đề:** Hệ thống Mô phỏng & Giám sát Tấn công Mạng - Hệ điều hành Đa tầng theo Thời gian thực (**God-View SIEM**)
* **Thông điệp chính:** Từ gói tin nhị phân trong Kernel Linux đến trực quan hóa 60 FPS và Phễu Phòng thủ Chiều sâu 3 Lớp (*Defense-in-Depth*).
* **Thành viên & Phân công 3 phân lớp rõ ràng:** UI/SIEM (TV1) — Network & OS Kernel (TV2) — Application L7 (TV3).

### Slide 2: Đặt vấn đề & Mục tiêu Đồ án
* **Vấn đề:** Các đòn tấn công mạng (ARP Spoofing, SYN Flood, RST) và khai thác HĐH (Reverse Shell, File Descriptor Exhaustion) diễn ra âm thầm trong Kernel/Network Stack, rất khó quan sát sự tương tác chéo giữa các tầng nếu chỉ nhìn từng cửa sổ Terminal rời rạc.
* **Giải pháp của nhóm:** Xây dựng mô hình Lab 4-Node cách ly kết hợp trạm giám sát **God-View SIEM** hiển thị đồng bộ mọi biến động từ Tầng 2 (Data Link), Tầng 4 (Transport), Nhân HĐH (OS/Kernel) đến Tầng 7 (Application).

### Slide 3: Kiến trúc Tổng thể 4-Node & Luồng Telemetry Thời gian thực
* **Sơ đồ mạng LAN ảo (`172.20.0.0/24` / `172.30.44.0/24`):**
  - `Client (.10)`: Bot sinh lưu lượng người dùng hợp lệ & Host Telemetry Agent.
  - `Target Server (.20:8000)`: Ứng dụng thương mại điện tử ElectroShop (NestJS + SQLite WAL) tích hợp 3 Lớp Khiên.
  - `Hacker Node (.66:9000)`: Bộ điều khiển tấn công Scapy/Python & L7 CLI.
  - `God-View SIEM (.99:4000)`: Trạm thu nạp Telemetry (`In-memory Ring Buffer 300 items`) & phát sóng WebSocket (`Socket.IO`).

### Slide 4: Phân hệ Target App (ElectroShop) & 5 Điểm Cắm Lỗ Hổng Tầng 7 (TV3 - Hoàng Trung)
* Kiến trúc NestJS + SQLite WAL của ElectroShop.
* 5 lỗ hổng có thể bật/tắt động:
  1. **SQL Injection** (Bypass đăng nhập Admin).
  2. **OS Command Injection** (`/api/system/network-ping` — bàn đạp mở Reverse Shell).
  3. **Path Traversal** (`/api/files/download?name=../../../../etc/passwd`).
  4. **Confidential Document Leak** (Rò rỉ bản vẽ thiết kế phần cứng mật).
  5. **Heavy Calculation DoS** (Băm SHA-256 đồng bộ làm nghẽn Event Loop) & **Low-rate Brute-force (1 req/s)** vượt tường lửa mạng.

### Slide 5: Tấn công Đường truyền Mạng L2/L4 (TV2 - Minh Trí)
* **Kịch bản S5 — ARP Spoofing & MitM Sniffing (L2):** Đầu độc bảng `/proc/net/arp` của Client và Target để bẻ cong luồng HTTP đi qua máy Hacker, bắt trộm mật khẩu và JWT Token.
* **Kịch bản S2 — TCP SYN Flood (L4):** Bắn bão cờ `SYN` làm ngập hàng đợi bán mở (`SYN_RECV` backlog queue) trong nhân Linux.
* **Kịch bản S6 — TCP RST Injection (L4):** Bắt số thứ tự `SEQ/ACK` và tiêm gói `RST` giả mạo để đánh sập kết nối đang hoạt động của người dùng.

### Slide 6: Tấn công Hệ điều hành & Tài nguyên Kernel (TV2 - Minh Trí)
* **Kịch bản S1 — Reverse Shell & Chiếm quyền Điều khiển OS:** Từ lỗ hổng Command Injection mở tiến trình con `/bin/sh -> nc -e /bin/sh` kết nối ngược về máy Hacker (`:4444`).
* **Kịch bản S3 — File Descriptor Exhaustion (`lsof` / `EMFILE`):** Mở hàng loạt file/socket làm chạm trần `ulimit -n`, khiến máy chủ không thể mở thêm kết nối mới.
* **Kịch bản S4 — Khai thác Đọc tệp Hệ thống:** Trích xuất `/etc/passwd`, `/proc/self/environ` và đối chiếu mã băm SHA-256.

### Slide 7: Trạm Giám sát God-View SIEM & Đồ họa Thời gian thực 60 FPS (TV1 - Hạnh Nguyên)
* **HTML5 Canvas Particle Engine:**
  - Đường cong Bézier cho lưu lượng chuẩn (hạt xanh lá).
  - Tự động bẻ góc đường truyền 2 chặng (`Client -> Hacker -> Server`, đổi màu cam) khi phát hiện ARP Spoofing.
  - Vẽ đường hầm Reverse Shell đi ngược từ `Server -> Hacker:4444`.
* **Bảng giám sát chuyên sâu:** Bảng ARP Cache báo đỏ MAC giả, Cửa sổ MitM Sniffer, Biểu đồ cột `SYN_RECV`, Cây tiến trình `pstree` nhấp nháy đỏ khi mọc `/bin/sh`, Đồng hồ bán nguyệt SVG đo `lsof`.

### Slide 8: Phễu Phòng thủ Chiều sâu 3 Lớp — Defense-in-Depth Funnel (Cả nhóm)
* **Lớp 1 — Khiên Mạng (L2/L4 Network Shield):** `Static ARP` (`nud permanent`) khóa cứng địa chỉ MAC + `iptables` giới hạn tốc độ gói `SYN` và lọc gói `RST` giả mạo.
* **Lớp 2 — Khiên Hệ điều hành (OS/Kernel Shield):** `net.ipv4.tcp_syncookies=1` chống tràn SYN backlog, giới hạn tài nguyên `ulimit -n` / `cgroups v2` (`pids.max`, CPU/RAM) và chạy dịch vụ dưới user `nologin` chống mở Reverse Shell.
* **Lớp 3 — Khiên Ứng dụng (L7 Application Shield):** Truy vấn tham số hóa `Prepared Statements` chống SQLi, `Sliding Window Rate Limiting` chống Brute-force/Heavy DoS, và `Input Sanitization` chống Command Injection/Path Traversal.

### Slide 9: Hiệu ứng Va chạm 3 Vòng Khiên & Kết quả Kiểm thử Chéo (TV1 + TV2 + TV3)
* Cơ chế 3 vòng khiên đồng tâm trên Canvas ($R_{L1}=152\text{px}$, $R_{L2}=126\text{px}$, $R_{L3}=98\text{px}$): Gói tin độc hại bị chặn ở tầng nào sẽ nổ tia lửa và **dội ngược lại (Bounce-Back Recoil)** tại đúng vòng khiên của tầng đó.
* Bảng đối chiếu kết quả thực nghiệm **Trước và Sau khi bật từng lớp khiên**.

### Slide 10: Tối ưu Hiệu năng Giao diện & Cơ chế Reset Lab 1-Chạm (< 3 giây) (W6-T1/T2/T3)
* **Chống đơ trình duyệt khi bão SYN Flood:** Gom nhóm sự kiện WebSocket theo khung hình (`requestAnimationFrame` Batching), chèn DOM bằng `DocumentFragment` và giới hạn trần 180 hạt trên Canvas giữ vững **60 FPS**.
* **Nút bấm `"⚡ RESET LAB 1-CHẠM"` (`POST /api/lab/reset`):** Khôi phục đồng bộ CSDL SQLite, xóa bộ đếm Rate Limit, xóa bảng ARP giả, ngắt Reverse Shell, đưa `lsof` về `42/1024` và xóa Ring Buffer trong **$< 50\text{ms}$** (cam kết SLA $< 3\text{s}$).

### Slide 11: Chuỗi Tấn công Liên hoàn 5 Giai đoạn — Multi-Layer Kill Chain (W6-ALL)
* Sơ đồ 5 bước liên hoàn trên God-View:
  `① Recon & ARP MitM` $\rightarrow$ `② L7 SQLi & Low-rate Brute-force` $\rightarrow$ `③ OS Reverse Shell` $\rightarrow$ `④ Data Exfiltration` $\rightarrow$ `⑤ SYN Flood + FD Exhaustion + TCP RST`.

### Slide 12: Kết luận, Kiểm thử Tự động & Hướng phát triển
* Tổng kết: **100% test tự động PASS** across cả 3 phân hệ (`12/12` God-View Hub tests, `27/27` Target App E2E tests, cùng bộ unittest Python/Controller của Attacker & Host Agent).

---

## PHẦN 2: KỊCH BẢN TRÌNH DIỄN LIVE DEMO TRƯỚC HỘI ĐỒNG (8 PHÚT)

### Bước 0: Khởi động & Giới thiệu Trạng thái Chuẩn (1 phút — TV1 Hạnh Nguyên)
1. Mở giao diện **God-View SIEM Dashboard** (`http://localhost:4000` hoặc cổng tích hợp `14000`) và trang **ElectroShop** (`http://localhost:8000` / `18000`).
2. Chỉ cho hội đồng thấy trạng thái sạch ban đầu:
   - Trên Header: `CONNECTED`, `UI ENGINE: 60 FPS · THROTTLED`.
   - 3 Lớp Khiên (`L1 Network`, `L2 OS/Kernel`, `L3 App`) đều đang ở trạng thái **`BYPASSED` (Tắt)**.
   - Bấm **`Ping Check`** / **`Normal Login`**: Các hạt gói tin màu xanh lá bay mượt từ `Client (.10)` sang `Target Server (.20)`.

### Bước 1: Chạy Chuỗi Tấn công Liên hoàn Kill Chain khi Chưa Bật Khiên (3 phút — TV2 Minh Trí & TV3 Hoàng Trung phối hợp, TV1 thuyết minh trên UI)
* Có thể bấm từng bước `Run S1` $\rightarrow$ `Run S5` trên thanh **Kill Chain Orchestrator** (hoặc chạy CLI thực tế từ máy Attacker kết hợp nút **`▶ AUTO-PLAY KILL CHAIN`**):
  1. **Giai đoạn 1 — ARP Spoofing & MitM (TV2):**
     - Bấm `Run S1` (hoặc chạy S5 ARP Spoof): Đường truyền thẳng `Client -> Server` bị gạch chéo đỏ. Các hạt xanh từ Client bị **bẻ góc đi vòng xuống Node Hacker**, đổi sang **màu cam** rồi mới lên Server.
     - Chỉ vào **Bảng ARP Cache** (đỏ rực `⚠️ POISONED`) và **Cửa sổ MitM Sniffer** (hiện rõ `USER: engineer_user | PASS: pass123` và chuỗi JWT Token vừa bắt được).
  2. **Giai đoạn 2 — Vượt Tường lửa bằng Low-rate Brute-force & SQL Injection (TV3):**
     - Bấm `Run S2` (hoặc chạy `node scripts/attack-l7.mjs --scenario sqli`): Hạt đỏ bay thẳng vào Server. Bảng **L7 Security Alerts** hiện cảnh báo `💥 EXPLOITED (200)` với payload `username="admin' OR '1'='1' --"`.
  3. **Giai đoạn 3 — Chiếm quyền Hệ điều hành với Reverse Shell (TV2 + TV3):**
     - Bấm `Run S3`: Lỗ hổng Command Injection tại `/api/system/network-ping` kích hoạt `/bin/sh -> nc`.
     - Chỉ vào **Cây tiến trình `pstree`**: Nhánh `[PID 412] /bin/sh -> [PID 413] nc` mọc ra và nhấp nháy đỏ. Trên Canvas xuất hiện **đường hầm màu hồng bắn hạt ngược từ `Server -> Hacker:4444`**.
  4. **Giai đoạn 4 — Đánh cắp Dữ liệu Hệ thống (TV2 + TV3):**
     - Bấm `Run S4`: Khai thác Path Traversal đọc `/etc/passwd` — hiển thị ngay trong mục `📂 lsof MONITOR` và bảng cảnh báo L7.
  5. **Giai đoạn 5 — Tấn công Từ chối Dịch vụ Đa tầng SYN Flood, FD Exhaustion & TCP RST (TV2):**
     - Bấm `Run S5` và bấm thêm **`🌊 STRESS TEST SYN BURST (120 PKTS)`**:
       - Hàng trăm hạt tím/đỏ lao vào Server nhưng chỉ số **`UI ENGINE: 60 FPS · BATCHING`** trên Header vẫn mượt mà, không hề đơ trình duyệt.
       - **Biểu đồ cột `SYN_RECV`** dựng đứng lên mức đỏ (`🔥 BACKLOG: FLOODED`).
       - **Đồng hồ bán nguyệt `lsof`** vọt lên $95\%$ (`🔥 EMFILE: FD EXHAUSTED`).
       - Thanh trạng thái Kill Chain báo: **`🔥 KILL CHAIN: 5/5 STAGES EXPLOITED`**.

### Bước 2: Khôi phục Trạng thái Sạch tức thì với Nút `"⚡ RESET LAB 1-CHẠM"` (1 phút — TV1 & TV3)
1. TV1 nhấn nút **`⚡ RESET LAB 1-CHẠM`** ở góc phải Header.
2. Chỉ trong **$< 50\text{ms}$**, Banner màu xanh lá xuất hiện: **`⚡ 1-TOUCH LAB RESET COMPLETED · PASS (<3s SLA)`**.
3. Chỉ cho hội đồng thấy toàn bộ hệ thống đã sạch bóng:
   - Bảng ARP trở về `ARP: VERIFIED`, đường truyền MitM và đường hầm Reverse Shell biến mất.
   - Cây tiến trình `pstree` trở về 4 tiến trình chuẩn (`OS: CLEAN`), đồng hồ `lsof` về `42 / 1024 (4%)`.
   - Biểu đồ `SYN_RECV` hạ về `0`, CSDL SQLite và bộ đếm Rate Limit trên Target App đã được khôi phục nguyên trạng.

### Bước 3: Bật Phễu Phòng thủ 3 Lớp & Kiểm thử Chéo để Trả lời Phản biện (3 phút — Cả nhóm)
1. **Minh họa từng vòng khiên hoặc bật cả 3 lớp khiên:**
   - Bấm **`ENABLE L1`** (vòng khiên Cyan ngoài cùng sáng lên quanh Target Server). Bắn thử `ARP Spoof` hoặc `TCP RST`: Hạt độc hại bị **chặn đứng ở vòng ngoài cùng ($152\text{px}$) và dội ngược lại về phía Hacker** kèm nhãn `🛡️ BLOCKED [L1: STATIC ARP]`.
   - Bấm **`ENABLE L2`** (vòng khiên Vàng ở giữa sáng lên). Bắn thử `FD Exhaust` hoặc `Reverse Shell` (khi L3 đang tắt): Hạt bị chặn tại vòng giữa ($126\text{px}$) với nhãn `🛡️ SHELL KILLED [L2: NOLOGIN / CGROUPS]`, cây `pstree` vẫn sạch sẽ.
   - Bấm **`ENABLE L3`** (hoặc bấm **`🛡️ ENABLE ALL 3 SHIELDS`** để bật đủ 3 vòng khiên đồng tâm Cyan - Vàng - Xanh lá).
2. **Chạy lại `▶ AUTO-PLAY KILL CHAIN (5 STAGES)` khi cả 3 Khiên đang BẬT:**
   - Toàn bộ 5 giai đoạn tấn công đều bị đánh bật tại đúng vòng khiên tương ứng!
   - Cả 5 ô trên thanh Kill Chain chuyển sang màu xanh lá: **`🛡️ KILL CHAIN: 5/5 STAGES MITIGATED`**.

---

## PHẦN 3: BỘ CÂU HỎI & TRẢ LỜI PHẢN BIỆN HỘI ĐỒNG (Q&A CHEAT SHEET)

1. **Hội đồng hỏi:** *"Tại sao khi bật Khiên Mạng L1 (`iptables` lọc SYN) và Khiên HĐH L2 (`tcp_syncookies`), kẻ tấn công vẫn khai thác được SQL Injection và Low-rate Brute-force?"*
   - **Trả lời (TV3 & TV1):** Vì `iptables` và `tcp_syncookies` hoạt động ở tầng Mạng/Vận chuyển (L3/L4 OSI), chỉ kiểm tra header IP/TCP và tốc độ gói SYN. Đòn `Low-rate Brute-force (1 req/s)` và `SQL Injection` sử dụng kết nối TCP hoàn toàn hợp lệ với tần suất thấp nên đi xuyên qua L1 và L2. Chỉ có **Khiên Ứng dụng L3** (`Prepared Statements` và `Sliding Window Rate Limit` theo ngữ cảnh endpoint `/api/auth/login`) mới hiểu được cú pháp SQL/HTTP để chặn đứng. Trên God-View Canvas, hội đồng có thể thấy rõ hạt SQLi đi xuyên qua vòng Cyan (L1) và vòng Vàng (L2) rồi mới bị chặn và dội ngược tại vòng Xanh lá trong cùng (L3).

2. **Hội đồng hỏi:** *"Nếu ứng dụng Web (L3) bị lỗi hoặc lập trình viên quên lọc đầu vào dẫn đến OS Command Injection, làm sao hệ thống ngăn không cho Hacker mở Reverse Shell?"*
   - **Trả lời (TV2 & TV1):** Đó chính là ý nghĩa của **Phòng thủ Chiều sâu (Defense-in-Depth)** ở **Khiên HĐH L2**. Khi chúng em tắt cờ `Sanitizer` của L3 nhưng bật **Khiên L2**, tiến trình web chạy dưới tài khoản giới hạn có shell là `/usr/sbin/nologin`, đồng thời bị khóa bởi `cgroups v2` (`pids.max`) và `ulimit -n`. Do đó dù lệnh shell được gọi từ Node.js, nhân Linux sẽ từ chối khởi tạo tiến trình `/bin/sh` tương tác, làm đứt gãy chuỗi Kill Chain ngay tại Bước 3.

3. **Hội đồng hỏi:** *"Khi bắn hàng nghìn gói SYN Flood mỗi giây, làm thế nào giao diện Web không bị treo (freeze) do phải vẽ lại bảng DOM và Canvas liên tục?"*
   - **Trả lời (TV1):** Em đã thiết kế cơ chế **`requestAnimationFrame` Event Batching & Particle Throttling** trong `app.js`. Khi bão sự kiện WebSocket đổ về, luồng mạng chỉ đẩy dữ liệu vào mảng tạm trong RAM ($\mathcal{O}(1)$). Mỗi khung hình ($16.6\text{ms}$), giao diện mới gom toàn bộ các bản tin trong lô đó vào một `DocumentFragment` để chèn vào bảng DOM đúng 1 lần duy nhất, đồng thời giới hạn trần `MAX_ACTIVE_PARTICLES = 180` trên Canvas. Nhờ đó trình duyệt luôn giữ vững tốc độ 60 FPS.
