# Hướng Dẫn Đóng Góp & Quy Trình Gitflow (Contribution & Gitflow Guide)

Tài liệu này quy định chuẩn mực làm việc với Git, quy trình phân nhánh (Gitflow), quy ước commit và cách mở Pull Request (PR) cho dự án **PBL4 - Hệ Thống Mô Phỏng & Giám Sát Tấn Công Mạng & Hệ Điều Hành (God-View)**.

---

## 1. Sơ đồ mô hình Gitflow

Dự án áp dụng mô hình **Gitflow cải tiến**, kết hợp **Squash and Merge** đối với các nhánh tính năng để giữ lịch sử nhánh `develop` luôn gọn gàng và mạch lạc:

```mermaid
gitGraph
    commit id: "initial commit"
    branch develop
    checkout develop
    commit id: "setup project"
    
    branch feature/t1-auth-api
    checkout feature/t1-auth-api
    commit id: "feat(target): add login"
    commit id: "test(target): test jwt"
    checkout develop
    merge feature/t1-auth-api id: "PR #2: feat(target): add login api (Squash)"
    
    branch feature/t1-syn-flood
    checkout feature/t1-syn-flood
    commit id: "feat(attacker): add scapy syn"
    checkout develop
    merge feature/t1-syn-flood id: "PR #3: feat(attacker): add syn flood module (Squash)"
    
    branch release/v1.0.0
    checkout release/v1.0.0
    commit id: "chore: bump version v1.0.0"
    checkout main
    merge release/v1.0.0 id: "Release v1.0.0 (Merge Commit)"
    tag: "v1.0.0"
    
    checkout develop
    branch sync/v1.0.0
    checkout sync/v1.0.0
    merge main id: "Sync back to develop"
    checkout develop
    merge sync/v1.0.0 id: "PR: sync main to develop"
```

---

## 2. Bảng quy chuẩn phân nhánh (Branching Model)

| Nhánh | Tạo từ | PR vào | Cách merge | Ý nghĩa & Mục đích |
| :--- | :--- | :--- | :--- | :--- |
| `feature/*` | `develop` | `develop` | **Squash** | Phát triển tính năng mới theo task (vd: `feature/t1-auth-api`). |
| `fix/*` | `develop` | `develop` | **Squash** | Sửa lỗi phát sinh trong quá trình phát triển trên `develop`. |
| `chore/*` | `develop` | `develop` | **Squash** | Cấu hình hạ tầng, Docker, dependencies, CI/CD. |
| `docs/*` | `develop` | `develop` | **Squash** | Thêm hoặc cập nhật tài liệu độc lập (báo cáo, slide, spec). |
| `refactor/*` | `develop` | `develop` | **Squash** | Tái cấu trúc mã nguồn mà không làm đổi logic/tính năng. |
| `test/*` | `develop` | `develop` | **Squash** | Viết thêm kịch bản kiểm thử tự động, unit test. |
| `release/*` | `develop` | `main` | **Merge commit** | Chuẩn bị phát hành phiên bản nghiệm thu (chỉ sửa lỗi phát hành). |
| `hotfix/*` | `main` | `main` | **Merge commit** | Vá lỗi khẩn cấp trực tiếp từ bản đã nghiệm thu trên `main`. |
| `sync/*` | `main` | `develop` | **Merge commit** | Đồng bộ ngược lại từ `main` về `develop` sau release/hotfix. |

> [!IMPORTANT]
> **Quy tắc bất biến:**
> - Tuyệt đối **KHÔNG commit trực tiếp** lên `main` và `develop` (ngoại lệ duy nhất là PR #1 thiết lập ban đầu vào `main`).
> - Không force push (`push -f`) lên nhánh chung (`main`, `develop`).
> - Chỉ rebase nhánh cá nhân khi người cùng làm đồng ý.

---

## 3. Quy trình từng bước khi làm việc (Step-by-Step Workflow)

Khi được giao một Task (ví dụ Task `T1-TV1`, `T1-TV2`, `T1-TV3` theo kế hoạch 6 tuần):

### Bước 1: Luôn cập nhật `develop` mới nhất
```bash
git checkout develop
git pull origin develop
```

### Bước 2: Tạo nhánh công việc mới
Tên nhánh đặt theo tiền tố quy định:
```bash
# Ví dụ làm tính năng tấn công SYN Flood
git checkout -b feature/t1-syn-flood-module

# Hoặc cấu hình Docker Compose
git checkout -b chore/docker-network-setup
```

### Bước 3: Code và Commit theo chuẩn Conventional Commits
Mỗi commit nên tập trung vào một đơn vị công việc rõ ràng:
```bash
git add <files>
git commit -m "<type>(<scope>): <mô tả ngắn bằng tiếng Anh/Việt>"
```
* **Format:** `<type>(<scope>): <mô tả>`
* **Types hợp lệ:** `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `ci`, `perf`.
* **Scope gợi ý theo kiến trúc dự án:**
  - `attacker`: Code hoặc kịch bản tấn công.
  - `target-app`: Ứng dụng Web Store mục tiêu.
  - `telemetry`: Các Agent đọc ARP, TCP, OS metrics.
  - `godview`: Giao diện Dashboard hoặc WebSocket server.
  - `docker`: Cấu hình container, mạng ảo, sysctl.
  - `schema`: Chuẩn JSON Event.
* **Ví dụ:**
  - `feat(attacker): implement tcp syn flood using scapy`
  - `feat(target-app): add login endpoint with jwt authentication`
  - `docs(api): document telemetry websocket event format`

### Bước 4: Đẩy nhánh lên GitHub
```bash
git push -u origin feature/t1-syn-flood-module
```

### Bước 5: Mở Pull Request vào `develop`
1. Vào GitHub repo, chọn:
   - **Base branch:** `develop`
   - **Compare branch:** Nhánh công việc của bạn (ví dụ `feature/t1-syn-flood-module`).
2. Điền tiêu đề PR theo Conventional Commits (ví dụ: `feat(attacker): add syn flood module`).
3. Điền mô tả: Mã task (ví dụ: `Task T1-TV2`), nội dung thay đổi, cách chạy thử nghiệm.
4. Chờ GitHub Action kiểm tra tiêu đề và nhờ ít nhất 1 thành viên review.
5. Sau khi được duyệt, bấm **Squash and merge**.

### Bước 6: Dọn dẹp nhánh và đồng bộ
```bash
# Xóa nhánh local sau khi đã merge
git checkout develop
git pull origin develop
git branch -d feature/t1-syn-flood-module
```

---

## 4. Quy chuẩn nghiệm thu & Release

1. **Nhánh `release/*`:**
   - Được tạo từ `develop` khi hoàn thành một Milestone lớn (ví dụ cuối Milestone 3 hoặc Milestone 6).
   - Chỉ nhận sửa lỗi phát hành (bug fixes), cập nhật số phiên bản và tài liệu.
   - Sau khi hội đồng/giảng viên nghiệm thu mới được merge vào `main` (bằng **Merge commit**) và gắn tag phiên bản (ví dụ: `v1.0.0`).
2. **Đồng bộ ngược về `develop`:**
   - Ngay sau khi merge vào `main`, phải tạo nhánh `sync/*` từ `main` để merge lại vào `develop` nhằm đảm bảo các bản vá trong release không bị thất lạc.

---

## 5. Quy định an toàn mã nguồn

* **Tuyệt đối không commit:**
  - Secret, API keys, JWT secret key nhạy cảm (dùng file `.env` local, tham chiếu mẫu qua [.env.example](.env.example)).
  - Database local, file log (`*.log`), file bắt gói tin dung lượng lớn (`*.pcap`).
  - Thư mục build (`dist/`, `build/`, `node_modules/`, `__pycache__/`).
* **Tính tái hiện:**
  - Khi thêm thư viện mới, bắt buộc commit lockfile (`package-lock.json`, `poetry.lock` hoặc `requirements.txt`).
  - Ghi rõ lệnh chạy, test trong tài liệu hoặc PR description.
