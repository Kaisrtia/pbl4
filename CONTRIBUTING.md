## Nhánh và commit

| Nhánh | Tạo từ | PR vào | Cách merge |
| --- | --- | --- | --- |
| `feature/*`, `fix/*`, `docs/*`, `chore/*`, `refactor/*`, `test/*` | `develop` | `develop` | Squash |
| `release/*` | `develop` | `main` | Merge commit |
| `hotfix/*` | `main` | `main` | Merge commit |
| `sync/*` | `main` sau release/hotfix | `develop` | Merge commit |

PR #1 thiết lập ban đầu vào `main` là ngoại lệ. Không commit trực tiếp lên `main`/`develop`, force push nhánh chung hoặc xóa hai nhánh này. Chỉ rebase nhánh cá nhân khi người cùng làm đồng ý.

Commit và tiêu đề PR theo Conventional Commits, ví dụ `feat(attacker): add arp spoofing module`. Mỗi commit tập trung một việc; breaking change dùng `!` và giải thích trong PR.

Release chỉ nhận sửa lỗi và việc chuẩn bị phát hành. Sau nghiệm thu mới gắn tag; đồng bộ về `develop` qua PR `sync/*`. Chỉ xóa nhánh công việc khi đã merge và không còn phụ thuộc.

## Khi đưa mã vào repo

Ghi phiên bản công cụ, lệnh cài/chạy/test; commit lockfile. Migration cần cách áp dụng và hoàn nguyên. Phần chưa kiểm tra phải nêu lý do.

Không commit secret, dữ liệu học viên, ghi âm cá nhân, database production hoặc file sinh ra khi build. Dùng cấu hình mẫu với giá trị giả. Chỉ sử dụng nội dung có quyền sử dụng; không tự công khai hay cấp phép repo thay nhóm. Báo riêng lỗ hổng hoặc secret bị lộ cho người phụ trách.

Mẫu/cấu hình quản lý repo đã chuyển ra hồ sơ local bên ngoài; việc dọn tệp local không thay đổi cài đặt trên GitHub.