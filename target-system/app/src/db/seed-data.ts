import { User, ResourceItem } from '@shared/schemas';

export interface SeedUser extends User {
  password: string; // Mật khẩu plaintext trong lab demo để kiểm thử xác thực và SQLi
}

/**
 * Danh sách người dùng mẫu có sẵn trong hệ thống Target App
 */
export const SEED_USERS: SeedUser[] = [
  {
    id: 1,
    username: 'admin',
    password: 'adminPassword2026!',
    email: 'admin@target-system.local',
    role: 'admin',
    fullName: 'System Administrator',
    isActive: true,
    createdAt: '2026-01-01T00:00:00.000Z',
  },
  {
    id: 2,
    username: 'victim',
    password: 'victimPassword123',
    email: 'victim@target-system.local',
    role: 'user',
    fullName: 'Normal Victim User',
    isActive: true,
    createdAt: '2026-02-15T08:30:00.000Z',
  },
  {
    id: 3,
    username: 'alice',
    password: 'aliceSecretPassword',
    email: 'alice@target-system.local',
    role: 'user',
    fullName: 'Alice Nguyen',
    isActive: true,
    createdAt: '2026-03-10T09:15:00.000Z',
  },
  {
    id: 4,
    username: 'guest',
    password: 'guestPassword',
    email: 'guest@target-system.local',
    role: 'guest',
    fullName: 'Guest Observer',
    isActive: true,
    createdAt: '2026-04-01T10:00:00.000Z',
  },
];

/**
 * Danh sách tài nguyên mẫu (gồm tài nguyên mật, file tải về và sản phẩm Web Store)
 */
export const SEED_RESOURCES: ResourceItem[] = [
  {
    id: 'res-001',
    name: 'Tài liệu Ngân sách Quý 1 & 2 (Confidential)',
    description: 'Báo cáo chi tiết phân bổ ngân sách nội bộ và lương thưởng ban giám đốc năm 2026.',
    category: 'financial',
    fileName: 'q1_financial_confidential.pdf',
    filePath: '/data/resources/financial/q1_financial_confidential.pdf',
    fileSize: 450280,
    mimeType: 'application/pdf',
    downloadUrl: '/api/resources/res-001/download',
    isPublic: false,
    createdBy: 1,
    createdAt: '2026-01-15T09:00:00.000Z',
    metadata: {
      classification: 'TOP_SECRET',
      department: 'Finance',
    },
  },
  {
    id: 'res-002',
    name: 'Bản lưu trữ SSH Private Keys & Firewall Rules',
    description: 'Khóa SSH truy cập root máy chủ 172.20.0.20 và cấu hình iptables dự phòng.',
    category: 'security',
    fileName: 'server_ssh_keys_backup.tar.gz',
    filePath: '/data/resources/security/server_ssh_keys_backup.tar.gz',
    fileSize: 18240,
    mimeType: 'application/gzip',
    downloadUrl: '/api/resources/res-002/download',
    isPublic: false,
    createdBy: 1,
    createdAt: '2026-02-01T14:30:00.000Z',
    metadata: {
      classification: 'CRITICAL',
      department: 'DevOps',
    },
  },
  {
    id: 'res-003',
    name: 'Bản sao lưu Dữ liệu Khách hàng (PII Database Dump)',
    description: 'Dữ liệu thông tin cá nhân khách hàng, số điện thoại, mật khẩu mã hóa và mã thẻ.',
    category: 'database',
    fileName: 'customer_pii_dump_2026.sql',
    filePath: '/data/resources/database/customer_pii_dump_2026.sql',
    fileSize: 1204850,
    mimeType: 'application/sql',
    downloadUrl: '/api/resources/res-003/download',
    isPublic: false,
    createdBy: 1,
    createdAt: '2026-02-20T11:00:00.000Z',
    metadata: {
      classification: 'RESTRICTED',
      department: 'DatabaseAdmin',
    },
  },
  {
    id: 'res-004',
    name: 'Danh mục Sản phẩm Công khai Web Store',
    description: 'Danh sách sản phẩm phần mềm, thiết bị mạng và dịch vụ tư vấn bảo mật đang bán.',
    category: 'store',
    price: 499.99,
    stock: 50,
    isPublic: true,
    createdBy: 2,
    createdAt: '2026-03-01T08:00:00.000Z',
    metadata: {
      classification: 'PUBLIC',
      sku: 'SKU-SEC-BUNDLE-01',
    },
  },
  {
    id: 'res-005',
    name: 'Sổ tay Kỹ thuật Phòng thủ 3 Lớp (Defense Runbook)',
    description: 'Chi tiết cấu hình static ARP, sysctl syncookies và middleware rate limiting.',
    category: 'documentation',
    fileName: 'defense_depth_runbook.md',
    filePath: '/data/resources/docs/defense_depth_runbook.md',
    fileSize: 84200,
    mimeType: 'text/markdown',
    downloadUrl: '/api/resources/res-005/download',
    isPublic: false,
    createdBy: 1,
    createdAt: '2026-03-15T16:45:00.000Z',
    metadata: {
      classification: 'INTERNAL_ONLY',
      department: 'CyberSecurity',
    },
  },
];
