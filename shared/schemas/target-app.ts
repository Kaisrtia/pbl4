/**
 * Target App Schemas & Types
 * Quy định các kiểu dữ liệu cho ứng dụng Target Web App (Store, Auth, Resources)
 */

/**
 * Phân quyền người dùng trong Target App
 */
export type UserRole = 'admin' | 'user' | 'guest';

/**
 * Thông tin định danh và tài khoản người dùng
 */
export interface User {
  id: string | number;
  username: string;
  email?: string;
  role: UserRole | string;
  fullName?: string;
  isActive?: boolean;
  createdAt?: string | Date;
  updatedAt?: string | Date;
}

/**
 * Bản tin yêu cầu đăng nhập (Login Request)
 */
export interface LoginRequest {
  username: string;
  password: string;
  rememberMe?: boolean;
}

/**
 * Bản tin phản hồi đăng nhập (Login Response)
 */
export interface LoginResponse {
  success: boolean;
  message?: string;
  token?: string;
  accessToken?: string;
  refreshToken?: string;
  expiresIn?: number; // Thời gian hết hạn tính bằng giây hoặc ms
  user?: Omit<User, 'password'>;
  error?: string;
}

/**
 * Mục tài nguyên (Resource item) của Web App (sản phẩm, file tải về, tài nguyên hệ thống)
 */
export interface ResourceItem {
  id: string | number;
  name: string;
  description?: string;
  category?: string;
  price?: number;
  stock?: number;
  
  // Thông tin file/tải về (phục vụ mô phỏng lỗ hổng Path Traversal / File Download)
  fileName?: string;
  filePath?: string;
  fileSize?: number;
  mimeType?: string;
  downloadUrl?: string;

  // Quyền truy cập & kiểm soát
  isPublic?: boolean;
  createdBy?: string | number;
  createdAt?: string | Date;
  updatedAt?: string | Date;

  // Metadata mở rộng (dành cho các kịch bản kiểm thử riêng)
  metadata?: Record<string, unknown>;
}

/**
 * DTO tạo mới tài nguyên
 */
export type CreateResourceDto = Omit<ResourceItem, 'id' | 'createdAt' | 'updatedAt'>;

/**
 * DTO cập nhật tài nguyên
 */
export type UpdateResourceDto = Partial<CreateResourceDto>;

// ==========================================
// Type Guards (Kiểm tra kiểu lúc runtime)
// ==========================================

/**
 * Type guard kiểm tra đối tượng có phải User hợp lệ không
 */
export function isUser(obj: unknown): obj is User {
  if (typeof obj !== 'object' || obj === null) return false;
  const user = obj as Record<string, unknown>;
  return (
    (typeof user.id === 'string' || typeof user.id === 'number') &&
    typeof user.username === 'string' &&
    (typeof user.role === 'string' || typeof user.role === 'undefined')
  );
}

/**
 * Type guard kiểm tra đối tượng có phải LoginRequest không
 */
export function isLoginRequest(obj: unknown): obj is LoginRequest {
  if (typeof obj !== 'object' || obj === null) return false;
  const req = obj as Record<string, unknown>;
  return typeof req.username === 'string' && typeof req.password === 'string';
}

/**
 * Type guard kiểm tra đối tượng có phải LoginResponse không
 */
export function isLoginResponse(obj: unknown): obj is LoginResponse {
  if (typeof obj !== 'object' || obj === null) return false;
  const res = obj as Record<string, unknown>;
  return typeof res.success === 'boolean';
}

/**
 * Type guard kiểm tra đối tượng có phải ResourceItem không
 */
export function isResourceItem(obj: unknown): obj is ResourceItem {
  if (typeof obj !== 'object' || obj === null) return false;
  const item = obj as Record<string, unknown>;
  return (
    (typeof item.id === 'string' || typeof item.id === 'number') &&
    typeof item.name === 'string'
  );
}
