/**
 * Telemetry Log Schemas & Types
 * Quy định định dạng bản tin Telemetry từ Target App / Agents gửi về God-View Node (172.20.0.99)
 */

/**
 * Các phương thức HTTP hợp lệ
 */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'HEAD' | (string & {});

/**
 * Các nhãn phân loại tấn công định danh trong các kịch bản PBL4
 */
export type AttackType =
  | 'NORMAL'
  | 'BRUTE_FORCE'
  | 'PATH_TRAVERSAL'
  | 'COMMAND_INJECTION'
  | 'SQL_INJECTION'
  | 'HEAVY_DOS'
  | 'SYN_FLOOD'
  | 'RST_INJECTION'
  | 'ARP_SPOOF'
  | (string & {});

/**
 * Hành động xử lý của các lớp phòng thủ (L1/L2/L3)
 */
export type DefenseAction = 'allowed' | 'blocked' | 'rate_limited' | 'sanitized' | 'monitored' | (string & {});

/**
 * Tóm tắt dữ liệu payload của request/response
 * Đảm bảo ghi nhận đủ thông tin phát hiện tấn công nhưng không làm quá tải băng thông truyền về God-View
 */
export interface PayloadSummary {
  /** Query params dạng object hoặc string raw query */
  query?: Record<string, unknown> | string;

  /** Trích xuất nội dung body (đã che hoặc cắt ngắn nếu quá dài) */
  body_preview?: string | Record<string, unknown>;

  /** Header liên quan như Content-Type, Authorization preview, User-Agent */
  headers?: Record<string, string>;

  /** URL route params (ví dụ: { id: "123" }) */
  params?: Record<string, unknown>;

  /** MIME type của payload (application/json, multipart/form-data, ...) */
  content_type?: string;

  /** Kích thước byte của payload */
  content_length?: number;

  /** Cờ đánh dấu body đã bị cắt ngắn do vượt quá giới hạn ký tự */
  truncated?: boolean;

  /** Cờ đánh dấu payload có chứa dữ liệu nhạy cảm cần ẩn */
  has_credentials?: boolean;

  /** Dấu hiệu nghi vấn được phát hiện sơ bộ tại middleware (ví dụ: shell chars ';', '|', '../') */
  detected_patterns?: string[];

  /** Cho phép các trường mở rộng linh hoạt */
  [key: string]: unknown;
}

/**
 * Cấu trúc bản tin Telemetry Log gửi về God-View
 * Đáp ứng đầy đủ các trường yêu cầu:
 * - timestamp: Thời điểm phát sinh sự kiện (ISO 8601 string hoặc unix ms)
 * - method: HTTP Method (GET, POST, ...)
 * - endpoint: URI/Path được gọi (ví dụ: /api/v1/login, /api/v1/resources/download)
 * - status_code: Mã phản hồi HTTP (200, 401, 403, 500, ...)
 * - response_time: Thời gian xử lý request (tính bằng milliseconds)
 * - client_ip: Địa chỉ IP của client gửi request (ví dụ: 172.20.0.10, 172.20.0.66)
 * - payload_summary: Bản tóm tắt tham số hoặc payload của request
 */
export interface TelemetryLog {
  /** Thời gian ghi nhận sự kiện (ISO 8601 string: '2026-10-29T09:00:00.000Z' hoặc Unix timestamp ms) */
  timestamp: string | number;

  /** Phương thức HTTP của yêu cầu */
  method: HttpMethod;

  /** Đường dẫn endpoint được gọi */
  endpoint: string;

  /** HTTP Status Code phản hồi */
  status_code: number;

  /** Thời gian phản hồi request (ms) */
  response_time: number;

  /** Địa chỉ IP của máy khách gửi yêu cầu */
  client_ip: string;

  /** Tóm tắt dữ liệu payload (body preview, query params, độ dài, ...) */
  payload_summary: PayloadSummary | string;

  // --- Các trường mở rộng hữu ích cho hệ thống Giám sát God-View ---
  /** Mã định danh duy nhất cho log entry hoặc trace ID (UUID v4) */
  id?: string;

  /** IP của node Server tiếp nhận request (mặc định: 172.20.0.20) */
  server_ip?: string;

  /** User-Agent của client */
  user_agent?: string;

  /** Thông tin user đã đăng nhập nếu có */
  user_id?: string | number;
  username?: string;

  /** Thông điệp lỗi nếu status_code >= 400 */
  error_message?: string;

  /** Cờ cảnh báo request bất thường (dấu hiệu tấn công) */
  is_suspicious?: boolean;

  /** Nhãn phân loại tấn công (phục vụ hiển thị cảnh báo đồ họa trên God-View Dashboard) */
  attack_tag?: AttackType;

  /** Hành động phòng thủ đã áp dụng đối với request này */
  defense_action?: DefenseAction;

  /** Dữ liệu tùy biến mở rộng khác */
  metadata?: Record<string, unknown>;
}

/**
 * Định dạng bản tin đóng gói qua WebSocket stream lên God-View Dashboard
 */
export interface TelemetryStreamMessage<T = TelemetryLog> {
  event: 'telemetry:log' | 'telemetry:alert' | 'telemetry:batch';
  node: 'target-server' | 'client' | 'hacker';
  data: T;
  sent_at: string | number;
}

// ==========================================
// Type Guards (Kiểm tra kiểu lúc runtime)
// ==========================================

/**
 * Type guard kiểm tra đối tượng có phải TelemetryLog hợp lệ không
 */
export function isTelemetryLog(obj: unknown): obj is TelemetryLog {
  if (typeof obj !== 'object' || obj === null) return false;
  const log = obj as Record<string, unknown>;
  return (
    (typeof log.timestamp === 'string' || typeof log.timestamp === 'number') &&
    typeof log.method === 'string' &&
    typeof log.endpoint === 'string' &&
    typeof log.status_code === 'number' &&
    typeof log.response_time === 'number' &&
    typeof log.client_ip === 'string' &&
    (typeof log.payload_summary === 'object' || typeof log.payload_summary === 'string')
  );
}
