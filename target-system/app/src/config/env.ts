import path from 'path';
import dotenv from 'dotenv';

// Tìm và nạp file .env từ thư mục gốc của dự án hoặc thư mục hiện tại
const rootEnvPath = path.resolve(__dirname, '../../../../.env');
const localEnvPath = path.resolve(__dirname, '../../.env');

dotenv.config({ path: rootEnvPath });
dotenv.config({ path: localEnvPath });

export const config = {
  port: parseInt(process.env.SERVER_PORT || '8000', 10),
  host: process.env.SERVER_HOST || '0.0.0.0',
  nodeEnv: process.env.NODE_ENV || 'development',
  serverIp: process.env.SERVER_IP || '172.20.0.20',
  godViewUrl: process.env.GODVIEW_URL || `http://${process.env.GODVIEW_IP || '172.20.0.99'}:${process.env.GODVIEW_BACKEND_PORT || '8080'}`,
  jwtSecret: process.env.JWT_SECRET || 'pbl4-cybersec-target-system-secret-key-2026',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '2h',
  
  // Trạng thái khiên chắn phòng thủ Lớp 3 (Application Layer)
  defenseL3App: process.env.DEFENSE_L3_APP === 'true',

  // Đường dẫn lưu file SQLite Database
  dbPath: process.env.DB_PATH || path.resolve(__dirname, '../../data/target_app.db'),

  // Bật/tắt gửi Telemetry trực tiếp về God-View qua HTTP/WebSocket
  telemetryEnabled: process.env.TELEMETRY_ENABLED !== 'false',
};
