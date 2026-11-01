import dotenv from 'dotenv';
import path from 'path';

// Nạp file .env từ thư mục server nếu có
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

export const envConfig = {
  // 1. Mạng & Máy chủ
  port: parseInt(process.env.PORT || '8000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  corsOrigin: process.env.CORS_ORIGIN || '*',

  // 2. Xác thực JWT
  jwtSecret: process.env.JWT_SECRET || 'pbl4_devsec_super_secret_jwt_key_2026!',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '30d',

  // 3. Cơ sở dữ liệu & Tập tin
  databasePath: process.env.DATABASE_PATH || './data/devsec.sqlite',
  dbBusyTimeoutMs: parseInt(process.env.DB_BUSY_TIMEOUT_MS || '5000', 10),
  publicFilesDir: process.env.PUBLIC_FILES_DIR || './data/public',

  // 4. Khiên L3 (Trạng thái khởi tạo)
  initialDefense: {
    l3Master: process.env.DEFENSE_L3_ENABLED === 'true',
    antiSqli: process.env.DEFENSE_ANTI_SQLI === 'true',
    rateLimit: process.env.DEFENSE_RATE_LIMIT === 'true',
    inputSanitization: process.env.DEFENSE_INPUT_SANITIZATION === 'true',
  },

  // 5. Ngưỡng Rate Limiting
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '5000', 10),
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '10', 10),
  },

  // 6. God-View Telemetry Hub
  godviewTelemetryUrl:
    process.env.GODVIEW_TELEMETRY_URL || 'http://localhost:4000/api/telemetry',
  godviewTimeoutMs: parseInt(process.env.GODVIEW_TIMEOUT_MS || '1000', 10),
};
