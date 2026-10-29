import path from 'path';
import dotenv from 'dotenv';

// Đọc file .env từ thư mục gốc hoặc local
const rootEnvPath = path.resolve(__dirname, '../../../../.env');
const localEnvPath = path.resolve(__dirname, '../../.env');

dotenv.config({ path: rootEnvPath });
dotenv.config({ path: localEnvPath });

export const config = {
  // Cổng server God-View (ưu tiên cổng 4000 theo yêu cầu)
  port: parseInt(process.env.PORT || process.env.GODVIEW_PORT || '4000', 10),
  host: process.env.HOST || '0.0.0.0',
  nodeEnv: process.env.NODE_ENV || 'development',

  // URL kết nối tới Target App (mặc định cổng 8000 của Target Server)
  targetAppUrl: process.env.TARGET_APP_URL || `http://${process.env.SERVER_IP || '127.0.0.1'}:${process.env.SERVER_PORT || '8000'}`,

  // Kích thước tối đa của bộ đệm Ring Buffer trong RAM
  maxBufferSize: 300,

  // Đường dẫn tới thư mục frontend tĩnh
  clientDir: path.resolve(__dirname, '../../client'),
};
