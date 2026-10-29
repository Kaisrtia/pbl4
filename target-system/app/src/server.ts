import { app } from './app';
import { config } from './config/env';

const server = app.listen(config.port, config.host, () => {
  console.log('====================================================');
  console.log(`[Target App] Máy chủ đang chạy tại: http://${config.host}:${config.port}`);
  console.log(`[Target App] IP Node dự kiến: ${config.serverIp}`);
  console.log(`[Target App] God-View URL: ${config.godViewUrl}`);
  console.log(`[Target App] Phòng thủ L3 (App Layer): ${config.defenseL3App ? 'ENABLED (Safe)' : 'DISABLED (Vulnerable to SQLi)'}`);
  console.log('====================================================');
  console.log('Các API chính sẵn sàng:');
  console.log(`  GET  http://${config.host}:${config.port}/api/ping`);
  console.log(`  GET  http://${config.host}:${config.port}/api/download`);
  console.log(`  GET  http://${config.host}:${config.port}/api/heavy-load | POST /api/heavy`);
  console.log(`  POST http://${config.host}:${config.port}/api/login`);
  console.log(`  GET  http://${config.host}:${config.port}/api/resources`);
  console.log(`  GET  http://${config.host}:${config.port}/api/health`);
  console.log('====================================================');
});

// Xử lý graceful shutdown
process.on('SIGTERM', () => {
  console.log('[Target App] Nhận tín hiệu SIGTERM, đang tắt máy chủ...');
  server.close(() => {
    console.log('[Target App] Máy chủ đã dừng an toàn.');
    process.exit(0);
  });
});
