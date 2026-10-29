import { Router, Request, Response } from 'express';
import { config } from '../config/env';
import { db } from '../db/database';

export const defenseRouter = Router();

/**
 * GET /api/health
 * Kiểm tra trạng thái máy chủ Target App
 */
defenseRouter.get('/health', (req: Request, res: Response) => {
  res.status(200).json({
    status: 'ONLINE',
    service: 'Target Web App (Store & L7 Vulnerabilities)',
    node_ip: config.serverIp,
    defense_l3_app: config.defenseL3App,
    timestamp: new Date().toISOString(),
  });
});

/**
 * GET /api/defense/status
 * Xem trạng thái khiên chắn tầng ứng dụng (L3)
 */
defenseRouter.get('/defense/status', (req: Request, res: Response) => {
  res.status(200).json({
    layer: 'L3_APPLICATION',
    defense_enabled: config.defenseL3App,
    description: config.defenseL3App
      ? 'Khiên chắn L3 ĐANG BẬT: Đã kích hoạt Parameterized Queries và Input Sanitization (Chặn SQLi)'
      : 'Khiên chắn L3 ĐANG TẮT: Các endpoint đang mở lỗ hổng (Vulnerable to SQLi)',
  });
});

/**
 * POST /api/defense/toggle
 * Bật/tắt nhanh khiên chắn L3 phục vụ kịch bản demo đối sánh trước/sau khi phòng thủ
 */
defenseRouter.post('/defense/toggle', (req: Request, res: Response) => {
  const { enabled } = req.body;
  if (typeof enabled === 'boolean') {
    config.defenseL3App = enabled;
  } else {
    config.defenseL3App = !config.defenseL3App;
  }

  res.status(200).json({
    success: true,
    defense_l3_app: config.defenseL3App,
    message: `Đã ${config.defenseL3App ? 'BẬT' : 'TẮT'} khiên chắn phòng thủ Lớp 3 (Application Layer).`,
  });
});

/**
 * POST /api/database/reset
 * Tái tạo lại dữ liệu database ban đầu
 */
defenseRouter.post('/database/reset', (req: Request, res: Response) => {
  db.resetDatabase();
  res.status(200).json({
    success: true,
    message: 'Đã khôi phục cơ sở dữ liệu về trạng thái mẫu ban đầu.',
  });
});
