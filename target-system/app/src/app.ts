import path from 'path';
import express, { Application, Request, Response } from 'express';
import cors from 'cors';
import { apiRouter } from './routes';
import { telemetryMiddleware } from './middleware/telemetry.middleware';
import { errorHandler } from './middleware/error.middleware';

export function createApp(): Application {
  const app: Application = express();

  // Middleware cơ bản
  app.use(cors());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Phục vụ giao diện tĩnh Storefront (public/index.html)
  const publicDir = path.resolve(__dirname, '../public');
  app.use(express.static(publicDir));

  // Middleware thu thập Telemetry Log gửi về God-View
  app.use(telemetryMiddleware);

  // Gắn các API endpoints chính
  app.use('/api', apiRouter);

  // API Info & Documentation index
  app.get('/api', (req: Request, res: Response) => {
    res.status(200).json({
      service: 'PBL4 Cyber Attack Simulation - Target Web Server',
      status: 'RUNNING',
      docs: {
        ping: 'GET /api/ping',
        download: 'GET /api/download',
        heavy_load: 'GET /api/heavy-load | POST /api/heavy',
        login: 'POST /api/login',
        resources: 'GET /api/resources (Protected)',
        health: 'GET /api/health',
        defense_status: 'GET /api/defense/status',
      },
    });
  });

  // Xử lý 404
  app.use((req: Request, res: Response) => {
    res.status(404).json({
      success: false,
      message: `Đường dẫn không tồn tại: ${req.method} ${req.originalUrl}`,
      error: 'NOT_FOUND',
    });
  });

  // Xử lý lỗi tập trung
  app.use(errorHandler);

  return app;
}

export const app = createApp();
