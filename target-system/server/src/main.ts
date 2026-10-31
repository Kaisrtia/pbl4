import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { envConfig } from './config/env.config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // 1. Cấu hình CORS từ biến môi trường (mặc định '*' hoặc danh sách domain phân tách bằng dấu phẩy)
  const corsOrigin = envConfig.corsOrigin.includes(',')
    ? envConfig.corsOrigin.split(',').map((item) => item.trim())
    : envConfig.corsOrigin;

  app.enableCors({
    origin: corsOrigin,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
  });

  // 2. Định tuyến API theo chuẩn /api/...
  app.setGlobalPrefix('api');

  // 3. Khởi động server tại cổng cấu hình
  const port = envConfig.port;
  await app.listen(port);
  console.log(` Target Server is running on: http://localhost:${port}/api`);
}
bootstrap();
