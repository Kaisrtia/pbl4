import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // 1. Cho phép Next.js và God-View gọi API mà không bị chặn CORS
  app.enableCors({
    origin: '*',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
  });

  // 2. Định tuyến API theo chuẩn /api/...
  app.setGlobalPrefix('api');

  // 3. Chạy tại cổng 8000 (Target Server chuẩn trong topo mạng)
  const port = process.env.PORT ?? 8000;
  await app.listen(port);
  console.log(` Target Server is running on: http://localhost:${port}/api`);
}
bootstrap();