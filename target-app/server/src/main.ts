import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import fs from 'fs';
import path from 'path';
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

  // 3. Khởi tạo tài liệu tương tác OpenAPI / Swagger UI
  const swaggerConfig = new DocumentBuilder()
    .setTitle('ElectroShop Target Server API & Defense Testbed')
    .setDescription(
      'Hệ sinh thái API Backend NestJS cho ứng dụng thương mại điện tử ElectroShop và môi trường thử nghiệm phòng thủ mạng L3 (PBL4).',
    )
    .setVersion('1.0.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'Authorization',
        description:
          'Nhập Access Token JWT (thời hạn 30 ngày) nhận được từ API đăng nhập',
        in: 'header',
      },
      'JWT-auth',
    )
    .addTag(
      'Authentication',
      'Xác thực tài khoản, khai thác/chặn SQL Injection và cấp phát JWT',
    )
    .addTag(
      'Products',
      'Quản lý linh kiện, danh mục và bộ lọc thông số kỹ thuật',
    )
    .addTag('Cart', 'Quản lý giỏ hàng và đồng bộ badge Navbar [2]')
    .addTag('Documents', 'Tài liệu kỹ thuật Datasheets và Blueprint tuyệt mật')
    .addTag(
      'Defense',
      'Điều khiển Khiên L3 (Master Toggle, Anti-SQLi, Rate Limit, Sanitization)',
    )
    .addTag('Reports', 'Mô phỏng tác vụ CPU nặng phục vụ kịch bản L7 DoS')
    .addTag('Files', 'Tải tài liệu và mô phỏng tấn công Path Traversal')
    .addTag('System', 'Kiểm tra trạng thái máy chủ (health, ping latency)')
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('api/docs', app, document, {
    customSiteTitle: 'ElectroShop API Docs - PBL4',
    swaggerOptions: {
      persistAuthorization: true,
    },
  });

  // 4. Tự động xuất file openapi.json sang thư mục docs/api/target-server/
  try {
    const docsApiDir = path.resolve(
      process.cwd(),
      '../../docs/api/target-server',
    );
    if (fs.existsSync(docsApiDir)) {
      fs.writeFileSync(
        path.join(docsApiDir, 'openapi.json'),
        JSON.stringify(document, null, 2),
      );
    }
  } catch {
    // Bỏ qua lỗi nếu không tìm thấy thư mục docs
  }

  // 5. Khởi động server tại cổng cấu hình
  const port = envConfig.port;
  await app.listen(port);
  console.log(` Target Server is running on: http://localhost:${port}/api`);
  console.log(` Interactive Swagger UI at: http://localhost:${port}/api/docs`);
}
bootstrap();
