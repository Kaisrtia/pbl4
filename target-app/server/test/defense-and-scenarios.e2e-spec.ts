import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import jwt from 'jsonwebtoken';
import { AppModule } from '../src/app.module';
import { DatabaseService } from '../src/database/database.service';
import {
  DEFENSE_SERVICE_TOKEN,
  IDefenseService,
} from '../src/modules/defense/defense.constants';

describe('Target System E2E: Defense Engine & Lab Scenarios', () => {
  let app: INestApplication<App>;
  let defenseService: IDefenseService;
  let dbService: DatabaseService;
  let adminJwtToken: string;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api');
    await app.init();

    defenseService = moduleFixture.get<IDefenseService>(DEFENSE_SERVICE_TOKEN);
    dbService = moduleFixture.get<DatabaseService>(DatabaseService);
    dbService.resetCart();
  });

  afterAll(async () => {
    dbService.resetCart();
    await app.close();
  });

  it('1. GET /api/system/health - should return online status and initial defense flags', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/system/health')
      .expect(200);
    expect(res.body.status).toBe('online');
    expect(res.body.defense_status).toBeDefined();
  });

  it('2. GET /api/system/ping - should return pong and measure latency', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/system/ping?t=' + (Date.now() - 50))
      .expect(200);
    expect(res.body.message).toBe('pong');
    expect(res.body.latency_ms).toBeGreaterThanOrEqual(0);
  });

  it('3. POST /api/auth/login - SQL Injection BYPASS when L3 shield is OFF', async () => {
    defenseService.setFlags({ l3_master: false, anti_sqli: false });

    // Payload SQLi bypass login
    const res = await request(app.getHttpServer())
      .post('/api/auth/login')
      .send({ username: "admin' --", password: 'any_dummy_password' })
      .expect(200);

    expect(res.body.status).toBe('success');
    expect(res.body.user.username).toBe('admin');
    expect(res.body.sqli_bypassed).toBe(true);
    expect(res.body.defense_mode).toBe('VULNERABLE_RAW_SQL');
  });

  it('4. POST /api/defense/toggle - Toggle L3 Master Shield ON', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/defense/toggle')
      .send({})
      .expect(200);
    expect(res.body.status).toBe('success');
    expect(res.body.current_state.l3_master).toBe(true);
    expect(res.body.current_state.anti_sqli).toBe(true);
  });

  it('5. POST /api/auth/login - SQL Injection BLOCKED when L3 shield is ON', async () => {
    defenseService.setFlags({ l3_master: true, anti_sqli: true });

    // Cùng payload đó nhưng phải bị chặn bằng mã 401
    await request(app.getHttpServer())
      .post('/api/auth/login')
      .send({ username: "admin' --", password: 'any_dummy_password' })
      .expect(401);
  });

  it('6. POST /api/auth/login - Standard login SUCCESS with valid credentials & 30-day JWT', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'adminPassword2026!' })
      .expect(200);

    expect(res.body.status).toBe('success');
    expect(res.body.user.username).toBe('admin');
    expect(res.body.access_token).toBeDefined();

    adminJwtToken = res.body.access_token;

    // Giải mã JWT để kiểm tra thời hạn 30 ngày (30 * 24 * 3600 = 2,592,000 giây)
    const decoded: any = jwt.decode(adminJwtToken);
    expect(decoded).toBeDefined();
    expect(decoded.username).toBe('admin');
    expect(decoded.exp).toBeDefined();
    expect(decoded.iat).toBeDefined();

    const durationSeconds = decoded.exp - decoded.iat;
    const thirtyDaysInSeconds = 30 * 24 * 3600;
    expect(durationSeconds).toBe(thirtyDaysInSeconds);
  });

  it('7. GET /api/reports/analytics - Heavy CPU workload execution', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/reports/analytics?iterations=5000')
      .expect(200);

    expect(res.body.status).toBe('completed');
    expect(res.body.computation_time_ms).toBeGreaterThanOrEqual(0);
  });

  it('8. GET /api/files/download - Path Traversal BLOCKED when L3 shield is ON', async () => {
    defenseService.setFlags({ l3_master: true, input_sanitization: true });

    // Payload Path Traversal
    const res = await request(app.getHttpServer())
      .get('/api/files/download?name=../../etc/passwd')
      .expect(400);

    expect(res.body.shield).toBe('L3_INPUT_SANITIZATION_ACTIVE');
  });

  it('9. GET /api/products/categories - Return category pills with product counts (All: 6, MCU: 2, Sensor: 2, Power: 2)', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/products/categories')
      .expect(200);

    expect(res.body.status).toBe('success');
    expect(res.body.data.total_products).toBe(6);
    expect(res.body.data.categories.length).toBe(3);

    const mcu = res.body.data.categories.find(
      (c: any) => c.slug === 'vi-dieu-khien',
    );
    expect(mcu).toBeDefined();
    expect(mcu.count).toBe(2);
  });

  it('10. GET /api/products - Return all 6 products with specs array', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/products')
      .expect(200);

    expect(res.body.status).toBe('success');
    expect(res.body.total).toBe(6);
    expect(Array.isArray(res.body.data[0].specs)).toBe(true);
  });

  it('11. GET /api/products?category=vi-dieu-khien - Filter products by category slug', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/products?category=vi-dieu-khien')
      .expect(200);

    expect(res.body.status).toBe('success');
    expect(res.body.total).toBe(2);
    expect(
      res.body.data.every((p: any) => p.category_slug === 'vi-dieu-khien'),
    ).toBe(true);
  });

  it('12. GET /api/products/sku/MCU-ARD-R4 - Get product details by SKU', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/products/sku/MCU-ARD-R4')
      .expect(200);

    expect(res.body.status).toBe('success');
    expect(res.body.data.name).toBe('Arduino Uno R4 WiFi');
    expect(res.body.data.price).toBe(320000);
    expect(res.body.data.brand).toBe('Arduino SA Official');
    expect(res.body.data.specs).toContain('Cortex-M4');
  });

  it('13. GET /api/cart - Return initial seeded cart matching UI badge (2 items, 345,000 VND)', async () => {
    const res = await request(app.getHttpServer()).get('/api/cart').expect(200);

    expect(res.body.status).toBe('success');
    expect(res.body.data.total_items).toBe(2);
    expect(res.body.data.total_price).toBe(345000);
    expect(res.body.data.items.length).toBe(2);
    expect(res.body.data.items[0].name).toBe('Arduino Uno R4 WiFi');
  });

  it('14. POST /api/cart - Add a new product to cart and increase badge count', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/cart')
      .send({ productId: 2, quantity: 1 })
      .expect(201);

    expect(res.body.status).toBe('success');
    expect(res.body.data.total_items).toBe(3);
    const esp32 = res.body.data.items.find((i: any) => i.product_id === 2);
    expect(esp32).toBeDefined();
    expect(esp32.name).toBe('ESP32-WROOM-32D DevBoard');
  });

  it('15. PATCH /api/cart/items/:id - Update cart item quantity', async () => {
    // Lấy id của món đầu tiên
    const currentCart = await request(app.getHttpServer()).get('/api/cart');
    const firstItem = currentCart.body.data.items[0];

    const res = await request(app.getHttpServer())
      .patch(`/api/cart/items/${firstItem.id}`)
      .send({ quantity: 3 })
      .expect(200);

    expect(res.body.status).toBe('success');
    const updatedItem = res.body.data.items.find(
      (i: any) => i.id === firstItem.id,
    );
    expect(updatedItem.quantity).toBe(3);
  });

  it('16. DELETE /api/cart/items/:id - Remove item from cart', async () => {
    const currentCart = await request(app.getHttpServer()).get('/api/cart');
    const esp32Item = currentCart.body.data.items.find(
      (i: any) => i.product_id === 2,
    );

    const res = await request(app.getHttpServer())
      .delete(`/api/cart/items/${esp32Item.id}`)
      .expect(200);

    expect(res.body.status).toBe('success');
    expect(res.body.data.items.some((i: any) => i.product_id === 2)).toBe(
      false,
    );
  });

  it('17. GET /api/documents - Return public documents list (4 datasheets, confidential hidden)', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/documents')
      .expect(200);

    expect(res.body.status).toBe('success');
    expect(res.body.total).toBe(4);
    expect(res.body.data.every((d: any) => d.is_confidential === false)).toBe(
      true,
    );
  });

  it('18. GET /api/documents?include_confidential=true - Return all documents including confidential', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/documents?include_confidential=true')
      .expect(200);

    expect(res.body.status).toBe('success');
    expect(res.body.total).toBe(5);
    const confidentialDoc = res.body.data.find(
      (d: any) => d.is_confidential === true,
    );
    expect(confidentialDoc).toBeDefined();
    expect(confidentialDoc.file_name).toBe(
      'rd-confidential-hardware-blueprint.pdf',
    );
  });

  it('19. GET /api/documents/5/download - Confidential download BLOCKED when L3 shield is ON', async () => {
    defenseService.setFlags({ l3_master: true, input_sanitization: true });

    const res = await request(app.getHttpServer())
      .get('/api/documents/5/download')
      .expect(403);

    expect(res.body.shield).toBe('L3_CONFIDENTIAL_POLICY_ACTIVE');
  });

  it('20. GET /api/documents/5/download - Confidential download LEAKED when L3 shield is OFF', async () => {
    defenseService.setFlags({ l3_master: false, input_sanitization: false });

    const res = await request(app.getHttpServer())
      .get('/api/documents/5/download')
      .expect(200);

    expect(res.headers['x-security-warning']).toBe(
      'Confidential-Document-Exfiltrated-Shield-Off',
    );
    const fileContent =
      res.text || (res.body ? res.body.toString('utf-8') : '');
    expect(fileContent).toContain(
      'FLAG{PBL4_PATH_TRAVERSAL_AND_CONFIDENTIAL_DOC_LEAKED}',
    );
  });
});
