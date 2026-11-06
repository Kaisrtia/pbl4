import {
  Injectable,
  OnModuleInit,
  OnModuleDestroy,
  Logger,
} from '@nestjs/common';
import { DatabaseSync } from 'node:sqlite';
import fs from 'fs';
import path from 'path';
import { envConfig } from '../config/env.config';

@Injectable()
export class DatabaseService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(DatabaseService.name);
  private db!: DatabaseSync;

  onModuleInit() {
    this.initDatabase();
    this.createTables();
    this.seedDefaultUsers();
    this.seedDefaultCategories();
    this.seedDefaultProducts();
    this.seedDefaultDocuments();
    this.seedDefaultCart();
  }

  onModuleDestroy() {
    if (this.db) {
      this.db.close();
      this.logger.log('Database connection closed.');
    }
  }

  private initDatabase() {
    const dbPath = envConfig.databasePath;

    if (dbPath !== ':memory:') {
      const dir = path.dirname(path.resolve(process.cwd(), dbPath));
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    }

    this.db = new DatabaseSync(dbPath);
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec(`PRAGMA busy_timeout = ${envConfig.dbBusyTimeoutMs};`);
    this.logger.log(
      `SQLite database connected at [${dbPath}] (WAL mode enabled)`,
    );
  }

  private createTables() {
    this.db.exec(`
      -- 1. Bảng tài khoản người dùng
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        full_name TEXT,
        email TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      -- 2. Bảng danh mục linh kiện (Vi điều khiển, Cảm biến, Module nguồn)
      CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        display_order INTEGER DEFAULT 0
      );

      -- 3. Bảng linh kiện / sản phẩm phần cứng (ElectroShop)
      CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category_id INTEGER NOT NULL,
        sku TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        brand TEXT NOT NULL,
        description TEXT NOT NULL,
        price INTEGER NOT NULL,
        stock INTEGER NOT NULL DEFAULT 0,
        image_url TEXT,
        specs_json TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (category_id) REFERENCES categories(id)
      );

      -- 4. Bảng tài liệu kỹ thuật / Datasheet (Phục vụ tải file & Path Traversal demo)
      CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER,
        title TEXT NOT NULL,
        file_name TEXT NOT NULL,
        file_size_kb INTEGER,
        is_confidential INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (product_id) REFERENCES products(id)
      );

      -- 5. Bảng giỏ hàng (Phục vụ số lượng 2 trên badge giỏ hàng của Navbar)
      CREATE TABLE IF NOT EXISTS cart_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        session_id TEXT,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (product_id) REFERENCES products(id)
      );

      -- 6. Bảng đơn hàng (Yêu cầu xác thực JWT khi thanh toán)
      CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_code TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        total_amount INTEGER NOT NULL,
        total_items INTEGER NOT NULL,
        shipping_address TEXT,
        status TEXT NOT NULL DEFAULT 'COMPLETED',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );

      -- 7. Bảng chi tiết đơn hàng
      CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        product_name TEXT NOT NULL,
        product_sku TEXT,
        price INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        subtotal INTEGER NOT NULL,
        FOREIGN KEY (order_id) REFERENCES orders(id)
      );
    `);
  }

  private seedDefaultUsers() {
    const countStatement = this.db.prepare(
      'SELECT COUNT(*) as count FROM users',
    );
    const result = countStatement.get() as { count: number };

    if (result && result.count === 0) {
      this.logger.log('Seeding initial lab users into database...');
      const insert = this.db.prepare(`
        INSERT INTO users (username, password, role, full_name, email)
        VALUES (?, ?, ?, ?, ?)
      `);

      const seedUsers = [
        [
          'admin',
          'adminPassword2026!',
          'admin',
          'System Administrator',
          'admin@devsec.pbl4',
        ],
        [
          'alice',
          'aliceSecretPassword',
          'user',
          'Alice Johnson',
          'alice@devsec.pbl4',
        ],
        [
          'victim',
          'victimPassword123',
          'user',
          'Lab Victim User',
          'victim@devsec.pbl4',
        ],
        [
          'guest',
          'guestPassword',
          'guest',
          'Guest Observer',
          'guest@devsec.pbl4',
        ],
      ];

      for (const user of seedUsers) {
        insert.run(...user);
      }
      this.logger.log('Default users successfully seeded.');
    }
  }

  private seedDefaultCategories() {
    const countStatement = this.db.prepare(
      'SELECT COUNT(*) as count FROM categories',
    );
    const result = countStatement.get() as { count: number };

    if (result && result.count === 0) {
      this.logger.log('Seeding default categories for ElectroShop...');
      const insert = this.db.prepare(`
        INSERT INTO categories (slug, name, description, display_order)
        VALUES (?, ?, ?, ?)
      `);

      const categories = [
        [
          'vi-dieu-khien',
          'Vi điều khiển',
          'Thiết bị vi xử lý, vi điều khiển và bo mạch phát triển IoT',
          1,
        ],
        [
          'cam-bien',
          'Cảm biến',
          'Cảm biến công nghiệp, đo khoảng cách, nhiệt độ và độ ẩm',
          2,
        ],
        [
          'module-nguon',
          'Module nguồn',
          'Mạch hạ áp, module nguồn và relay bảo vệ cách ly',
          3,
        ],
      ];

      for (const cat of categories) {
        insert.run(...cat);
      }
      this.logger.log('Default categories successfully seeded.');
    }
  }

  private seedDefaultProducts() {
    const countStatement = this.db.prepare(
      'SELECT COUNT(*) as count FROM products',
    );
    const result = countStatement.get() as { count: number };

    if (result && result.count === 0) {
      this.logger.log('Seeding 6 ElectroShop hardware products from design...');
      const insert = this.db.prepare(`
        INSERT INTO products (category_id, sku, name, brand, description, price, stock, image_url, specs_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const products = [
        [
          1,
          'MCU-ARD-R4',
          'Arduino Uno R4 WiFi',
          'Arduino SA Official',
          'Renesas RA4M1 32-bit ARM Cortex-M4 (48MHz) kèm module ESP32-S3 hỗ trợ WiFi 802.11 b/g/n & Bluetooth 5.0.',
          320000,
          48,
          '/images/products/arduino-uno-r4.png',
          JSON.stringify(['Cortex-M4', '5V Logic', 'WiFi / BLE']),
        ],
        [
          1,
          'MCU-ESP-32D',
          'ESP32-WROOM-32D DevBoard',
          'Espressif Systems',
          'Dual-core Xtensa 32-bit LX6 240MHz, 520KB SRAM, 4MB SPI Flash tích hợp, ăng-ten PCB trên bo tiện dụng.',
          95000,
          120,
          '/images/products/esp32-wroom-32d.png',
          JSON.stringify(['240MHz Dual-Core', '4MB Flash', 'NodeMCU 38P']),
        ],
        [
          2,
          'SEN-UC-SR04',
          'Cảm biến siêu âm HC-SR04',
          'ElecRobo Sensor',
          'Dải đo khoảng cách 2cm - 400cm, độ phân giải 0.3cm, góc đo 15 độ. Tương thích chuẩn 5V TTL cho Arduino, ESP.',
          25000,
          250,
          '/images/products/hc-sr04.png',
          JSON.stringify(['2cm - 400cm', '5V DC / 15mA', '40kHz Sonar']),
        ],
        [
          3,
          'PWR-LM-2596',
          'Module Nguồn Hạ Áp LM2596',
          'PowerTech Labs',
          'Điện áp vào 4V-40V DC, điện áp ra điều chỉnh 1.25V-37V DC. Dòng tải tối đa 3A, hiệu suất chuyển đổi lên tới 92%.',
          18000,
          85,
          '/images/products/lm2596.png',
          JSON.stringify(['In: 4-40V', 'Out: 1.25-37V', 'Imax: 3A']),
        ],
        [
          2,
          'SEN-DHT-22',
          'Cảm biến nhiệt ẩm DHT22 (AM2302)',
          'Aosong Electronics',
          'Độ chính xác cao: nhiệt độ -40°C đến 80°C (±0.5°C), độ ẩm 0-100% RH (±2% RH). Tín hiệu số Single-Bus chống nhiễu.',
          68000,
          64,
          '/images/products/dht22.png',
          JSON.stringify(['±0.5°C Acc', '0-100% RH', '3.3V - 6V']),
        ],
        [
          3,
          'MOD-RLY-4CH',
          'Module Relay 4 Kênh 5V Cách Ly Opto',
          'Songle Automation',
          'Đóng ngắt AC 250V 10A / DC 30V 10A. Cách ly quang Optocoupler chống nhiễu ngược bảo vệ vi điều khiển an toàn.',
          42000,
          92,
          '/images/products/relay-4ch.png',
          JSON.stringify(['4 Channels', '10A 250VAC', 'Opto PC817']),
        ],
      ];

      for (const p of products) {
        insert.run(...p);
      }
      this.logger.log('6 ElectroShop products successfully seeded.');
    }
  }

  private seedDefaultDocuments() {
    const countStatement = this.db.prepare(
      'SELECT COUNT(*) as count FROM documents',
    );
    const result = countStatement.get() as { count: number };

    if (result && result.count === 0) {
      this.logger.log(
        'Seeding technical datasheets & confidential documents...',
      );
      const insert = this.db.prepare(`
        INSERT INTO documents (product_id, title, file_name, file_size_kb, is_confidential)
        VALUES (?, ?, ?, ?, ?)
      `);

      const documents = [
        [
          1,
          'Datasheet Arduino Uno R4 WiFi (PDF)',
          'arduino-uno-r4-datasheet.pdf',
          1420,
          0,
        ],
        [
          2,
          'ESP32 Technical Reference Manual v4.8 (PDF)',
          'esp32-technical-reference.pdf',
          2850,
          0,
        ],
        [
          3,
          'Sơ đồ chân & Hướng dẫn kết nối HC-SR04',
          'hc-sr04-ultrasonic-pinout.pdf',
          480,
          0,
        ],
        [
          4,
          'LM2596 Step-Down Converter Circuit Schematics',
          'lm2596-buck-schematic.pdf',
          620,
          0,
        ],
        [
          null,
          'TOP SECRET: R&D Hardware Architecture Blueprint 2026',
          'rd-confidential-hardware-blueprint.pdf',
          5120,
          1,
        ],
      ];

      for (const doc of documents) {
        insert.run(...doc);
      }
      this.logger.log('Technical documents successfully seeded.');
    }
  }

  /**
   * Khôi phục giỏ hàng mẫu về trạng thái ban đầu (dành cho kiểm thử hoặc reset lab)
   */
  resetCart(): void {
    this.db.exec('DELETE FROM cart_items;');
    this.seedDefaultCart();
  }

  /**
   * Khôi phục đơn hàng (dành cho kiểm thử E2E)
   */
  resetOrders(): void {
    this.db.exec('DELETE FROM order_items;');
    this.db.exec('DELETE FROM orders;');
  }

  private seedDefaultCart() {
    const countStatement = this.db.prepare(
      'SELECT COUNT(*) as count FROM cart_items',
    );
    const result = countStatement.get() as { count: number };

    if (result && result.count === 0) {
      this.logger.log(
        'Seeding 2 initial cart items to match header badge (2)...',
      );
      const insert = this.db.prepare(`
        INSERT INTO cart_items (user_id, session_id, product_id, quantity)
        VALUES (?, ?, ?, ?)
      `);

      // Seed 2 món linh kiện cho session mẫu hoặc user admin: 1 Arduino R4 WiFi + 1 Cảm biến HC-SR04
      const cartSeed = [
        [1, 'demo-guest-session-pbl4', 1, 1], // 1x Arduino Uno R4 WiFi
        [1, 'demo-guest-session-pbl4', 3, 1], // 1x Cảm biến siêu âm HC-SR04
      ];

      for (const item of cartSeed) {
        insert.run(...item);
      }
      this.logger.log('2 Cart items successfully seeded (Badge: 2).');
    }
  }

  /**
   * Truy vấn an toàn dùng Prepared Statement (Dùng khi Khiên L3 BẬT)
   */
  query<T = any>(sql: string, params: any[] = []): T[] {
    const stmt = this.db.prepare(sql);
    return stmt.all(...params) as T[];
  }

  /**
   * Truy vấn nối chuỗi thô (Dùng khi Khiên L3 TẮT - Cho phép mô phỏng SQL Injection)
   */
  rawQuery<T = any>(sql: string): T[] {
    const stmt = this.db.prepare(sql);
    return stmt.all() as T[];
  }

  /**
   * Thực thi câu lệnh DDL / Update
   */
  exec(sql: string): void {
    this.db.exec(sql);
  }
}
