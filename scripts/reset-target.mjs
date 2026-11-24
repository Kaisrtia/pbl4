#!/usr/bin/env node
/**
 * ============================================================================
 * PBL4 - Target App Clean State Reset CLI (Task W6-T3)
 * Phụ trách: Hoàng Trung (TV3) - Target App & Tấn công L7
 * ============================================================================
 * 
 * Script khôi phục trạng thái sạch nguyên tử cho Target App:
 * 1. Khôi phục Cơ sở dữ liệu SQLite: Xóa đơn hàng, dọn giỏ hàng & re-seed lại toàn bộ data mẫu.
 * 2. Xóa sạch bộ đếm Rate Limiting trong bộ nhớ RAM của DynamicRateLimitGuard.
 * 3. Đưa cấu hình Khiên L3 về trạng thái mặc định ban đầu.
 * 
 * Hỗ trợ 2 chế độ:
 * - Online: Gọi HTTP API POST /api/system/reset tới Target Server đang chạy.
 * - Offline Fallback: Thao tác trực tiếp lên tệp SQLite trên đĩa nếu server chưa bật.
 */

import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

const DEFAULT_TARGET = process.env.TARGET_APP_URL || 'http://localhost:18000';
const DEFAULT_DB_PATH = process.env.DATABASE_PATH || './target-app/server/data/devsec.sqlite';

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  bgGreen: '\x1b[42m',
  bgRed: '\x1b[41m',
  white: '\x1b[37m',
};

function banner() {
  console.log(`
${C.cyan}${C.bold}╔══════════════════════════════════════════════════════════════════════╗
║               PBL4 - TARGET APP 1-TOUCH RESET TOOL                   ║
║         Khôi Phục Trạng Thái Sạch Cho Target App (Task W6-T3)        ║
║                    Phụ trách: Hoàng Trung (TV3)                      ║
╚══════════════════════════════════════════════════════════════════════╝${C.reset}`);
}

async function sendRequest(baseUrl, path, options = {}) {
  const url = `${baseUrl.replace(/\/+$/, '')}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      'User-Agent': 'PBL4-Reset-CLI/1.0',
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...(options.headers || {}),
    },
    signal: AbortSignal.timeout(options.timeout || 5000),
  });
  const data = await res.json().catch(() => null);
  return { ok: res.ok, status: res.status, data };
}

// Chế độ 1: Reset Online qua API
async function resetOnline(targetUrl) {
  console.log(`\n${C.yellow}→ Đang kết nối tới Target Server tại [${targetUrl}]...${C.reset}`);
  const res = await sendRequest(targetUrl, '/api/system/reset', {
    method: 'POST',
    body: JSON.stringify({}),
  });

  if (res.ok && res.data?.status === 'success') {
    const summary = res.data.reset_summary;
    console.log(`\n${C.bgGreen}${C.white} KHÔI PHỤC TRẠNG THÁI SẠCH THÀNH CÔNG (ONLINE) ${C.reset}`);
    console.log(`  • Thông báo: ${C.green}${res.data.message}${C.reset}`);
    console.log(`  • Bảng cơ sở dữ liệu đã dọn: ${C.cyan}${summary?.database?.clearedTables?.join(', ') || 'N/A'}${C.reset}`);
    console.log(`  • Số lượng dữ liệu mẫu được nạp lại:`);
    console.log(`    - Tài khoản người dùng: ${C.bold}${summary?.database?.users || 5}${C.reset}`);
    console.log(`    - Danh mục sản phẩm:    ${C.bold}${summary?.database?.categories || 3}${C.reset}`);
    console.log(`    - Sản phẩm phần cứng:   ${C.bold}${summary?.database?.products || 6}${C.reset}`);
    console.log(`    - Tài liệu kỹ thuật:    ${C.bold}${summary?.database?.documents || 5}${C.reset}`);
    console.log(`    - Giỏ hàng mẫu (Badge): ${C.bold}${summary?.database?.cart_items || 2}${C.reset}`);
    console.log(`  • Bộ đếm Dynamic Rate Limiting: ${C.green}ĐÃ XÓA SẠCH TRÊN RAM${C.reset}`);
    console.log(`  • Cấu hình Khiên L3:`);
    console.log(`    - Master Shield:        ${summary?.defense_flags_reset?.l3_master ? C.green + 'BẬT' : C.red + 'TẮT'}${C.reset}`);
    console.log(`    - Anti-SQLi:            ${summary?.defense_flags_reset?.anti_sqli ? C.green + 'BẬT' : C.red + 'TẮT'}${C.reset}`);
    console.log(`    - Rate Limit:           ${summary?.defense_flags_reset?.rate_limit ? C.green + 'BẬT' : C.red + 'TẮT'}${C.reset}`);
    console.log(`    - Input Sanitization:   ${summary?.defense_flags_reset?.input_sanitization ? C.green + 'BẬT' : C.red + 'TẮT'}${C.reset}`);
    console.log(`  • Thời điểm: ${C.dim}${res.data.timestamp}${C.reset}\n`);
    return true;
  } else {
    throw new Error(`API trả về lỗi: HTTP ${res.status} - ${JSON.stringify(res.data)}`);
  }
}

// Chế độ 2: Reset Offline trực tiếp trên SQLite file
function resetOffline(dbPath) {
  const resolvedPath = path.resolve(process.cwd(), dbPath);
  console.log(`\n${C.yellow}→ Chế độ Offline: Thao tác trực tiếp trên SQLite file: [${resolvedPath}]...${C.reset}`);

  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Tệp SQLite không tồn tại tại đường dẫn: ${resolvedPath}`);
  }

  const db = new DatabaseSync(resolvedPath);
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec('BEGIN TRANSACTION;');

  try {
    db.exec('DELETE FROM order_items;');
    db.exec('DELETE FROM orders;');
    db.exec('DELETE FROM cart_items;');
    db.exec('DELETE FROM documents;');
    db.exec('DELETE FROM products;');
    db.exec('DELETE FROM categories;');
    db.exec('DELETE FROM users;');
    db.exec("DELETE FROM sqlite_sequence WHERE name IN ('order_items', 'orders', 'cart_items', 'documents', 'products', 'categories', 'users');");

    // Seed lại Users
    const insertUser = db.prepare('INSERT INTO users (username, password, role, full_name, email) VALUES (?, ?, ?, ?, ?)');
    insertUser.run('admin', 'adminPassword2026!', 'admin', 'System Administrator', 'admin@devsec.pbl4');
    insertUser.run('alice', 'aliceSecretPassword', 'user', 'Alice Johnson', 'alice@devsec.pbl4');
    insertUser.run('victim', 'victimPassword123', 'user', 'Lab Victim User', 'victim@devsec.pbl4');
    insertUser.run('guest', 'guestPassword', 'guest', 'Guest Observer', 'guest@devsec.pbl4');
    insertUser.run('engineer_user', 'pass123', 'user', 'Embedded Systems Engineer', 'engineer@devsec.pbl4');

    // Seed Categories
    const insertCat = db.prepare('INSERT INTO categories (slug, name, description, display_order) VALUES (?, ?, ?, ?)');
    insertCat.run('vi-dieu-khien', 'Vi điều khiển', 'Thiết bị vi xử lý, vi điều khiển và bo mạch phát triển IoT', 1);
    insertCat.run('cam-bien', 'Cảm biến', 'Cảm biến công nghiệp, đo khoảng cách, nhiệt độ và độ ẩm', 2);
    insertCat.run('module-nguon', 'Module nguồn', 'Mạch hạ áp, module nguồn và relay bảo vệ cách ly', 3);

    // Seed Products
    const insertProd = db.prepare('INSERT INTO products (category_id, sku, name, brand, description, price, stock, image_url, specs_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
    insertProd.run(1, 'MCU-ARD-R4', 'Arduino Uno R4 WiFi', 'Arduino SA Official', 'Renesas RA4M1 32-bit ARM Cortex-M4 (48MHz)', 320000, 48, '/images/products/arduino-uno-r4.png', JSON.stringify(['Cortex-M4', '5V Logic', 'WiFi / BLE']));
    insertProd.run(1, 'MCU-ESP-32D', 'ESP32-WROOM-32D DevBoard', 'Espressif Systems', 'Dual-core Xtensa 32-bit LX6 240MHz', 95000, 120, '/images/products/esp32-wroom-32d.png', JSON.stringify(['240MHz Dual-Core', '4MB Flash']));
    insertProd.run(2, 'SEN-UC-SR04', 'Cảm biến siêu âm HC-SR04', 'ElecRobo Sensor', 'Dải đo khoảng cách 2cm - 400cm', 25000, 250, '/images/products/hc-sr04.png', JSON.stringify(['2cm - 400cm', '5V DC']));
    insertProd.run(3, 'PWR-LM-2596', 'Module Nguồn Hạ Áp LM2596', 'PowerTech Labs', 'Điện áp vào 4V-40V DC, điện áp ra 1.25V-37V DC', 18000, 85, '/images/products/lm2596.png', JSON.stringify(['In: 4-40V', 'Out: 1.25-37V']));
    insertProd.run(2, 'SEN-DHT-22', 'Cảm biến nhiệt ẩm DHT22', 'Aosong Electronics', 'Nhiệt độ -40°C đến 80°C, độ ẩm 0-100% RH', 68000, 64, '/images/products/dht22.png', JSON.stringify(['±0.5°C Acc', '0-100% RH']));
    insertProd.run(3, 'MOD-RLY-4CH', 'Module Relay 4 Kênh 5V', 'Songle Automation', 'Đóng ngắt AC 250V 10A / DC 30V 10A', 42000, 92, '/images/products/relay-4ch.png', JSON.stringify(['4 Channels', '10A 250VAC']));

    // Seed Documents
    const insertDoc = db.prepare('INSERT INTO documents (product_id, title, file_name, file_size_kb, is_confidential) VALUES (?, ?, ?, ?, ?)');
    insertDoc.run(1, 'Arduino Uno R4 WiFi Datasheet', 'arduino-uno-r4-datasheet.pdf', 1240, 0);
    insertDoc.run(2, 'ESP32 Technical Reference Manual', 'esp32-technical-reference.pdf', 2850, 0);
    insertDoc.run(3, 'HC-SR04 Ultrasonic Sensor Pinout & Timing', 'hc-sr04-ultrasonic-pinout.pdf', 450, 0);
    insertDoc.run(4, 'LM2596 Step-Down Regulator Schematic', 'lm2596-buck-schematic.pdf', 620, 0);
    insertDoc.run(null, 'ElectroShop R&D Confidential Hardware Blueprint', 'rd-confidential-hardware-blueprint.pdf', 5120, 1);

    // Seed Cart
    const insertCart = db.prepare('INSERT INTO cart_items (user_id, session_id, product_id, quantity) VALUES (?, ?, ?, ?)');
    insertCart.run(1, 'demo-guest-session-pbl4', 1, 1);
    insertCart.run(1, 'demo-guest-session-pbl4', 3, 1);

    db.exec('COMMIT;');
    db.close();

    console.log(`\n${C.bgGreen}${C.white} KHÔI PHỤC SQLITE OFFLINE THÀNH CÔNG ${C.reset}`);
    console.log(`  • Tệp cơ sở dữ liệu đã được làm sạch và re-seed toàn bộ data chuẩn.`);
    console.log(`  • Dữ liệu giỏ hàng, người dùng, sản phẩm, tài liệu mật đã sẵn sàng cho buổi demo tiếp theo.\n`);
    return true;
  } catch (err) {
    db.exec('ROLLBACK;');
    db.close();
    throw err;
  }
}

async function main() {
  banner();

  const args = process.argv.slice(2);
  let target = DEFAULT_TARGET;

  const targetIdx = args.indexOf('--target');
  if (targetIdx !== -1 && args[targetIdx + 1]) {
    target = args[targetIdx + 1];
  }

  // Thử Reset Online trước
  try {
    await resetOnline(target);
    return;
  } catch (onlineErr) {
    console.log(`  ${C.yellow}⚠ Không thể reset qua HTTP tại ${target} (${onlineErr.message}).${C.reset}`);
    console.log(`    Đang thử cổng fallback http://localhost:8000 ...`);
    try {
      await resetOnline('http://localhost:8000');
      return;
    } catch {
      console.log(`  ${C.dim}→ Cả 2 cổng HTTP đều chưa chạy. Chuyển sang Reset SQLite trực tiếp...${C.reset}`);
    }
  }

  // Fallback sang Reset Offline trực tiếp trên tệp SQLite
  try {
    const dbPath = args.includes('--db') ? args[args.indexOf('--db') + 1] : DEFAULT_DB_PATH;
    resetOffline(dbPath);
  } catch (offlineErr) {
    console.error(`\n${C.red}✖ Lỗi khi khôi phục trạng thái sạch:${C.reset}`, offlineErr.message);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(`\n${C.red}Lỗi thực thi Reset CLI:${C.reset}`, err);
  process.exit(1);
});
