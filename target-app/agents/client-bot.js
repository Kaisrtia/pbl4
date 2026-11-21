#!/usr/bin/env node
/**
 * Client Bot Traffic Generator (Node.js version - Task W3-T3 - PBL4)
 * Người phụ trách: Hoàng Trung (TV3) - Target App & Tấn công L7
 *
 * Chạy vòng lặp định kỳ mỗi 3–5 giây:
 * 1. GET /api/products (duyệt sản phẩm)
 * 2. POST /api/auth/login với tài khoản engineer_user / pass123
 * 3. GET /api/products/categories & GET /api/cart
 * 4. GET /api/system/ping?t=<now>&echo=integration-client
 */

import { writeFileSync, renameSync } from 'node:fs';

const TARGET_URL = (process.env.TARGET_APP_URL || 'http://localhost:8000').replace(/\/+$/, '');
const INTERVAL_MS = Math.max(1000, Number(process.env.CLIENT_INTERVAL_MS || 3500));
const USERNAME = process.env.CLIENT_USERNAME || 'engineer_user';
const PASSWORD = process.env.CLIENT_PASSWORD || 'pass123';
const PROBE_FILE = process.env.PROBE_FILE_PATH || '/tmp/client-probe.json';

let stopped = false;
let accessToken = null;
let iteration = 0;
const sessionId = `client-bot-session-${Date.now()}`;

process.on('SIGINT', () => { stopped = true; });
process.on('SIGTERM', () => { stopped = true; });

function writeProbe(ok, statusCode = 200, latencyMs = 0, error = null) {
  try {
    const data = {
      ok,
      status_code: statusCode,
      latency_ms: Math.round(latencyMs * 100) / 100,
      timestamp: new Date().toISOString(),
      client_bot: {
        username: USERNAME,
        session_id: sessionId,
        authenticated: accessToken !== null,
        iterations: iteration,
      },
      ...(error ? { error } : {}),
    };
    writeFileSync(`${PROBE_FILE}.tmp`, JSON.stringify(data, null, 2));
    renameSync(`${PROBE_FILE}.tmp`, PROBE_FILE);
  } catch {
    // Bỏ qua lỗi ghi file
  }
}

async function request(endpoint, options = {}) {
  const url = `${TARGET_URL}${endpoint}`;
  const headers = {
    'User-Agent': 'PBL4-ClientBot-Node/1.0 (ElectroShop Victim Agent)',
    'Accept': 'application/json',
    'x-session-id': sessionId,
    ...(options.headers || {}),
  };
  if (options.useAuth && accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }

  const start = performance.now();
  const res = await fetch(url, {
    method: options.method || 'GET',
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    signal: AbortSignal.timeout(4000),
  });
  const latency = performance.now() - start;

  let body = null;
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    body = await res.json();
  } else {
    body = await res.text();
  }

  return { status: res.status, ok: res.ok, body, latency };
}

async function runCycle() {
  iteration++;
  console.log(`\n[${new Date().toISOString()}] --- [VÒNG LẶP #${iteration}] Client Bot gửi traffic ---`);

  try {
    // 1. Duyệt sản phẩm
    const prodRes = await request('/api/products');
    const prodCount = prodRes.body?.data?.length || 0;
    console.log(`[BOT-BROWSE] Duyệt sản phẩm: ${prodCount} linh kiện (HTTP ${prodRes.status}, ${prodRes.latency.toFixed(1)}ms)`);

    // 2. Đăng nhập (gửi credentials qua HTTP)
    const loginRes = await request('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: { username: USERNAME, password: PASSWORD },
    });
    if (loginRes.ok && loginRes.body?.access_token) {
      accessToken = loginRes.body.access_token;
      console.log(`[BOT-LOGIN] Đăng nhập thành công với '${USERNAME}' (HTTP 200, ${loginRes.latency.toFixed(1)}ms)`);
    } else {
      console.warn(`[BOT-LOGIN] Đăng nhập thất bại: HTTP ${loginRes.status}`);
    }

    // 3. Duyệt danh mục và giỏ hàng
    await request('/api/products/categories');
    await request('/api/cart', { useAuth: true });

    // 4. Ping đo độ trễ & duy trì kết nối TCP
    const pingRes = await request(`/api/system/ping?t=${Date.now()}&echo=integration-client`);
    console.log(`[BOT-PING] Ping phản hồi thành công (Độ trễ: ${pingRes.latency.toFixed(1)}ms, Server IP: ${pingRes.body?.client_ip || 'ok'})`);

    writeProbe(true, pingRes.status, pingRes.latency);
  } catch (err) {
    console.error(`[BOT-ALERT] Sự cố kết nối tới Target Server: ${err.message}`);
    writeProbe(false, 503, 0, err.message);
  }
}

async function start() {
  console.log(`[ClientBot Node] Bắt đầu giả lập người dùng tới ${TARGET_URL} (chu kỳ ${INTERVAL_MS}ms, user: ${USERNAME})`);
  while (!stopped) {
    const cycleStart = performance.now();
    await runCycle();
    const elapsed = performance.now() - cycleStart;
    const sleepMs = Math.max(500, INTERVAL_MS - elapsed);
    await new Promise(r => setTimeout(r, sleepMs));
  }
  console.log('[ClientBot Node] Tiến trình dừng an toàn.');
}

start();
