// Client Bot Traffic Generator for Integration Lab (Task W3-T3 - PBL4)
// Phụ trách: Hoàng Trung (TV3) - Target App & Tấn công L7
import { writeFileSync, renameSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { failedProbe } from './client-probe.mjs';

const base = (process.env.TARGET_APP_URL || 'http://target:8000').replace(/\/+$/, '');
const interval = Math.max(1000, Number(process.env.CLIENT_INTERVAL_MS || 3000));
const username = process.env.CLIENT_USERNAME || 'engineer_user';
const password = process.env.CLIENT_PASSWORD || 'pass123';
const probeFile = process.env.PROBE_FILE_PATH || '/tmp/client-probe.json';

const shutdown = new AbortController();
let accessToken = null;
let iteration = 0;
const sessionId = `integration-client-${Date.now()}`;

process.on('SIGTERM', () => shutdown.abort());
process.on('SIGINT', () => shutdown.abort());

async function req(path, options = {}) {
  const start = performance.now();
  const headers = {
    'User-Agent': 'PBL4-ClientBot-Integration/1.0',
    'Accept': 'application/json',
    'x-session-id': sessionId,
    ...(options.headers || {}),
  };
  if (options.useAuth && accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }

  const response = await fetch(`${base}${path}`, {
    method: options.method || 'GET',
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    signal: AbortSignal.any([shutdown.signal, AbortSignal.timeout(3000)]),
  });

  const latency = performance.now() - start;
  let data = null;
  const ct = response.headers.get('content-type') || '';
  if (ct.includes('application/json')) {
    data = await response.json();
  } else {
    data = await response.text();
  }

  return { ok: response.ok, status: response.status, data, latency };
}

while (!shutdown.signal.aborted) {
  iteration++;
  const cycleStart = performance.now();
  let probeResult;

  try {
    // 1. Duyệt sản phẩm
    await req('/api/products');

    // 2. Đăng nhập người dùng (truyền thông tin đăng nhập qua kết nối TCP phục vụ MitM sniffing)
    const loginRes = await req('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: { username, password },
    });
    if (loginRes.ok && loginRes.data?.access_token) {
      accessToken = loginRes.data.access_token;
    }

    // 3. Duyệt danh mục & giỏ hàng
    await req('/api/products/categories');
    await req('/api/cart', { useAuth: true });

    // 4. Ping liên tục với echo=integration-client (cho verify.mjs & duy trì kết nối TCP cho TCP RST attack)
    const pingRes = await req('/api/system/ping?echo=integration-client');
    probeResult = {
      ok: pingRes.ok,
      status_code: pingRes.status,
      status_source: 'http',
      timestamp: new Date().toISOString(),
      latency_ms: Math.round(pingRes.latency * 100) / 100,
      authenticated: accessToken !== null,
      iteration,
    };
  } catch (error) {
    if (shutdown.signal.aborted) break;
    probeResult = failedProbe(error, iteration, performance.now() - cycleStart);
  }

  // Cập nhật atomic file probe cho Docker Healthcheck
  try {
    writeFileSync(`${probeFile}.tmp`, JSON.stringify(probeResult));
    renameSync(`${probeFile}.tmp`, probeFile);
    console.log(JSON.stringify(probeResult));
  } catch {
    // Bỏ qua lỗi I/O
  }

  const elapsed = performance.now() - cycleStart;
  const sleepMs = Math.max(500, interval - elapsed);
  try {
    await delay(sleepMs, undefined, { signal: shutdown.signal });
  } catch (error) {
    if (!shutdown.signal.aborted) throw error;
  }
}
