// Baseline HTTP probe, not the full login/download client bot planned for W3-T3.
import { writeFileSync, renameSync } from 'node:fs';
const base = process.env.TARGET_APP_URL || 'http://target:8000';
const interval = Math.max(1000, Number(process.env.CLIENT_INTERVAL_MS || 3000));
let stopped = false;
process.on('SIGTERM', () => { stopped = true; });
while (!stopped) {
  const start = performance.now();
  let result;
  try {
    const response = await fetch(`${base}/api/system/ping?echo=integration-client`, { signal: AbortSignal.timeout(2000) });
    await response.text();
    result = { ok: response.ok, status_code: response.status };
  } catch (error) {
    result = { ok: false, error: error.message };
  }
  result = { ...result, timestamp: new Date().toISOString(), latency_ms: performance.now() - start };
  writeFileSync('/tmp/client-probe.json.tmp', JSON.stringify(result));
  renameSync('/tmp/client-probe.json.tmp', '/tmp/client-probe.json');
  console.log(JSON.stringify(result));
  await new Promise(resolve => setTimeout(resolve, interval));
}
