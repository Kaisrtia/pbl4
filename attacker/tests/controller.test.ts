import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createServer } from 'node:http';
import { loadConfig } from '../src/config.js';
import { validateStart } from '../src/attacks/catalog.js';
import { Runs, ConflictError } from '../src/services/runs.js';
import { Telemetry } from '../src/services/telemetry.js';
import { Receiver } from '../src/services/receiver.js';
import { startServer } from '../src/server.js';

async function until(predicate: () => boolean) {
  for (let i = 0; i < 200; i++) { if (predicate()) return; await new Promise(r => setTimeout(r, 10)); }
  throw new Error('Timed out');
}
function fixture(mode: string, python = process.execPath, watchdog = 2000) {
  const dir = mkdtempSync(join(tmpdir(), 'pbl4-controller-'));
  const config = loadConfig({ ATTACKER_DATA_DIR: dir, GODVIEW_TELEMETRY_URL: 'http://127.0.0.1:1/events' });
  const telemetry = new Telemetry(config), receiver = new Receiver(config);
  const runs = new Runs(config, telemetry, receiver, () => ({ command: python, args: [resolve('tests/fixtures/worker.mjs'), mode] }), 100, watchdog);
  return { dir, config, runs, telemetry, async close() { await runs.close(); telemetry.close(); rmSync(dir, { recursive: true, force: true }); } };
}
test('validation rejects destination injection and invalid bounds', () => {
  for (const input of [null, { scenario: 'S5' }, { scenario: 'S2', target: '8.8.8.8' },
    { scenario: 'S2', parameters: { pps: -1 } }, { scenario: 'S2', parameters: { pps: 151 } },
    { scenario: 'S2', parameters: { duration_sec: 1.5 } }, { scenario: 'S3', parameters: { command: 'anything' } }])
    assert.throws(() => validateStart(input));
  assert.deepEqual(validateStart({ scenario: 'S2' }).parameters, { pps: 50, duration_sec: 5 });
});
test('fragmented NDJSON is parsed; actual zero measurements remain zero', async () => {
  const f = fixture('fragmented');
  try {
    const run = f.runs.start({ scenario: 'S2' });
    await until(() => run.state === 'COMPLETED');
    assert.equal(run.result?.measurements.count, 0);
    assert.equal(run.cleanup_pending, false);
    assert.ok(readFileSync(join(f.dir, run.run_id + '.jsonl'), 'utf8').includes('COMPLETED'));
  } finally { await f.close(); }
});
test('stop stays STOPPING until exit, is idempotent and prevents concurrent starts', async () => {
  const f = fixture('stop');
  try {
    const run = f.runs.start({ scenario: 'S1' });
    await until(() => run.state === 'RUNNING');
    assert.throws(() => f.runs.start({ scenario: 'S2' }), ConflictError);
    f.runs.stop(run.run_id);
    assert.equal(run.state, 'STOPPING');
    f.runs.stop(run.run_id);
    await until(() => run.state === 'STOPPED');
    assert.equal(run.cleanup_pending, false);
    assert.equal(f.runs.stop(run.run_id)?.state, 'STOPPED');
  } finally { await f.close(); }
});
test('forced stop records unconfirmed cleanup', async () => {
  const f = fixture('hang');
  try {
    const run = f.runs.start({ scenario: 'S3' });
    await until(() => run.state === 'RUNNING'); f.runs.stop(run.run_id);
    await until(() => run.state === 'STOPPED'); assert.equal(run.cleanup_pending, true);
  } finally { await f.close(); }
});
test('watchdog terminates a hung worker and records FAILED', async () => {
  const f = fixture('hang', process.execPath, 200);
  try {
    const run = f.runs.start({ scenario: 'S2' });
    await until(() => run.state === 'FAILED');
    assert.equal(run.error, 'Run deadline exceeded');
    assert.equal(run.cleanup_pending, true);
  } finally { await f.close(); }
});
for (const mode of ['fail', 'malformed', 'missing']) test(`${mode} cannot become a successful experiment`, async () => {
  const f = fixture(mode, mode === 'missing' ? '/missing-pbl4-python' : process.execPath);
  try {
    const run = f.runs.start({ scenario: 'S2' });
    await until(() => run.state === 'FAILED'); assert.ok(run.error); assert.equal(run.result, undefined);
  } finally { await f.close(); }
});
test('restart marks interrupted runs FAILED, not completed', async () => {
  const f = fixture('fragmented');
  try {
    writeFileSync(join(f.dir, 'interrupted.run.json'), JSON.stringify({ run_id: 'interrupted', scenario: 'S1', state: 'RUNNING', started_at: new Date().toISOString(), parameters: {}, cleanup_pending: false }));
    const recovered = new Runs(f.config, f.telemetry, new Receiver(f.config));
    assert.equal(recovered.get('interrupted')?.state, 'FAILED');
    assert.equal(recovered.get('interrupted')?.cleanup_pending, true);
  } finally { await f.close(); }
});
test('telemetry persists while offline and retries with the same event id', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'pbl4-telemetry-'));
  let fail = true;
  const seen: string[] = [];
  const server = createServer(async (req, res) => {
    let raw = ''; for await (const chunk of req) raw += chunk;
    seen.push(JSON.parse(raw).event_id); res.writeHead(fail ? 503 : 200).end();
  });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  const config = loadConfig({ ATTACKER_DATA_DIR: dir, GODVIEW_TELEMETRY_URL: `http://127.0.0.1:${(server.address() as { port: number }).port}/events` });
  let t = new Telemetry(config);
  try {
    const payload = { state: 'STARTING' };
    t.emit({ run_id: 'test', scenario: 'S1', state: 'STARTING', parameters: {}, started_at: '', cleanup_pending: false }, 'RUN_STATE', payload);
    payload.state = 'COMPLETED';
    assert.equal(t.events()[0]?.payload.state, 'STARTING');
    await t.flush(); assert.equal(t.status().pending, 1); t.close();
    t = new Telemetry(config); assert.equal(t.status().pending, 1);
    fail = false; await t.flush(); assert.equal(t.status().pending, 0); assert.equal(seen[0], seen[1]);
  } finally { t.close(); server.closeAllConnections(); server.close(); rmSync(dir, { recursive: true, force: true }); }
});
test('receiver validates token, size, hash and replay', async () => {
  const config = loadConfig({ HACKER_IP: '127.0.0.1' });
  config.receiverPort = 0; config.receiverBind = '127.0.0.1';
  const receiver = new Receiver(config); await receiver.start();
  try {
    const registration = receiver.register('test-run');
    const headers = { Authorization: 'Bearer ' + registration.token };
    assert.equal((await fetch(registration.url, { method: 'POST', body: 'sample' })).status, 403);
    assert.equal((await fetch(registration.url, { method: 'POST', headers, body: 'a'.repeat(4097) })).status, 413);
    assert.equal(receiver.receipt('test-run'), undefined);
    const response = await fetch(registration.url, { method: 'POST', headers, body: 'sample' });
    assert.equal(response.status, 200);
    const receipt = await response.json() as { bytes: number; sha256: string };
    assert.equal(receipt.bytes, 6); assert.equal(receipt.sha256.length, 64);
    assert.equal((await fetch(registration.url, { method: 'POST', headers, body: 'sample' })).status, 409);
    receiver.unregister('test-run');
    assert.equal((await fetch(registration.url, { method: 'POST', headers, body: 'sample' })).status, 403);
  } finally { await receiver.close(); }
});
test('HTTP auth, input errors and no false start', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'pbl4-api-'));
  const config = loadConfig({ ATTACKER_DATA_DIR: dir, ATTACKER_API_TOKEN: 'test-only-token-12345' });
  config.port = 0; config.receiverPort = 0;
  const app = await startServer(config);
  const base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
  try {
    assert.equal((await fetch(base + '/api/v1/runs')).status, 401);
    const headers = { Authorization: 'Bearer test-only-token-12345', 'Content-Type': 'application/json' };
    assert.equal((await fetch(base + '/api/v1/runs', { method: 'POST', headers, body: '{' })).status, 400);
    assert.equal((await fetch(base + '/api/v1/runs', { method: 'POST', headers, body: '{"scenario":"S2","parameters":{"pps":5000}}' })).status, 400);
    assert.deepEqual(app.runs.list(), []);
    const configResponse = await (await fetch(base + '/api/v1/config', { headers })).text();
    assert.ok(!configResponse.includes('test-only-token'));
    assert.equal((await fetch(base + '/api/v1/runs', { headers: { ...headers, Origin: 'http://unrelated.test' } })).status, 403);
  } finally { await app.close(); rmSync(dir, { recursive: true, force: true }); }
});
