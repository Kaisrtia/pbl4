import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { io as connect } from 'socket.io-client';

test('hub integration contracts', { timeout: 15000 }, async (t) => {
  let master = false;
  let offline = false;
  let malformed = false;
  const target = createServer(async (req, res) => {
    let text = '';
    for await (const part of req) text += part;
    const body = text ? JSON.parse(text) : {};
    res.setHeader('Content-Type', 'application/json');
    if (offline) { res.writeHead(503); res.end('{}'); return; }
    if (malformed) { res.end('{"unexpected":true}'); return; }
    if (req.url?.endsWith('/set')) {
      for (const flag of ['anti_sqli', 'rate_limit', 'input_sanitization']) assert.equal(body[flag], body.l3_master);
      master = body.l3_master;
    }
    if (req.url?.endsWith('/toggle')) master = !master;
    res.end(JSON.stringify(req.url?.endsWith('/status') ? { flags: { l3_master: master } } : { current_state: { l3_master: master } }));
  });
  target.listen(0, '127.0.0.1');
  await once(target, 'listening');
  const address = target.address() as { port: number };
  process.env.PORT = '0';
  process.env.HOST = '127.0.0.1';
  process.env.TARGET_APP_URL = `http://127.0.0.1:${address.port}`;
  const { server, io } = await import('../src/server');
  if (!server.listening) await once(server, 'listening');
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const socket = connect(base, { transports: ['websocket'], autoConnect: false });
  after(async () => {
    socket.disconnect();
    await new Promise<void>(resolve => io.close(() => resolve()));
    target.closeAllConnections();
    await new Promise<void>(resolve => target.close(() => resolve()));
  });
  const initial = once(socket, 'INITIAL_STATE');
  socket.connect();
  await initial;
  async function api(path: string, body?: unknown) {
    const response = await fetch(base + path, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: response.status, data: await response.json() as any };
  }
  const event = {
    schema_version: '1.0', event_id: 'test-1', run_id: 'run-1', timestamp: new Date().toISOString(),
    source_node: 'ATTACKER', source_ip: '172.30.44.66', target_ip: '172.30.44.20',
    scenario: 'S4', event_type: 'RUN_STATE', execution_mode: 'real', payload: { state: 'COMPLETED' },
  };

  await t.test('real HTTP logs still work and metrics are labelled simulated', async () => {
    const log = { endpoint: '/api/system/ping', status_code: 200, method: 'GET', response_time: 1, client_ip: '172.30.44.10', payload_summary: {} };
    assert.equal((await api('/api/telemetry', log)).status, 200);
    const history = (await api('/api/telemetry/history')).data;
    assert.equal(history.count, 1);
    assert.equal(history.metrics.source, 'simulated');
  });
  await t.test('attack schema, Socket.IO delivery, retry deduplication and run filtering', async () => {
    const delivered = once(socket, 'ATTACK_EVENT');
    assert.equal((await api('/api/events/attack', event)).status, 200);
    assert.deepEqual((await delivered)[0], event);
    assert.equal((await api('/api/events/attack', event)).data.duplicate, true);
    assert.equal((await api('/api/events/attack?run_id=run-1')).data.count, 1);
    assert.equal((await api('/api/events/attack?run_id=missing')).data.count, 0);
    assert.equal((await api('/api/telemetry/history')).data.count, 1);
    assert.equal((await api('/api/events/attack', { ...event, scenario: 'BAD' })).status, 400);
    assert.equal((await api('/api/events/attack', { ...event, event_type: 'WORKER_EVENT', payload: { type: 'progress', run_id: 'wrong' } })).status, 400);
  });
  await t.test('reads Target state and explicit set is idempotent', async () => {
    assert.equal((await api('/api/defense/status')).data.defense_l3_app, false);
    for (let i = 0; i < 2; i++) {
      const result = await api('/api/defense/toggle', { enabled: true });
      assert.equal(result.status, 200);
      assert.equal(result.data.defense_l3_app, true);
      assert.equal(master, true);
    }
    assert.equal((await api('/api/defense/toggle', {})).data.defense_l3_app, false);
    assert.equal((await api('/api/defense/toggle', { enabled: 'true' })).status, 400);
    master = true; // A change made directly at Target is reflected on the next read.
    assert.equal((await api('/api/defense/status')).data.defense_l3_app, true);
  });
  await t.test('direct Target changes and outage reach connected dashboards without a reload', async () => {
    async function awaitState(expected: boolean | null, mutate: () => void) {
      const received = new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => { socket.off('DEFENSE_TOGGLED', listener); reject(new Error('No automatic defense update')); }, 4500);
        const listener = (payload: any) => {
          if (payload.defense_l3_state !== expected) return;
          clearTimeout(timer);
          socket.off('DEFENSE_TOGGLED', listener);
          resolve();
        };
        socket.on('DEFENSE_TOGGLED', listener);
      });
      mutate();
      await received;
    }
    await awaitState(false, () => { master = false; });
    await awaitState(null, () => { offline = true; });
    await awaitState(true, () => { offline = false; master = true; });
  });
  await t.test('offline or invalid Target response never reports a successful local toggle', async () => {
    offline = true;
    const result = await api('/api/defense/toggle', {});
    assert.equal(result.status, 502);
    assert.equal(result.data.defense_l3_app, null);
    assert.equal(master, true);
    const socketError = once(socket, 'DEFENSE_ERROR');
    socket.emit('TOGGLE_DEFENSE');
    await socketError;
    assert.equal(master, true);
    offline = false;
    malformed = true;
    assert.equal((await api('/api/defense/status')).status, 502);
    malformed = false;
    assert.equal((await api('/api/defense/status')).data.defense_l3_app, true);
  });
});
