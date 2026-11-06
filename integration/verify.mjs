import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
const host = process.env.LAB_BIND_IP || '127.0.0.1';
const target = `http://${host}:${process.env.LAB_TARGET_PORT || 18000}`;
const hub = `http://${host}:${process.env.LAB_GODVIEW_PORT || 14000}`;
const attacker = `http://${host}:${process.env.LAB_ATTACKER_PORT || 19090}`;
const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.LAB_ATTACKER_TOKEN}` };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function api(base, path, body, expected = 200) {
  const response = await fetch(base + path, { method: body === undefined ? 'GET' : 'POST', headers,
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(5000) });
  const data = await response.json();
  assert.equal(response.status, expected, `${path}: ${JSON.stringify(data)}`);
  return data;
}
async function waitFor(check, message) {
  for (let i = 0; i < 80; i++) { if (await check()) return; await sleep(250); }
  throw new Error(message);
}

await api(hub, '/api/health');
await api(target, '/api/system/health');
const preflight = await api(attacker, '/api/v1/preflight');
for (const flag of ['target_ssh_reachable', 'target_http_reachable', 'known_hosts_present', 'credential_present']) assert.equal(preflight[flag], true);
const initial = await api(target, '/api/defense/status');
try {
  for (const enabled of [true, true, false]) {
    const result = await api(hub, '/api/defense/toggle', { enabled });
    assert.equal(result.proxied_to_target, true);
    assert.equal(result.defense_l3_app, enabled);
    assert.equal((await api(target, '/api/defense/status')).flags.l3_master, enabled);
  }
  // Validate the existing application defense through a harmless traversal rejection.
  await api(hub, '/api/defense/toggle', { enabled: true });
  await api(target, '/api/files/download?name=../../etc/passwd', undefined, 400);
  await api(hub, '/api/defense/toggle', { enabled: false });
  await api(target, '/api/system/ping?echo=integration-verification');
  await waitFor(async () => (await api(hub, '/api/telemetry/history')).history.some(log => log.endpoint.includes('integration-verification')), 'Target telemetry did not reach God-View');
  await waitFor(async () => (await api(hub, '/api/telemetry/history')).history.some(log => log.endpoint.includes('integration-client') && log.client_ip === (process.env.LAB_CLIENT_IP || '172.30.44.10')), 'No real Client traffic observed');
  const probe = JSON.parse(execFileSync('docker', ['compose', '--project-name', 'pbl4-integration', '--env-file', 'integration/.env.local', '-f', 'compose.integration.yaml', 'exec', '-T', 'client', 'cat', '/tmp/client-probe.json'], { encoding: 'utf8' }));
  assert.equal(probe.ok, true);
  console.log('PASS: real Client -> Target -> God-View; L3 state and application rejection');

  for (const [scenario, parameters] of [['S1', {}], ['S2', { pps: 5, duration_sec: 1 }], ['S3', { max_fds: 32, hold_sec: 1 }], ['S4', {}]]) {
    const accepted = await api(attacker, '/api/v1/runs', { scenario, parameters }, 202);
    let run;
    await waitFor(async () => {
      run = await api(attacker, `/api/v1/runs/${accepted.run_id}`);
      return ['COMPLETED', 'FAILED', 'STOPPED'].includes(run.state);
    }, `${scenario} did not finish`);
    assert.equal(run.state, 'COMPLETED', JSON.stringify(run));
    assert.equal(run.cleanup_pending, false);
    assert.equal(run.result.outcome, 'OBSERVED', JSON.stringify(run));
    if (scenario === 'S2') assert.ok(run.result.measurements.send_calls_succeeded > 0);
    if (scenario === 'S3') assert.equal(run.result.measurements.opened_fds, 32);
    if (scenario === 'S4') assert.equal(run.result.measurements.sha256, run.result.measurements.receiver_receipt.sha256);
    await waitFor(async () => (await api(hub, `/api/events/attack?run_id=${accepted.run_id}`)).events.some(event => event.payload.state === 'COMPLETED'), `${scenario} evidence did not reach God-View`);
    console.log(`PASS: ${scenario}, run ${accepted.run_id}, real Target and God-View event delivery`);
  }
} finally {
  await api(target, '/api/defense/set', initial.flags);
  await api(hub, '/api/defense/status');
}
console.log('PASS: integration lab. SYN delivery/backlog impact and OS/network defenses are not asserted.');
