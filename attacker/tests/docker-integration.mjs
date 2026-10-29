import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import Ajv from 'ajv';

const prefix = ['compose', '-p', 'pbl4-attacker-test', '-f', 'tests/compose.yaml'];
const compose = (...args) => execFileSync('docker', [...prefix, ...args], { encoding: 'utf8', timeout: 120000 });
const target = command => compose('exec', '-T', 'target', 'sh', '-c', command);
const headers = { 'Content-Type': 'application/json', Authorization: 'Bearer fixture-only-token-not-for-deployment' };
async function api(path, method = 'GET', body, expected = 200) {
  const response = await fetch('http://127.0.0.1:19000/api/v1/' + path, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(5000),
  });
  const data = await response.json();
  assert.equal(response.status, expected, JSON.stringify(data));
  return data;
}
async function finished(id) {
  for (let i = 0; i < 160; i++) {
    const run = await api('runs/' + id);
    if (['COMPLETED', 'FAILED', 'STOPPED'].includes(run.state)) return run;
    await new Promise(r => setTimeout(r, 250));
  }
  throw new Error('Run did not terminate');
}
async function execute(scenario, parameters = {}) {
  const accepted = await api('runs', 'POST', { scenario, parameters }, 202);
  const run = await finished(accepted.run_id);
  console.log(`${scenario}: ${run.state}, ${run.result?.outcome || run.error}`);
  assert.equal(run.state, 'COMPLETED', JSON.stringify(run));
  assert.equal(run.cleanup_pending, false, JSON.stringify(run));
  return run;
}
try {
  compose('up', '-d', '--wait', '--wait-timeout', '90');
  target('prlimit --pid "$(cat /run/sshd.pid)" --nofile=1024:; chmod 644 /home/lab/pbl4-lab/sample.txt; if [ -f /home/lab/.ssh/authorized_keys.disabled ]; then mv /home/lab/.ssh/authorized_keys.disabled /home/lab/.ssh/authorized_keys; fi');
  const check = await api('preflight');
  assert.equal(check.target_ssh_reachable, true); assert.equal(check.target_http_reachable, true);
  const s1 = await execute('S1'); assert.equal(s1.result.measurements.stages.length, 5);
  const s4 = await execute('S4');
  assert.equal(s4.result.measurements.bytes, s4.result.measurements.receiver_receipt.bytes);
  assert.equal(s4.result.measurements.sha256, s4.result.measurements.receiver_receipt.sha256);
  const s3 = await execute('S3', { max_fds: 32, hold_sec: 1 });
  assert.equal(s3.result.measurements.opened_fds, 32);
  assert.equal(s3.result.measurements.hit_emfile, false);
  const s2 = await execute('S2', { pps: 5, duration_sec: 1 });
  assert.ok(s2.result.measurements.send_calls_succeeded > 0);
  assert.equal(s2.result.measurements.target_received, null);

  // Actual DAC rejection, no simulated defense boolean.
  target('chmod 600 /home/lab/pbl4-lab/sample.txt');
  assert.equal((await execute('S4')).result.outcome, 'BLOCKED');
  target('chmod 644 /home/lab/pbl4-lab/sample.txt');

  // Actual inherited RLIMIT_NOFILE in new SSH sessions.
  target('prlimit --pid "$(cat /run/sshd.pid)" --nofile=64:');
  const limited = await execute('S3', { max_fds: 128, hold_sec: 1 });
  assert.equal(limited.result.measurements.soft_limit, 64);
  assert.equal(limited.result.measurements.hit_emfile, true);
  target('prlimit --pid "$(cat /run/sshd.pid)" --nofile=1024:');

  // Real SSH denial. No later S1 stage may run.
  target('mv /home/lab/.ssh/authorized_keys /home/lab/.ssh/authorized_keys.disabled');
  assert.equal((await execute('S1')).result.outcome, 'BLOCKED');
  target('mv /home/lab/.ssh/authorized_keys.disabled /home/lab/.ssh/authorized_keys');

  const running = await api('runs', 'POST', { scenario: 'S3', parameters: { max_fds: 32, hold_sec: 8 } }, 202);
  await api('runs', 'POST', { scenario: 'S1' }, 409);
  // Wait until the remote FD operation actually started before requesting cancellation.
  for (let i = 0; i < 40; i++) {
    if ((await api('events?run_id=' + running.run_id)).some(e => e.payload.stage === 'TARGET_FD_START')) break;
    await new Promise(r => setTimeout(r, 100));
  }
  await new Promise(r => setTimeout(r, 300));
  const stopping = await api(`runs/${running.run_id}/stop`, 'POST', {}, 202);
  assert.equal(stopping.state, 'STOPPING');
  const stopped = await finished(running.run_id); assert.equal(stopped.state, 'STOPPED');
  assert.equal(stopped.cleanup_pending, false, JSON.stringify(stopped));
  assert.equal(target('find /home/lab/pbl4-lab -mindepth 1 -type d').trim(), '');

  await new Promise(r => setTimeout(r, 2200));
  const events = await (await fetch('http://127.0.0.1:18080/')).json();
  const schema = JSON.parse(fs.readFileSync('../shared/schemas/attacker-event.schema.json', 'utf8'));
  const validate = new Ajv({ strict: false }).compile(schema);
  for (const e of events) assert.ok(validate(e), JSON.stringify(validate.errors));
  for (const id of [s1.run_id, s2.run_id, s3.run_id, s4.run_id]) assert.ok(events.some(e => e.run_id === id && e.payload.state === 'COMPLETED'));
  const probes = JSON.parse(compose('exec', '-T', 'client', 'cat', '/tmp/probes.json'));
  assert.ok(probes.some(p => p.ok));
  console.log(`PASS: four real scenarios, DAC denial, FD limit, SSH denial, cancel, telemetry schema (${events.length} events), independent Client`);
} finally {
  if (process.env.KEEP_LAB !== '1') compose('down', '-v', '--remove-orphans');
}
