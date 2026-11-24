import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

for (const phase of ['request', 'interval']) {
  test(`SIGTERM interrupts the client during ${phase}`, { timeout: 5000 }, async t => {
    const dir = await mkdtemp(join(tmpdir(), 'pbl4-client-'));
    const probe = join(dir, 'probe.json');
    t.after(() => rm(dir, { recursive: true, force: true }));
    const stub = phase === 'request'
      ? `globalThis.fetch = (_, { signal }) => new Promise((_, reject) => {
           const timer = setTimeout(() => reject(new Error('fixture timed out')), 10000);
           signal.addEventListener('abort', () => {
             clearTimeout(timer);
             reject(signal.reason);
           }, { once: true });
           process.send('ready');
         });`
      : `globalThis.fetch = async () => Response.json({});
         console.log = () => process.send('ready');`;
    const child = fork(new URL('./client.mjs', import.meta.url), [], {
      silent: true,
      execArgv: ['--import', 'data:text/javascript,' + encodeURIComponent(stub)],
      env: { ...process.env, CLIENT_INTERVAL_MS: '30000', PROBE_FILE_PATH: probe },
    });
    t.after(() => child.kill('SIGKILL'));
    const deadline = AbortSignal.timeout(2000);
    const [message] = await once(child, 'message', { signal: deadline });
    assert.equal(message, 'ready');
    const exit = once(child, 'exit', { signal: AbortSignal.timeout(1500) });
    child.kill('SIGTERM');
    assert.deepEqual(await exit, [0, null]);
    if (phase === 'request') {
      await assert.rejects(readFile(probe), { code: 'ENOENT' });
    } else {
      assert.equal(JSON.parse(await readFile(probe)).ok, true);
    }
  });
}
