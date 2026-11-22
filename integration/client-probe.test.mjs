import assert from 'node:assert/strict';
import { test } from 'node:test';
import { failedProbe } from './client-probe.mjs';

test('client reports only explicit reset evidence and omits raw error details', () => {
  for (const [error, expected] of [
    [new TypeError('fetch failed', { cause: { code: 'ECONNRESET' } }), 'ECONNRESET'],
    [{ code: 'ECONNRESET' }, 'ECONNRESET'],
    [new DOMException('deadline exceeded', 'TimeoutError'), 'TIMEOUT'],
    [{ cause: { code: 'UND_ERR_BODY_TIMEOUT' } }, 'TIMEOUT'],
    [{ cause: { code: 'UND_ERR_SOCKET' } }, 'SOCKET_ERROR'],
    [new Error('response data must stay private'), 'CLIENT_ERROR'],
    [{ cause: { code: 'unrecognized value must stay private' } }, 'CLIENT_ERROR'],
  ]) {
    const probe = failedProbe(error, 3, 5);
    assert.equal(probe.error, expected);
    assert.equal(probe.status_source, 'client');
    assert.equal(probe.status_code, 503);
    assert.equal(probe.ok, false);
    assert.equal(probe.iteration, 3);
    assert.equal(probe.latency_ms, 5);
    assert.doesNotMatch(JSON.stringify(probe), /must stay private/);
  }
});
