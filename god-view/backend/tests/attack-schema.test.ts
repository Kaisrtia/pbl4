import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import Ajv from 'ajv';
import type { AttackEvent } from '../../../shared/schemas/attack-event';

const schema = JSON.parse(readFileSync('../../shared/schemas/attacker-event.schema.json', 'utf8'));
const validate = new Ajv({ strict: false }).compile(schema);

test('all six scenarios use the v1 worker envelope', () => {
  const scenarios: AttackEvent['scenario'][] = ['S1', 'S2', 'S3', 'S4', 'S5', 'S6'];
  const run_id = 'ca773d64-6100-429c-9902-66b93eb8f272';
  for (const scenario of scenarios) {
    const event: AttackEvent = {
      scenario, schema_version: '1.0', execution_mode: 'real', event_type: 'WORKER_EVENT',
      run_id, event_id: 'schema-test',
      source_node: 'ATTACKER', source_ip: '192.0.2.1', target_ip: '192.0.2.2',
      timestamp: '2026-01-01T00:00:00Z', payload: { type: 'ready', run_id, scenario },
    };
    assert.equal(validate(event), true);
    assert.equal(validate({ ...event, payload: { type: 'ready', scenario } }), false);
    assert.equal(validate({ ...event, scenario: 'S7' }), false);
  }
});
