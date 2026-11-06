/** Runtime validation uses attacker-event.schema.json. */
export interface AttackEvent {
  schema_version: '1.0';
  event_id: string;
  run_id: string;
  timestamp: string;
  source_node: 'ATTACKER';
  source_ip: string;
  target_ip: string;
  scenario: 'S1' | 'S2' | 'S3' | 'S4';
  event_type: 'RUN_STATE' | 'WORKER_EVENT';
  execution_mode: 'real';
  payload: Record<string, unknown>;
}
