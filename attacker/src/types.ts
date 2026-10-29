export type Scenario = 'S1' | 'S2' | 'S3' | 'S4';
export type State = 'STARTING' | 'RUNNING' | 'STOPPING' | 'COMPLETED' | 'STOPPED' | 'FAILED';
export type Outcome = 'OBSERVED' | 'BLOCKED' | 'INCONCLUSIVE';
export interface WorkerResult {
  outcome: Outcome;
  summary: string;
  measurements: Record<string, unknown>;
  cleanup_pending: boolean;
}
export interface Run {
  run_id: string;
  scenario: Scenario;
  state: State;
  parameters: Record<string, number>;
  started_at: string;
  ended_at?: string;
  result?: WorkerResult;
  error?: string;
  cleanup_pending: boolean;
}
export interface AttackEvent {
  schema_version: '1.0';
  event_id: string;
  run_id: string;
  timestamp: string;
  source_node: 'ATTACKER';
  source_ip: string;
  target_ip: string;
  scenario: Scenario;
  event_type: 'RUN_STATE' | 'WORKER_EVENT';
  execution_mode: 'real';
  payload: Record<string, unknown>;
}
