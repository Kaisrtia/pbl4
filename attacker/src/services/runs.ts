import { spawn, type ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { readdirSync, readFileSync, writeFileSync, renameSync } from 'node:fs';
import type { Config } from '../config.js';
import { scenarios, validateStart } from '../attacks/catalog.js';
import type { Run, WorkerResult } from '../types.js';
import { Telemetry } from './telemetry.js';
import { Receiver } from './receiver.js';

export class ConflictError extends Error {}
const activeStates = new Set(['STARTING', 'RUNNING', 'STOPPING']);
type Launch = (script: string) => { command: string; args: string[] };

export class Runs {
  private records = new Map<string, Run>();
  private active?: { run: Run; child: ChildProcess; watchdog: NodeJS.Timeout; killer?: NodeJS.Timeout };
  journalError: string | null = null;
  constructor(private config: Config, private telemetry: Telemetry, private receiver: Receiver,
    private launch: Launch = script => ({ command: config.python, args: ['-u', join(config.scriptsDir, script)] }),
    private graceMs = 5000, private watchdogMs = 45000) {
    for (const name of readdirSync(config.dataDir).filter(n => n.endsWith('.run.json'))) {
      const run = JSON.parse(readFileSync(join(config.dataDir, name), 'utf8')) as Run;
      if (activeStates.has(run.state)) {
        run.state = 'FAILED'; run.error = 'Controller restarted; inspect Target cleanup before retrying';
        run.cleanup_pending = true; run.ended_at = new Date().toISOString(); this.save(run);
      }
      this.records.set(run.run_id, run);
    }
  }
  private save(run: Run) {
    const path = join(this.config.dataDir, `${run.run_id}.run.json`);
    writeFileSync(path + '.tmp', JSON.stringify(run)); renameSync(path + '.tmp', path);
  }
  private publish(run: Run, kind: 'RUN_STATE' | 'WORKER_EVENT', payload: Record<string, unknown>) {
    try { this.save(run); this.telemetry.emit(run, kind, payload); }
    catch { this.journalError = 'Cannot persist run evidence'; if (this.active?.run === run) this.stop(run.run_id, this.journalError); }
  }
  list() { return [...this.records.values()].sort((a, b) => b.started_at.localeCompare(a.started_at)).slice(0, 100); }
  get(id: string) { return this.records.get(id); }
  start(body: unknown) {
    if (this.active) throw new ConflictError('A run is already active; stop it or wait for completion');
    if (this.journalError) throw new Error(this.journalError);
    const input = validateStart(body);
    const run: Run = { run_id: randomUUID(), ...input, state: 'STARTING', started_at: new Date().toISOString(), cleanup_pending: false };
    this.save(run);
    this.records.set(run.run_id, run);
    const script = scenarios.find(s => s.id === run.scenario)!.script;
    const command = this.launch(script);
    const receiver = run.scenario === 'S4' ? this.receiver.register(run.run_id) : undefined;
    const child = spawn(command.command, command.args, {
      detached: process.platform !== 'win32', shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const watchdog = setTimeout(() => this.stop(run.run_id, 'Run deadline exceeded'), this.watchdogMs);
    this.active = { run, child, watchdog };
    this.publish(run, 'RUN_STATE', { state: run.state });
    let buffer = '';
    let finalResult: WorkerResult | undefined;
    let protocolError: string | undefined;
    let stderrBytes = 0;
    const fail = (message: string) => {
      protocolError = message;
      this.stop(run.run_id, message);
    };
    child.stdout!.setEncoding('utf8');
    child.stdout!.on('data', (chunk: string) => {
      buffer += chunk;
      if (Buffer.byteLength(buffer) > 65536) { fail('Worker output exceeded limit'); return; }
      let position: number;
      while ((position = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, position); buffer = buffer.slice(position + 1);
        if (!line.trim()) continue;
        try {
          const event = JSON.parse(line) as Record<string, unknown>;
          if (event.run_id !== run.run_id || !['ready', 'progress', 'result', 'error'].includes(String(event.type))) throw new Error();
          if (finalResult) throw new Error();
          if (event.type === 'ready' && run.state === 'STARTING') {
            run.state = 'RUNNING'; this.publish(run, 'RUN_STATE', { state: run.state });
          }
          if (event.type === 'error') { protocolError = String(event.message || 'Worker failed'); }
          if (event.type === 'result') {
            const result = event.result as WorkerResult;
            if (!result || !['OBSERVED', 'BLOCKED', 'INCONCLUSIVE'].includes(result.outcome) ||
                typeof result.summary !== 'string' || typeof result.cleanup_pending !== 'boolean' ||
                !result.measurements || typeof result.measurements !== 'object' || Array.isArray(result.measurements)) throw new Error();
            finalResult = result;
          }
          this.publish(run, 'WORKER_EVENT', event);
        } catch { fail('Invalid worker protocol'); }
      }
    });
    // Diagnostics are not exposed: SSH errors may contain paths or credential details.
    child.stderr!.on('data', (chunk: Buffer) => { stderrBytes += chunk.length; });
    child.on('error', () => { protocolError = 'Worker could not start (check Python and dependencies)'; });
    child.stdin!.on('error', () => { if (run.state !== 'STOPPING') protocolError = 'Worker input pipe failed'; });
    child.on('close', (code, signal) => {
      const active = this.active;
      if (!active || active.run !== run) return;
      clearTimeout(active.watchdog); clearTimeout(active.killer);
      if (buffer.trim()) protocolError ||= 'Incomplete worker output';
      if (run.scenario === 'S4' && finalResult?.outcome === 'OBSERVED') {
        const receipt = this.receiver.receipt(run.run_id);
        if (!receipt || receipt.sha256 !== finalResult.measurements.sha256 || receipt.bytes !== finalResult.measurements.bytes)
          protocolError = 'Sender result does not match receiver receipt';
        else finalResult.measurements.receiver_receipt = receipt;
      }
      this.receiver.unregister(run.run_id);
      run.cleanup_pending = finalResult?.cleanup_pending ?? true;
      if (run.error || protocolError || (run.state !== 'STOPPING' && (code !== 0 || !finalResult))) {
        run.state = 'FAILED'; run.error ||= protocolError || `Worker exited without a valid result (${code ?? signal}; diagnostic bytes: ${stderrBytes})`;
      } else if (run.state === 'STOPPING') run.state = 'STOPPED';
      else run.state = 'COMPLETED';
      run.result = finalResult;
      run.ended_at = new Date().toISOString();
      this.active = undefined;
      this.publish(run, 'RUN_STATE', { state: run.state, error: run.error, cleanup_pending: run.cleanup_pending, result: run.result });
    });
    child.stdin!.end(JSON.stringify({ schema_version: '1.0', run_id: run.run_id, scenario: run.scenario,
      parameters: run.parameters, target: { ip: this.config.targetIp, ssh_port: this.config.sshPort, http_port: this.config.httpPort },
      ssh: this.config.ssh, receiver }));
    return run;
  }
  stop(id: string, error?: string) {
    const run = this.records.get(id);
    if (!run) return undefined;
    const active = this.active;
    if (!active || active.run !== run || run.state === 'STOPPING') return run;
    run.state = 'STOPPING'; if (error) run.error = error;
    // Stop is acknowledged now; terminal state is emitted only after the child closes.
    this.publish(run, 'RUN_STATE', { state: run.state, reason: error || 'requested' });
    const signal = (name: NodeJS.Signals) => {
      if (!active.child.pid) return;
      try {
        if (process.platform === 'win32') active.child.kill(name);
        else process.kill(-active.child.pid, name);
      } catch { /* Already exited. */ }
    };
    signal('SIGTERM');
    active.killer = setTimeout(() => signal('SIGKILL'), this.graceMs);
    return run;
  }
  async close() {
    if (!this.active) return;
    const child = this.active.child;
    const closed = new Promise<void>(resolve => child.once('close', () => resolve()));
    this.stop(this.active.run.run_id);
    await closed;
  }
}
