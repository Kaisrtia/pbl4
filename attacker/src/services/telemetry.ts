import { appendFileSync, mkdirSync, readFileSync, readdirSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { Config } from '../config.js';
import type { AttackEvent, Run } from '../types.js';

export class Telemetry {
  private sending = false;
  private timer: NodeJS.Timeout;
  private stopped = false;
  private pending = new Map<string, AttackEvent>();
  private history: AttackEvent[] = [];
  lastError: string | null = null;
  dropped = 0;
  constructor(private config: Config) {
    mkdirSync(join(config.dataDir, 'outbox'), { recursive: true });
    for (const file of readdirSync(join(config.dataDir, 'outbox')).filter(f => f.endsWith('.json'))) {
      try {
        const event = JSON.parse(readFileSync(join(config.dataDir, 'outbox', file), 'utf8')) as AttackEvent;
        this.pending.set(event.event_id, event);
      } catch { this.lastError = 'Unreadable event in outbox'; }
    }
    this.timer = setInterval(() => void this.flush(), 2000);
    this.timer.unref();
  }
  emit(run: Run, eventType: AttackEvent['event_type'], payload: Record<string, unknown>) {
    const event: AttackEvent = {
      schema_version: '1.0', event_id: randomUUID(), run_id: run.run_id,
      timestamp: new Date().toISOString(), source_node: 'ATTACKER',
      source_ip: this.config.receiverIp, target_ip: this.config.targetIp,
      scenario: run.scenario, event_type: eventType, execution_mode: 'real', payload: structuredClone(payload),
    };
    // Persist before attempting delivery. No network wait in the run lifecycle.
    appendFileSync(join(this.config.dataDir, `${run.run_id}.jsonl`), JSON.stringify(event) + '\n');
    this.history.push(event);
    if (this.history.length > 500) this.history.shift();
    if (this.pending.size >= 500) {
      const oldest = this.pending.keys().next().value!;
      this.pending.delete(oldest);
      unlinkSync(join(this.config.dataDir, 'outbox', `${oldest}.json`));
      this.dropped++;
    }
    const destination = join(this.config.dataDir, 'outbox', `${event.event_id}.json`);
    writeFileSync(destination + '.tmp', JSON.stringify(event));
    renameSync(destination + '.tmp', destination);
    this.pending.set(event.event_id, event);
    return event;
  }
  events(runId?: string) { return this.history.filter(e => !runId || e.run_id === runId); }
  status() { return { pending: this.pending.size, delivery_error: this.lastError, dropped_from_outbox: this.dropped }; }
  async flush() {
    if (this.sending || this.stopped) return;
    this.sending = true;
    try {
      for (const [id, event] of this.pending) {
        if (this.stopped) break;
        try {
          const response = await fetch(this.config.telemetryUrl, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(event), signal: AbortSignal.timeout(1500),
          });
          await response.body?.cancel();
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          unlinkSync(join(this.config.dataDir, 'outbox', `${id}.json`));
          this.pending.delete(id);
          this.lastError = null;
        } catch (error) { this.lastError = (error as Error).message; break; }
      }
    } finally { this.sending = false; }
  }
  close() { this.stopped = true; clearInterval(this.timer); }
}
