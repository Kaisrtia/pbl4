export interface DefenseStateFlags {
  l3_master: boolean;
  anti_sqli: boolean;
  rate_limit: boolean;
  input_sanitization: boolean;
}

export type DefenseSubFlag = keyof Omit<DefenseStateFlags, 'l3_master'>;

const VALID_SUB_FLAGS: ReadonlySet<string> = new Set([
  'anti_sqli',
  'rate_limit',
  'input_sanitization',
]);

export function isDefenseSubFlag(flag: unknown): flag is DefenseSubFlag {
  return typeof flag === 'string' && VALID_SUB_FLAGS.has(flag);
}

/** Target is authoritative. Never report a local toggle as a successful defense. */
export class TargetDefense {
  state: boolean | null = null;
  currentState: DefenseStateFlags | null = null;

  constructor(private readonly targetUrl: string) {}
  private pending: Promise<unknown> = Promise.resolve();

  // Serialize reads and writes so a slow poll cannot overwrite a newer toggle.
  private enqueue(endpoint: string, body?: unknown): Promise<boolean> {
    const next = this.pending.then(() => this.request(endpoint, body));
    this.pending = next.catch(() => undefined);
    return next;
  }

  private async request(endpoint: string, body?: unknown): Promise<boolean> {
    try {
      const response = await fetch(`${this.targetUrl}/api/defense/${endpoint}`, {
        method: body === undefined ? 'GET' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(1500),
      });
      if (!response.ok) throw new Error(`Target returned HTTP ${response.status}`);
      const data = await response.json() as {
        flags?: Record<string, unknown>;
        current_state?: Record<string, unknown>;
      };
      const rawState = endpoint === 'status' ? data.flags : data.current_state;
      const value = rawState?.l3_master;
      if (typeof value !== 'boolean') throw new Error('Target returned an invalid defense state');

      this.state = value;
      this.currentState = {
        l3_master: value,
        anti_sqli: typeof rawState?.anti_sqli === 'boolean' ? rawState.anti_sqli : value,
        rate_limit: typeof rawState?.rate_limit === 'boolean' ? rawState.rate_limit : value,
        input_sanitization:
          typeof rawState?.input_sanitization === 'boolean' ? rawState.input_sanitization : value,
      };
      return value;
    } catch (error) {
      this.state = null;
      this.currentState = null;
      throw error;
    }
  }

  read() {
    return this.enqueue('status');
  }

  change(options?: boolean | { enabled?: boolean; flag?: DefenseSubFlag }) {
    if (typeof options === 'boolean') {
      return this.enqueue('set', {
        l3_master: options,
        anti_sqli: options,
        rate_limit: options,
        input_sanitization: options,
      });
    }
    if (options && options.enabled !== undefined) {
      return this.enqueue('set', {
        l3_master: options.enabled,
        anti_sqli: options.enabled,
        rate_limit: options.enabled,
        input_sanitization: options.enabled,
      });
    }
    if (options && options.flag !== undefined) {
      return this.enqueue('toggle', { flag: options.flag });
    }
    return this.enqueue('toggle', {});
  }
}
