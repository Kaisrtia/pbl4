import type {
  DefenseLayerId,
  ThreeLayerDefenseState,
} from '@shared/schemas';

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

const VALID_LAYERS: ReadonlySet<string> = new Set(['l1', 'l2', 'l3']);

export function isDefenseSubFlag(flag: unknown): flag is DefenseSubFlag {
  return typeof flag === 'string' && VALID_SUB_FLAGS.has(flag);
}

export function isDefenseLayerId(layer: unknown): layer is DefenseLayerId {
  return typeof layer === 'string' && VALID_LAYERS.has(layer);
}

/** Target is authoritative for L3; God-View Hub coordinates L1 (Network) & L2 (OS) alongside L3 (App). */
export class TargetDefense {
  state: boolean | null = null;
  currentState: DefenseStateFlags | null = null;
  l1Network: boolean = false;
  l2Os: boolean = false;

  constructor(private readonly targetUrl: string) {}
  private pending: Promise<unknown> = Promise.resolve();

  getLayersState(): ThreeLayerDefenseState {
    return {
      l1_network: this.l1Network,
      l2_os: this.l2Os,
      l3_app: this.state,
      l3_subflags: this.currentState
        ? {
            anti_sqli: this.currentState.anti_sqli,
            rate_limit: this.currentState.rate_limit,
            input_sanitization: this.currentState.input_sanitization,
          }
        : null,
      updated_at: new Date().toISOString(),
    };
  }

  setLayer(layer: 'l1' | 'l2', enabled?: boolean): boolean {
    if (layer === 'l1') {
      this.l1Network = typeof enabled === 'boolean' ? enabled : !this.l1Network;
      return this.l1Network;
    }
    this.l2Os = typeof enabled === 'boolean' ? enabled : !this.l2Os;
    return this.l2Os;
  }

  /**
   * W6-T1 & W6-T3: Khôi phục toàn bộ trạng thái sạch cho cả 3 lớp khiên và gọi POST /api/system/reset trên Target App
   */
  async resetTargetAndLayers(): Promise<{
    target_reset: boolean;
    target_details: Record<string, unknown> | null;
  }> {
    this.l1Network = false;
    this.l2Os = false;
    try {
      const response = await fetch(`${this.targetUrl}/api/system/reset`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
        signal: AbortSignal.timeout(2500),
      });
      if (response.ok) {
        const data = (await response.json().catch(() => null)) as Record<string, unknown> | null;
        const resetSummary =
          data && typeof data.reset_summary === 'object' && data.reset_summary !== null
            ? (data.reset_summary as Record<string, unknown>)
            : null;
        const flagsReset =
          resetSummary &&
          typeof resetSummary.defense_flags_reset === 'object' &&
          resetSummary.defense_flags_reset !== null
            ? (resetSummary.defense_flags_reset as Record<string, unknown>)
            : null;
        if (flagsReset && typeof flagsReset.l3_master === 'boolean') {
          this.state = flagsReset.l3_master;
          this.currentState = {
            l3_master: flagsReset.l3_master,
            anti_sqli:
              typeof flagsReset.anti_sqli === 'boolean' ? flagsReset.anti_sqli : flagsReset.l3_master,
            rate_limit:
              typeof flagsReset.rate_limit === 'boolean' ? flagsReset.rate_limit : flagsReset.l3_master,
            input_sanitization:
              typeof flagsReset.input_sanitization === 'boolean'
                ? flagsReset.input_sanitization
                : flagsReset.l3_master,
          };
          return { target_reset: true, target_details: resetSummary };
        }
      }
    } catch {
      // Nếu Target chưa hỗ trợ /api/system/reset hoặc đang chạy mock server, fallback gọi change(false)
    }

    try {
      await this.change(false);
      return { target_reset: true, target_details: null };
    } catch {
      this.state = null;
      this.currentState = null;
      return { target_reset: false, target_details: null };
    }
  }

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
