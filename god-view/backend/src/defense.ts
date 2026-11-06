/** Target is authoritative. Never report a local toggle as a successful defense. */
export class TargetDefense {
  state: boolean | null = null;
  constructor(private readonly targetUrl: string) {}

  private async request(endpoint: string, body?: unknown): Promise<boolean> {
    try {
      const response = await fetch(`${this.targetUrl}/api/defense/${endpoint}`, {
        method: body === undefined ? 'GET' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(1500),
      });
      if (!response.ok) throw new Error(`Target returned HTTP ${response.status}`);
      const data = await response.json() as { flags?: { l3_master?: unknown }; current_state?: { l3_master?: unknown } };
      const value = (endpoint === 'status' ? data.flags : data.current_state)?.l3_master;
      if (typeof value !== 'boolean') throw new Error('Target returned an invalid defense state');
      this.state = value;
      return value;
    } catch (error) {
      this.state = null;
      throw error;
    }
  }

  read() { return this.request('status'); }

  change(enabled?: boolean) {
    return enabled === undefined ? this.request('toggle', {}) : this.request('set', {
      l3_master: enabled, anti_sqli: enabled, rate_limit: enabled, input_sanitization: enabled,
    });
  }
}
