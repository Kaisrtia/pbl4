import { createServer, type Server } from 'node:http';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Config } from '../config.js';

interface Receipt { bytes: number; sha256: string; received_at: string; }
export class Receiver {
  private allowed = new Map<string, { token: string; receipt?: Receipt }>();
  private server?: Server;
  constructor(private config: Config) {}
  register(runId: string) {
    const token = randomBytes(24).toString('hex');
    this.allowed.set(runId, { token });
    return { url: `http://${this.config.receiverIp}:${this.config.receiverPort}/receive/${runId}`, token };
  }
  receipt(runId: string) { return this.allowed.get(runId)?.receipt; }
  unregister(runId: string) { this.allowed.delete(runId); }
  async start() {
    this.server = createServer(async (req, res) => {
      const entry = this.allowed.get((req.url || '').replace(/^\/receive\//, ''));
      const token = String(req.headers.authorization || '').replace(/^Bearer /, '');
      if (req.method !== 'POST' || !req.url?.startsWith('/receive/') || !entry ||
          Buffer.byteLength(token) !== Buffer.byteLength(entry.token) || !timingSafeEqual(Buffer.from(token), Buffer.from(entry.token))) {
        res.writeHead(403).end(); req.resume(); return;
      }
      if (entry.receipt) { res.writeHead(409).end(); req.resume(); return; }
      let length = 0;
      const chunks: Buffer[] = [];
      req.setTimeout(5000, () => req.destroy());
      try {
        for await (const chunk of req) {
          length += chunk.length;
          if (length > 4096) { res.writeHead(413).end(); req.resume(); return; }
          chunks.push(chunk);
        }
        if (!length) { res.writeHead(400).end(); return; }
        // Keep only the receipt, never persist sample content.
        entry.receipt = { bytes: length, sha256: createHash('sha256').update(Buffer.concat(chunks)).digest('hex'), received_at: new Date().toISOString() };
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(entry.receipt));
      } catch { if (!res.headersSent) res.writeHead(400).end(); }
    });
    await new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject);
      this.server!.listen(this.config.receiverPort, this.config.receiverBind, resolve);
    });
    this.config.receiverPort = (this.server.address() as { port: number }).port;
  }
  async close() {
    this.server?.closeAllConnections();
    if (this.server?.listening) await new Promise<void>(resolve => this.server!.close(() => resolve()));
  }
}
