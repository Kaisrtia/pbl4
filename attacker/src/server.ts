import { createServer, type IncomingMessage } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { timingSafeEqual } from 'node:crypto';
import { createConnection } from 'node:net';
import { attackerRoot, InputError, type Config } from './config.js';
import { scenarios } from './attacks/catalog.js';
import { ConflictError, Runs } from './services/runs.js';
import { Telemetry } from './services/telemetry.js';
import { Receiver } from './services/receiver.js';

async function jsonBody(req: IncomingMessage) {
  if (!req.headers['content-type']?.startsWith('application/json')) throw new InputError('Content-Type must be application/json');
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body) > 8192) throw new InputError('Request body too large');
  }
  try { return JSON.parse(body || '{}') as unknown; } catch { throw new InputError('Invalid JSON'); }
}
async function reachable(host: string, port: number) {
  return new Promise<boolean>(resolve => {
    const socket = createConnection({ host, port });
    const finish = (result: boolean) => { socket.destroy(); resolve(result); };
    socket.setTimeout(1500, () => finish(false));
    socket.once('connect', () => finish(true)); socket.once('error', () => finish(false));
  });
}
export async function startServer(config: Config) {
  if (!['127.0.0.1', '::1', 'localhost'].includes(config.host) && config.apiToken.length < 16)
    throw new Error('A non-loopback controller requires ATTACKER_API_TOKEN (at least 16 characters)');
  const telemetry = new Telemetry(config);
  const receiver = new Receiver(config);
  const runs = new Runs(config, telemetry, receiver);
  try { await receiver.start(); } catch (e) { telemetry.close(); throw e; }
  const server = createServer(async (req, res) => {
    const send = (status: number, body: unknown) => {
      res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify(body));
    };
    try {
      const url = new URL(req.url || '/', 'http://localhost');
      if (url.pathname === '/' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end(readFileSync(join(attackerRoot, 'public/index.html'))); return;
      }
      if (url.pathname === '/app.js' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8' }); res.end(readFileSync(join(attackerRoot, 'public/app.js'))); return;
      }
      if (url.pathname === '/health' && req.method === 'GET') { send(200, { status: 'ok', service: 'attacker' }); return; }
      const supplied = String(req.headers.authorization || '').replace(/^Bearer /, '');
      if (config.apiToken && (Buffer.byteLength(supplied) !== Buffer.byteLength(config.apiToken) ||
          !timingSafeEqual(Buffer.from(supplied), Buffer.from(config.apiToken)))) { send(401, { error: 'Invalid API token' }); return; }
      if (req.headers.origin && req.headers.origin !== `http://${req.headers.host}` && req.headers.origin !== `https://${req.headers.host}`) {
        send(403, { error: 'Cross-origin browser control is disabled; use the God-View backend' }); return;
      }
      if (url.pathname === '/api/v1/scenarios' && req.method === 'GET') { send(200, scenarios.map(({ script: _, ...s }) => s)); return; }
      if (url.pathname === '/api/v1/config' && req.method === 'GET') {
        send(200, { target_ip: config.targetIp, ssh_port: config.sshPort, http_port: config.httpPort,
          attacker_ip: config.receiverIp, receiver_port: config.receiverPort, limits: config.limits,
          telemetry: telemetry.status(), journal_error: runs.journalError, execution_mode: 'real' }); return;
      }
      if (url.pathname === '/api/v1/preflight' && req.method === 'GET') {
        const [ssh, http] = await Promise.all([reachable(config.targetIp, config.sshPort), reachable(config.targetIp, config.httpPort)]);
        send(200, { target_ssh_reachable: ssh, target_http_reachable: http,
          known_hosts_present: existsSync(config.ssh.known_hosts),
          credential_present: existsSync(config.ssh.password_file || config.ssh.key_file),
          note: 'TCP reachability does not prove authentication or reverse connectivity. S4 verifies the reverse path.' }); return;
      }
      if (url.pathname === '/api/v1/events' && req.method === 'GET') { send(200, telemetry.events(url.searchParams.get('run_id') || undefined)); return; }
      if (url.pathname === '/api/v1/runs' && req.method === 'GET') { send(200, runs.list()); return; }
      if (url.pathname === '/api/v1/runs' && req.method === 'POST') { send(202, runs.start(await jsonBody(req))); return; }
      const match = url.pathname.match(/^\/api\/v1\/runs\/([0-9a-f-]{36})(\/stop)?$/);
      if (match && ((req.method === 'GET' && !match[2]) || (req.method === 'POST' && match[2]))) {
        const run = match[2] ? runs.stop(match[1]!) : runs.get(match[1]!);
        send(run ? (match[2] && run.state === 'STOPPING' ? 202 : 200) : 404, run || { error: 'Unknown run' }); return;
      }
      send(404, { error: 'Unknown endpoint' });
    } catch (error) {
      send(error instanceof InputError ? 400 : error instanceof ConflictError ? 409 : 500,
        { error: error instanceof InputError || error instanceof ConflictError ? error.message : 'Controller operation failed; inspect local logs' });
    }
  });
  server.requestTimeout = 10000;
  try {
    await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(config.port, config.host, resolve); });
  } catch (e) { await receiver.close(); telemetry.close(); throw e; }
  return { server, runs, telemetry, receiver, async close() {
    server.close(); await runs.close(); await receiver.close(); telemetry.close(); server.closeAllConnections();
  } };
}
