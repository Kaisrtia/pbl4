import { isIP } from 'node:net';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';

export const attackerRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export class InputError extends Error {}
export function integer(value: unknown, name: string, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max)
    throw new InputError(`${name} must be an integer between ${min} and ${max}`);
  return value;
}
export function loadConfig(env: NodeJS.ProcessEnv = process.env) {
  const port = (name: string, fallback: number) => integer(Number(env[name] ?? fallback), name, 1, 65535);
  const ip = (name: string, fallback: string) => {
    const value = env[name] || fallback;
    if (isIP(value) !== 4) throw new Error(`${name} must be an IPv4 address`);
    return value;
  };
  const targetIp = ip('SERVER_IP', '172.20.0.20');
  const receiverIp = ip('HACKER_IP', '172.20.0.66');
  const telemetryUrl = env.GODVIEW_TELEMETRY_URL || `http://${env.GODVIEW_IP || '172.20.0.99'}:${env.GODVIEW_BACKEND_PORT || '8080'}/api/events/attack`;
  const url = new URL(telemetryUrl);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Telemetry requires http(s)');
  const sandbox = env.LAB_SANDBOX || '/home/lab/pbl4-lab';
  if (!/^\/[a-zA-Z0-9_./-]+$/.test(sandbox) || sandbox.split('/').includes('..') || sandbox === '/')
    throw new Error('LAB_SANDBOX must be an absolute dedicated lab directory');
  return {
    host: env.ATTACKER_BIND || '127.0.0.1',
    port: port('HACKER_API_PORT', 9000),
    receiverPort: port('EXFIL_RECEIVER_PORT', 9001),
    receiverBind: env.RECEIVER_BIND || '0.0.0.0',
    receiverIp, targetIp,
    httpPort: port('SERVER_PORT', 8000), sshPort: port('TARGET_SSH_PORT', 22),
    telemetryUrl,
    apiToken: env.ATTACKER_API_TOKEN || '',
    python: env.PYTHON_BIN || 'python3',
    scriptsDir: resolve(attackerRoot, 'scripts'),
    dataDir: resolve(env.ATTACKER_DATA_DIR || resolve(attackerRoot, '.data')),
    ssh: {
      username: env.LAB_SSH_USER || 'lab',
      known_hosts: env.LAB_KNOWN_HOSTS || '/run/lab-secrets/known_hosts',
      key_file: env.LAB_SSH_KEY_FILE || '/run/lab-secrets/id_ed25519',
      password_file: env.LAB_SSH_PASSWORD_FILE || '',
      sandbox,
    },
    limits: { pps: 150, duration_sec: 15, max_fds: 256, hold_sec: 8 },
  };
}
export type Config = ReturnType<typeof loadConfig>;
export function loadEnvFiles() {
  // Existing environment always wins; attacker/.env overrides defaults from the root file.
  for (const path of [resolve(attackerRoot, '.env'), resolve(attackerRoot, '../.env')]) {
    if (existsSync(path)) process.loadEnvFile(path);
  }
}
