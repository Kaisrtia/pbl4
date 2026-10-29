import { loadEnvFiles } from './config.js';
loadEnvFiles();
const [command = 'list', argument, parameterJson = '{}'] = process.argv.slice(2);
const base = process.env.ATTACKER_URL || `http://127.0.0.1:${process.env.HACKER_API_PORT || 9000}`;
let path = '/api/v1/runs', method = 'GET', body: string | undefined;
if (command === 'start') { method = 'POST'; body = JSON.stringify({ scenario: argument, parameters: JSON.parse(parameterJson) }); }
else if (command === 'stop') { method = 'POST'; path += `/${encodeURIComponent(argument || '')}/stop`; }
else if (command === 'status') path += `/${encodeURIComponent(argument || '')}`;
else if (command === 'preflight') path = '/api/v1/preflight';
else if (command === 'scenarios') path = '/api/v1/scenarios';
else if (command !== 'list') throw new Error('Usage: cli list | scenarios | preflight | start S1|S2|S3|S4 [JSON] | status ID | stop ID');
const response = await fetch(base + path, { method, body, headers: {
  'Content-Type': 'application/json', Authorization: `Bearer ${process.env.ATTACKER_API_TOKEN || ''}`,
}, signal: AbortSignal.timeout(5000) });
console.log(JSON.stringify(await response.json(), null, 2));
if (!response.ok) process.exitCode = 1;
