import { InputError, integer } from '../config.js';
import type { Scenario } from '../types.js';

export const scenarios = [
  { id: 'S1', name: 'Chuỗi SSH lab', script: 'ssh_chain.py', description: 'SSH thật; reconnect và thao tác tệp mẫu có phạm vi. Không cài backdoor hoặc xóa log hệ thống.', defaults: {} },
  { id: 'S2', name: 'SYN có giới hạn', script: 'syn_flood.py', description: 'Raw SYN qua Scapy; không tự chuyển sang TCP connect khi thiếu quyền.', defaults: { pps: 50, duration_sec: 5 } },
  { id: 'S3', name: 'Giới hạn file descriptor', script: 'fd_exhaustion.py', description: 'Tiến trình Python riêng trên Target qua SSH; đọc giới hạn FD thật.', defaults: { max_fds: 128, hold_sec: 3 } },
  { id: 'S4', name: 'Truyền tệp mẫu', script: 'sample_transfer.py', description: 'Target gửi sample.txt (tối đa 4 KiB) đến receiver; đối chiếu SHA-256.', defaults: {} },
] as const;

export function validateStart(body: unknown): { scenario: Scenario; parameters: Record<string, number> } {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new InputError('Expected a JSON object');
  const b = body as Record<string, unknown>;
  if (Object.keys(b).some(k => !['scenario', 'parameters'].includes(k))) throw new InputError('Unknown request field');
  const definition = scenarios.find(s => s.id === b.scenario);
  if (!definition) throw new InputError('scenario must be S1, S2, S3 or S4');
  const parameters = b.parameters ?? {};
  if (typeof parameters !== 'object' || !parameters || Array.isArray(parameters)) throw new InputError('parameters must be an object');
  const p = parameters as Record<string, unknown>;
  if (Object.keys(p).some(k => !(k in definition.defaults))) throw new InputError('Unknown scenario parameter');
  const result: Record<string, number> = {};
  if (definition.id === 'S2') {
    result.pps = integer(p.pps ?? 50, 'pps', 1, 150);
    result.duration_sec = integer(p.duration_sec ?? 5, 'duration_sec', 1, 15);
  }
  if (definition.id === 'S3') {
    result.max_fds = integer(p.max_fds ?? 128, 'max_fds', 8, 256);
    result.hold_sec = integer(p.hold_sec ?? 3, 'hold_sec', 1, 8);
  }
  return { scenario: definition.id, parameters: result };
}
