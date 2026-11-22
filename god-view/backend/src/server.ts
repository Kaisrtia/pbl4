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
} from '@shared/schemas';
import type { AttackEvent } from '@shared/schemas/attack-event';
import { readFileSync } from 'node:fs';
import Ajv from 'ajv';
import { TargetDefense, isDefenseSubFlag } from './defense';

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
    socketMetrics.syn_recv = Math.min(socketMetrics.syn_recv + 25, 250);
  } else if (log.attack_tag === 'ARP_SPOOF') {
    poisonArpCache();
    extractSniffedInfoFromLog(log);
  } else if (log.attack_tag === 'RST_INJECTION') {
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
  } else if (log.attack_tag === 'HEAVY_DOS') {
    socketMetrics.established = Math.min(socketMetrics.established + 8, 120);
    socketMetrics.syn_recv = Math.min(socketMetrics.syn_recv + 5, 80);
  } else if (isAttack) {
    socketMetrics.syn_recv = Math.min(socketMetrics.syn_recv + 2, 40);
  } else {
    // Lưu lượng bình thường
    socketMetrics.established = Math.max(8, Math.min(socketMetrics.established + 1, 60));
    socketMetrics.time_wait = Math.min(socketMetrics.time_wait + 1, 30);
    // Nếu đang bị MitM ARP Spoofing, mọi request từ Client đều đi qua Hacker và bị Sniff!
    if (networkState.mitm_active) {
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

  // 2. Cập nhật chỉ số socket
  updateTcpMetrics(log);

  // 3. Phát tán sự kiện thời gian thực qua WebSocket
  io.emit('GOD_VIEW_UPDATE', {
    log,
    buffer_size: telemetryBuffer.size(),
    metrics: socketMetrics,
    network_state: networkState,
    defense_l3_state: defense.state,
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
    metrics: socketMetrics,
    network_state: networkState,
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

  // Phát tín hiệu reset đến tất cả client đang kết nối
  io.emit('GOD_VIEW_RESET', {
    message: 'Telemetry buffer cleared by user.',
    timestamp: new Date().toISOString(),
    network_state: networkState,
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
 * Điểm tiếp nhận thông số Kernel/OS & Network (/proc/net/tcp, /proc/net/arp) từ Telemetry Agent
 */
app.post('/api/telemetry/host', (req: Request, res: Response) => {
  const { metrics, arp_table } = req.body || {};
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

  io.emit('NETWORK_STATE_UPDATE', {
    network_state: networkState,
    metrics: socketMetrics,
  });

  res.status(200).json({
    success: true,
    metrics_updated: true,
    metrics: socketMetrics,
    network_state: networkState,
  });
});

/**
 * POST /api/defense/toggle
 * Chuyển tiếp (proxy) lệnh bật/tắt khiên L3/L7 tới Target App và đồng bộ hóa qua WebSocket
 */
function broadcastDefense() {
  const payload = {
    defense_l3_state: defense.state,
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
  const { enabled, flag } = req.body || {};
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
  try {
    await defense.change({ enabled, flag });
    broadcastDefense();
    res.json({
      success: true,
      defense_l3_app: defense.state,
      current_state: defense.currentState,
      proxied_to_target: true,
      message: `Khiên phòng thủ L3/L7 hiện đang: ${defense.state ? 'BẬT (SECURED)' : 'TẮT (VULNERABLE)'}`,
    });
  } catch {
    broadcastDefense();
    res.status(502).json({
      success: false,
      defense_l3_app: null,
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
      defense_l3_app: defense.state,
      current_state: defense.currentState,
      target_url: config.targetAppUrl,
      proxied_to_target: true,
    });
  } catch {
    broadcastDefense();
    res.status(502).json({
      defense_l3_app: null,
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
    defense_l3_state: defense.state,
    capacity: telemetryBuffer.getCapacity(),
  });

  // Đo RTT Latency: Client gửi ping_rtt kèm client_time, server phản hồi
  socket.on('ping_rtt', (data: { client_time: number }) => {
    socket.emit('pong_rtt', {
      client_time: data.client_time,
      server_time: Date.now(),
    });
  });

  // Client yêu cầu toggle khiên chắn trực tiếp từ socket
  socket.on('TOGGLE_DEFENSE', async (data?: { flag?: string; enabled?: boolean }) => {
    try {
      const flag = data && isDefenseSubFlag(data.flag) ? data.flag : undefined;
      const enabled = data && typeof data.enabled === 'boolean' ? data.enabled : undefined;
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
