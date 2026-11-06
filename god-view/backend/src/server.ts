import express, { Request, Response } from 'express';
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';
import cors from 'cors';
import path from 'path';
import { config } from './config';
import { RingBuffer } from './ring-buffer';
import type { TelemetryLog } from '@shared/schemas';
import type { AttackEvent } from '@shared/schemas/attack-event';
import { readFileSync } from 'node:fs';
import Ajv from 'ajv';
import { TargetDefense } from './defense';

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
  source: 'simulated',
  established: 12,
  syn_recv: 0,
  time_wait: 4,
  last_updated: new Date().toISOString(),
};

/**
 * Cập nhật động các chỉ số kết nối TCP dựa trên các bản tin Telemetry nhận được
 */
function updateTcpMetrics(log: TelemetryLog) {
  const isAttack = Boolean(log.is_suspicious || (log.attack_tag && log.attack_tag !== 'NORMAL'));

  if (log.attack_tag === 'SYN_FLOOD') {
    socketMetrics.syn_recv = Math.min(socketMetrics.syn_recv + 15, 250);
  } else if (log.attack_tag === 'HEAVY_DOS') {
    socketMetrics.established = Math.min(socketMetrics.established + 8, 120);
    socketMetrics.syn_recv = Math.min(socketMetrics.syn_recv + 5, 80);
  } else if (isAttack) {
    socketMetrics.syn_recv = Math.min(socketMetrics.syn_recv + 2, 40);
  } else {
    // Lưu lượng bình thường
    socketMetrics.established = Math.max(8, Math.min(socketMetrics.established + 1, 60));
    socketMetrics.time_wait = Math.min(socketMetrics.time_wait + 1, 30);
  }

  socketMetrics.last_updated = new Date().toISOString();
}

// Giảm dần các kết nối SYN_RECV theo chu kỳ nếu không có bão gói tin tiếp diễn
setInterval(() => {
  if (socketMetrics.syn_recv > 0) {
    socketMetrics.syn_recv = Math.max(0, socketMetrics.syn_recv - 2);
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

  // Phát tín hiệu reset đến tất cả client đang kết nối
  io.emit('GOD_VIEW_RESET', {
    message: 'Telemetry buffer cleared by user.',
    timestamp: new Date().toISOString(),
  });

  res.status(200).json({
    success: true,
    message: 'Đã xóa rỗng bộ đệm Telemetry Ring Buffer.',
  });
});

/**
 * POST /api/defense/toggle
 * Chuyển tiếp (proxy) lệnh bật/tắt khiên L3/L7 tới Target App và đồng bộ hóa qua WebSocket
 */
function broadcastDefense() {
  const payload = { defense_l3_state: defense.state, proxied_to_target: defense.state !== null, updated_at: new Date().toISOString() };
  io.emit('DEFENSE_TOGGLED', payload);
  return payload;
}

app.post('/api/defense/toggle', async (req: Request, res: Response) => {
  const { enabled } = req.body || {};
  if (enabled !== undefined && typeof enabled !== 'boolean') {
    res.status(400).json({ success: false, message: 'enabled must be boolean' });
    return;
  }
  try {
    await defense.change(enabled);
    broadcastDefense();
    res.json({ success: true, defense_l3_app: defense.state, proxied_to_target: true });
  } catch {
    broadcastDefense();
    res.status(502).json({ success: false, defense_l3_app: null, proxied_to_target: false, message: 'Không xác nhận được trạng thái từ Target. Hãy kiểm tra kết nối.' });
  }
});

app.get('/api/defense/status', async (_req: Request, res: Response) => {
  try {
    await defense.read();
    broadcastDefense();
    res.json({ defense_l3_app: defense.state, target_url: config.targetAppUrl, proxied_to_target: true });
  } catch {
    broadcastDefense();
    res.status(502).json({ defense_l3_app: null, proxied_to_target: false });
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
    res.json({ success: true, duplicate: true, event_id: event.event_id });
    return;
  }
  attackEvents.set(event.event_id, event);
  if (attackEvents.size > config.maxBufferSize) attackEvents.delete(attackEvents.keys().next().value!);
  io.emit('ATTACK_EVENT', event);
  res.json({ success: true, duplicate: false, event_id: event.event_id });
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
  socket.on('TOGGLE_DEFENSE', async () => {
    try {
      await defense.change();
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
