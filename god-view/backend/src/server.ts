import express, { Request, Response } from 'express';
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';
import cors from 'cors';
import path from 'path';
import { config } from './config';
import { RingBuffer } from './ring-buffer';
import { TelemetryLog } from '@shared/schemas';

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
let defenseL3State = false;
let socketMetrics = {
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
}, 1500);

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
    defense_l3_state: defenseL3State,
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
    defense_l3_state: defenseL3State,
    metrics: socketMetrics,
  });
});

/**
 * DELETE /api/telemetry/clear
 * Xóa rỗng toàn bộ Ring Buffer trong RAM
 */
app.delete('/api/telemetry/clear', (req: Request, res: Response) => {
  telemetryBuffer.clear();
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
app.post('/api/defense/toggle', async (req: Request, res: Response) => {
  const { enabled } = req.body;
  let targetAppResponded = false;

  try {
    // Thử gửi lệnh sang Target App (172.20.0.20:8000 hoặc localhost:8000)
    const response = await fetch(`${config.targetAppUrl}/api/defense/toggle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
      signal: AbortSignal.timeout(1500),
    });

    if (response.ok) {
      const data: any = await response.json();
      defenseL3State = Boolean(data.defense_l3_app);
      targetAppResponded = true;
    }
  } catch (err) {
    // Nếu Target App chưa online, chuyển trạng thái local để phục vụ demo độc lập
    if (typeof enabled === 'boolean') {
      defenseL3State = enabled;
    } else {
      defenseL3State = !defenseL3State;
    }
  }

  // Phát sự kiện đổi trạng thái khiên chắn tới toàn bộ browser clients
  io.emit('DEFENSE_TOGGLED', {
    defense_l3_state: defenseL3State,
    proxied_to_target: targetAppResponded,
    updated_at: new Date().toISOString(),
  });

  res.status(200).json({
    success: true,
    defense_l3_app: defenseL3State,
    proxied_to_target: targetAppResponded,
    message: `Khiên phòng thủ L3/L7 hiện đang: ${defenseL3State ? 'BẬT (ACTIVE)' : 'TẮT (BYPASSED)'}`,
  });
});

/**
 * GET /api/defense/status
 * Lấy trạng thái hiện tại của khiên chắn
 */
app.get('/api/defense/status', (req: Request, res: Response) => {
  res.status(200).json({
    defense_l3_app: defenseL3State,
    target_url: config.targetAppUrl,
  });
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
    metrics: socketMetrics,
    defense_l3_state: defenseL3State,
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
    defenseL3State = !defenseL3State;
    try {
      await fetch(`${config.targetAppUrl}/api/defense/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: defenseL3State }),
        signal: AbortSignal.timeout(1000),
      });
    } catch (e) {
      // Ignored
    }

    io.emit('DEFENSE_TOGGLED', {
      defense_l3_state: defenseL3State,
      updated_at: new Date().toISOString(),
    });
  });

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
