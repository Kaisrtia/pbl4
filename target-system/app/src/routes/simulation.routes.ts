import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { Readable } from 'stream';

export const simulationRouter = Router();

/**
 * 1. GET /api/ping
 * Trả về 'pong' và thông tin thời gian máy chủ để đo lường độ trễ mạng (latency)
 * Hỗ trợ query:
 * - ?t=<client_timestamp_ms>: để máy chủ tính toán độ trễ ước tính (one-way latency)
 * - ?echo=<string>: phản hồi lại thông điệp của client
 */
simulationRouter.get('/ping', (req: Request, res: Response) => {
  const serverTime = Date.now();
  const clientTimeParam = req.query.t || req.query.timestamp;
  let estimatedLatencyMs: number | undefined = undefined;

  if (clientTimeParam) {
    const clientTimestamp = Number(clientTimeParam);
    if (!isNaN(clientTimestamp)) {
      estimatedLatencyMs = Math.max(0, serverTime - clientTimestamp);
    }
  }

  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

  res.status(200).json({
    status: 'success',
    message: 'pong',
    server_time: serverTime,
    server_iso: new Date(serverTime).toISOString(),
    client_ip: clientIp.replace('::ffff:', ''),
    echo: req.query.echo || undefined,
    latency_ms: estimatedLatencyMs,
  });
});

/**
 * 2. GET /api/download
 * Cho phép tải xuống một file giả lập dữ liệu nhị phân với dung lượng tùy chỉnh
 * Phục vụ kiểm thử lưu lượng mạng (bandwidth testing) hoặc tạo traffic cho MitM Sniffing
 * Hỗ trợ query:
 * - ?size=<number>: Dung lượng tính bằng MB (Mặc định: 1MB, Tối đa: 50MB)
 * - ?bytes=<number>: Dung lượng tính chính xác bằng byte (ghi đè size)
 * - ?filename=<string>: Tên file xuất ra
 */
simulationRouter.get('/download', (req: Request, res: Response) => {
  let sizeInBytes = 1 * 1024 * 1024; // Mặc định 1MB

  // Xử lý tham số dung lượng
  if (req.query.bytes) {
    const parsedBytes = parseInt(req.query.bytes as string, 10);
    if (!isNaN(parsedBytes) && parsedBytes > 0) {
      sizeInBytes = Math.min(parsedBytes, 50 * 1024 * 1024); // Giới hạn max 50MB để an toàn RAM
    }
  } else if (req.query.size) {
    const parsedMb = parseFloat(req.query.size as string);
    if (!isNaN(parsedMb) && parsedMb > 0) {
      sizeInBytes = Math.min(Math.round(parsedMb * 1024 * 1024), 50 * 1024 * 1024);
    }
  }

  const filename = (req.query.filename as string) || 'simulated_traffic_sample.bin';

  // Thiết lập HTTP headers tải file chuẩn
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Length', sizeInBytes.toString());
  res.setHeader('X-Simulated-Bytes', sizeInBytes.toString());

  // Kích thước mỗi chunk truyền qua stream (64KB)
  const chunkSize = 64 * 1024;
  let remainingBytes = sizeInBytes;

  // Tạo mẫu dữ liệu 64KB lặp lại (chuỗi byte giả lập traffic)
  const patternChunk = Buffer.alloc(chunkSize, 'A');

  // Sử dụng Readable stream để truyền tuần tự, tránh tràn Heap Memory của Node.js
  const stream = new Readable({
    read() {
      if (remainingBytes <= 0) {
        this.push(null); // Kết thúc stream
        return;
      }

      const currentChunkSize = Math.min(remainingBytes, chunkSize);
      remainingBytes -= currentChunkSize;

      if (currentChunkSize === chunkSize) {
        this.push(patternChunk);
      } else {
        this.push(patternChunk.subarray(0, currentChunkSize));
      }
    },
  });

  stream.pipe(res);
});

/**
 * Hàm thực thi tính toán nặng (CPU intensive hashing) và độ trễ nhân tạo
 */
async function executeHeavyWorkload(iterations: number, delayMs: number) {
  const startTime = Date.now();

  // 1. Giả lập tính toán nặng tiêu tốn chu kỳ CPU (SHA-256 liên tục)
  let hash = 'initial_seed_data_for_pbl4_simulation';
  for (let i = 0; i < iterations; i++) {
    hash = crypto.createHash('sha256').update(hash + i).digest('hex');
  }

  const cpuDuration = Date.now() - startTime;

  // 2. Giả lập delay/độ trễ nghẽn tài nguyên nếu có yêu cầu
  if (delayMs > 0) {
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }

  const totalDuration = Date.now() - startTime;

  return {
    iterations,
    final_hash: hash.substring(0, 16) + '...',
    cpu_time_ms: cpuDuration,
    simulated_delay_ms: delayMs,
    total_duration_ms: totalDuration,
  };
}

/**
 * 3. GET /api/heavy-load & POST /api/heavy
 * Giả lập endpoint xử lý nặng (Heavy Endpoint DoS) để test:
 * - Tải CPU và RAM của Target Server (hiển thị trên đồ thị Host Metrics của God-View)
 * - Kích hoạt cơ chế Rate Limiting hoặc phát hiện flood DoS tầng L7
 * Tham số (hỗ trợ qua query param ở GET hoặc JSON body ở POST):
 * - iterations: Số vòng lặp tính toán SHA-256 (Mặc định: 150,000, Tối đa: 2,000,000)
 * - delay: Thời gian cố tình tạo trễ (ms) (Mặc định: 0, Tối đa: 5000ms)
 */
async function handleHeavyRequest(req: Request, res: Response) {
  // Lấy tham số từ body (POST) hoặc query (GET)
  const source = req.method === 'POST' ? req.body : req.query;

  let iterations = 150000;
  if (source.iterations) {
    const parsed = parseInt(source.iterations as string, 10);
    if (!isNaN(parsed) && parsed > 0) {
      iterations = Math.min(parsed, 2000000); // Giới hạn tối đa 2 triệu vòng
    }
  }

  let delayMs = 0;
  if (source.delay || source.delay_ms) {
    const parsed = parseInt((source.delay || source.delay_ms) as string, 10);
    if (!isNaN(parsed) && parsed > 0) {
      delayMs = Math.min(parsed, 5000); // Giới hạn delay tối đa 5 giây
    }
  }

  // Đánh dấu telemetry nếu tải nặng bất thường (dấu hiệu DoS)
  if (iterations >= 300000 || delayMs >= 1000) {
    (req as any).telemetryMeta = {
      isSuspicious: true,
      attackTag: 'HEAVY_DOS',
    };
  }

  try {
    const result = await executeHeavyWorkload(iterations, delayMs);

    res.status(200).json({
      status: 'completed',
      service: 'Heavy Workload & DoS Simulation Endpoint',
      metrics: result,
      server_state: result.total_duration_ms > 200 ? 'UNDER_HEAVY_LOAD' : 'NORMAL',
      timestamp: new Date().toISOString(),
    });
  } catch (err: any) {
    res.status(500).json({
      status: 'error',
      message: 'Lỗi trong quá trình xử lý tải nặng',
      error: err.message,
    });
  }
}

simulationRouter.get('/heavy-load', handleHeavyRequest);
simulationRouter.post('/heavy', handleHeavyRequest);
simulationRouter.get('/heavy', handleHeavyRequest); // Hỗ trợ thêm GET /api/heavy
