import { Request, Response, NextFunction } from 'express';
import { config } from '../config/env';
import { TelemetryLog, PayloadSummary, HttpMethod, AttackType } from '@shared/schemas';

/**
 * Thu thập và tạo PayloadSummary an toàn từ Express Request
 */
function extractPayloadSummary(req: Request): PayloadSummary {
  const query = Object.keys(req.query).length > 0 ? (req.query as Record<string, unknown>) : undefined;
  let bodyPreview: Record<string, unknown> | string | undefined = undefined;
  let hasCredentials = false;

  if (req.body && typeof req.body === 'object') {
    const sanitizedBody: Record<string, unknown> = { ...req.body };
    // Che mật khẩu nếu có
    if ('password' in sanitizedBody) {
      sanitizedBody.password = '******';
      hasCredentials = true;
    }
    bodyPreview = sanitizedBody;
  }

  // Thu thập các pattern bất thường
  const detectedPatterns: string[] = [];
  const rawStringToCheck = JSON.stringify({ body: req.body, query: req.query, url: req.url });

  if (/('|--|#|union\s+select|or\s+['\d\w]+\s*=)/i.test(rawStringToCheck)) {
    detectedPatterns.push('SQL_INJECTION_PATTERN');
  }
  if (/(\.\.\/|\.\.\\)/i.test(rawStringToCheck)) {
    detectedPatterns.push('PATH_TRAVERSAL_PATTERN');
  }
  if (/(;|\||`|\$\(|\bsh\b|\bbash\b)/i.test(rawStringToCheck)) {
    detectedPatterns.push('COMMAND_INJECTION_PATTERN');
  }

  return {
    query,
    body_preview: bodyPreview,
    content_type: req.headers['content-type'],
    content_length: req.headers['content-length'] ? parseInt(req.headers['content-length'], 10) : undefined,
    params: Object.keys(req.params).length > 0 ? (req.params as Record<string, unknown>) : undefined,
    has_credentials: hasCredentials,
    detected_patterns: detectedPatterns.length > 0 ? detectedPatterns : undefined,
  };
}

/**
 * Gửi bản tin Telemetry bất đồng bộ về God-View Node
 */
async function sendTelemetryToGodView(telemetry: TelemetryLog): Promise<void> {
  if (!config.telemetryEnabled) return;

  const endpointUrl = `${config.godViewUrl}/api/telemetry`;
  try {
    // Sử dụng native fetch của Node 18+
    await fetch(endpointUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(telemetry),
      // Cấu hình timeout ngắn để không làm chậm Target App nếu God-View chưa bật
      signal: AbortSignal.timeout(1000),
    });
  } catch (err) {
    // Không ném lỗi nếu God-View backend chưa online hoặc từ chối kết nối
    // Vẫn hiển thị log tóm tắt ở console của Target App
  }
}

/**
 * Middleware tự động ghi nhận và chuyển tiếp Telemetry Log cho mọi HTTP request
 */
export function telemetryMiddleware(req: Request, res: Response, next: NextFunction): void {
  const startTime = Date.now();

  // Đính kèm cờ cho phép các route đánh dấu loại tấn công nếu phát hiện
  (req as any).telemetryMeta = {
    isSuspicious: false,
    attackTag: 'NORMAL' as AttackType,
  };

  // Lắng nghe khi response hoàn tất gửi về cho client
  res.on('finish', () => {
    const responseTime = Date.now() - startTime;
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
    const payloadSummary = extractPayloadSummary(req);

    const hasPatterns = (payloadSummary.detected_patterns?.length ?? 0) > 0;
    const customMeta = (req as any).telemetryMeta || {};

    const isSuspicious = customMeta.isSuspicious || hasPatterns || res.statusCode >= 400;
    let attackTag: AttackType = customMeta.attackTag || 'NORMAL';

    if (hasPatterns && attackTag === 'NORMAL') {
      if (payloadSummary.detected_patterns?.includes('SQL_INJECTION_PATTERN')) {
        attackTag = 'SQL_INJECTION';
      } else if (payloadSummary.detected_patterns?.includes('PATH_TRAVERSAL_PATTERN')) {
        attackTag = 'PATH_TRAVERSAL';
      } else if (payloadSummary.detected_patterns?.includes('COMMAND_INJECTION_PATTERN')) {
        attackTag = 'COMMAND_INJECTION';
      }
    }

    const telemetryLog: TelemetryLog = {
      timestamp: new Date().toISOString(),
      method: req.method as HttpMethod,
      endpoint: req.originalUrl || req.url,
      status_code: res.statusCode,
      response_time: responseTime,
      client_ip: clientIp.replace('::ffff:', ''), // Làm sạch IPv4 format
      payload_summary: payloadSummary,
      server_ip: config.serverIp,
      user_agent: req.headers['user-agent'],
      is_suspicious: isSuspicious,
      attack_tag: attackTag,
      defense_action: config.defenseL3App ? 'sanitized' : 'allowed',
    };

    // In log gọn gàng ra terminal
    const tagDisplay = telemetryLog.is_suspicious ? `[WARN:${telemetryLog.attack_tag}]` : `[INFO]`;
    console.log(
      `[Telemetry] ${tagDisplay} ${telemetryLog.method} ${telemetryLog.endpoint} -> ${telemetryLog.status_code} (${telemetryLog.response_time}ms) from ${telemetryLog.client_ip}`
    );

    // Gửi bất đồng bộ sang God-View
    sendTelemetryToGodView(telemetryLog);
  });

  next();
}
