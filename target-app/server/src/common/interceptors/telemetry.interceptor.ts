import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import http from 'http';
import { envConfig } from '../../config/env.config';

@Injectable()
export class TelemetryInterceptor implements NestInterceptor {
  private readonly logger = new Logger(TelemetryInterceptor.name);

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const startTime = Date.now();
    const httpContext = context.switchToHttp();
    const req = httpContext.getRequest();
    const res = httpContext.getResponse();

    return next.handle().pipe(
      tap({
        next: (body) => {
          this.processAndSendTelemetry(req, res, startTime, body, null);
        },
        error: (err) => {
          this.processAndSendTelemetry(req, res, startTime, null, err);
        },
      }),
    );
  }

  private processAndSendTelemetry(
    req: any,
    res: any,
    startTime: number,
    responseBody: any,
    error: any,
  ) {
    const responseTime = Date.now() - startTime;
    const statusCode = error
      ? error.status || error.statusCode || 500
      : res.statusCode || 200;
    const clientIp = String(
      req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1',
    ).replace('::ffff:', '');
    const endpoint = req.originalUrl || req.url || '';
    const method = req.method || 'GET';

    // Xác định dấu hiệu tấn công sơ bộ
    let attackTag: string | undefined = undefined;
    let isSuspicious = false;

    const bodyStr = JSON.stringify(req.body || {});
    const queryStr = JSON.stringify(req.query || {});

    if (
      endpoint.includes('/auth/login') &&
      (bodyStr.includes("'") ||
        bodyStr.includes('--') ||
        bodyStr.includes('/*'))
    ) {
      attackTag = 'SQL_INJECTION';
      isSuspicious = true;
    } else if (
      endpoint.includes('/reports/') &&
      (queryStr.includes('iterations') || bodyStr.includes('iterations'))
    ) {
      attackTag = 'HEAVY_DOS';
      isSuspicious = true;
    } else if (
      endpoint.includes('/files/download') &&
      (queryStr.includes('..') ||
        queryStr.includes('/') ||
        queryStr.includes('\\'))
    ) {
      attackTag = 'PATH_TRAVERSAL';
      isSuspicious = true;
    } else if (statusCode === 429) {
      attackTag = 'RATE_LIMIT_BLOCKED';
      isSuspicious = true;
    }

    const payload = {
      timestamp: new Date().toISOString(),
      method,
      endpoint,
      status_code: statusCode,
      response_time: responseTime,
      client_ip: clientIp,
      payload_summary: {
        query: req.query,
        body_preview: req.method === 'POST' ? req.body : undefined,
        user_agent: req.headers['user-agent'],
      },
      is_suspicious: isSuspicious,
      attack_tag: attackTag,
    };

    // Bắn telemetry về trạm trung chuyển God-View không chặn request
    this.sendToGodView(payload);
  }

  private sendToGodView(payload: any) {
    try {
      const url = new URL(envConfig.godviewTelemetryUrl);
      const data = JSON.stringify(payload);

      const options = {
        hostname: url.hostname,
        port: url.port || 80,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data),
        },
        timeout: envConfig.godviewTimeoutMs,
      };

      const req = http.request(options);
      req.on('error', () => {
        // God-View chưa chạy hoặc timeout -> bỏ qua trong yên lặng, không làm chậm Target Server
      });
      req.write(data);
      req.end();
    } catch {
      // Bỏ qua lỗi URL
    }
  }
}
