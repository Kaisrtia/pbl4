import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Inject,
} from '@nestjs/common';
import { DEFENSE_SERVICE_TOKEN, IDefenseService } from '../defense.constants';
import { envConfig } from '../../../config/env.config';

interface IpRecord {
  timestamps: number[];
}

@Injectable()
export class DynamicRateLimitGuard implements CanActivate {
  private readonly ipRequests = new Map<string, IpRecord>();
  private readonly windowMs = envConfig.rateLimit.windowMs;
  private readonly maxRequests = envConfig.rateLimit.maxRequests;

  constructor(
    @Inject(DEFENSE_SERVICE_TOKEN)
    private readonly defenseService: IDefenseService,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    // 1. Kiểm tra trạng thái Khiên L3 (Rate Limiting)
    if (!this.defenseService.isRateLimitEnabled()) {
      // Khiên TẮT: Cho phép mọi request chạy tự do (mô phỏng DoS / Brute-force)
      return true;
    }

    // 2. Khiên BẬT: Áp dụng thuật toán giới hạn tần suất theo IP
    const request = context.switchToHttp().getRequest();
    const clientIp =
      request.headers['x-forwarded-for'] ||
      request.socket.remoteAddress ||
      'unknown-ip';
    const now = Date.now();

    let record = this.ipRequests.get(clientIp);
    if (!record) {
      record = { timestamps: [] };
      this.ipRequests.set(clientIp, record);
    }

    // Lọc bỏ các timestamp quá cũ ngoài cửa sổ 5 giây
    record.timestamps = record.timestamps.filter(
      (ts) => now - ts < this.windowMs,
    );

    if (record.timestamps.length >= this.maxRequests) {
      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          error: 'Too Many Requests',
          message: 'L3 Shield Rate Limiter: Yêu cầu bị chặn do gửi quá nhanh!',
          shield: 'L3_RATE_LIMIT_ACTIVE',
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    record.timestamps.push(now);
    return true;
  }
}
