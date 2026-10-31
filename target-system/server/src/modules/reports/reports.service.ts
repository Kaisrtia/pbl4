import { Injectable, Logger } from '@nestjs/common';
import crypto from 'crypto';

@Injectable()
export class ReportsService {
  private readonly logger = new Logger(ReportsService.name);

  async generateHeavyAnalytics(
    iterations: number = 100000,
    delayMs: number = 0,
  ) {
    const startTime = Date.now();
    const safeIterations = Math.min(Math.max(iterations, 1000), 2000000);

    this.logger.log(
      `[REPORTS] Executing heavy CPU calculation (${safeIterations} iterations)...`,
    );

    // 1. Tiêu tốn CPU chu kỳ bằng thuật toán băm SHA-256 liên tiếp
    let hash = 'seed_data_pbl4_report_analytics';
    for (let i = 0; i < safeIterations; i++) {
      hash = crypto
        .createHash('sha256')
        .update(hash + i)
        .digest('hex');
    }

    // 2. Độ trễ nhân tạo nếu có yêu cầu
    if (delayMs > 0) {
      const safeDelay = Math.min(delayMs, 5000);
      await new Promise((resolve) => setTimeout(resolve, safeDelay));
    }

    const durationMs = Date.now() - startTime;
    this.logger.log(`[REPORTS] Heavy calculation completed in ${durationMs}ms`);

    return {
      status: 'completed',
      service: 'Heavy Report & Analytics Processing',
      iterations: safeIterations,
      computation_time_ms: durationMs,
      summary_hash: hash.substring(0, 16) + '...',
      server_load: durationMs > 250 ? 'HIGH_CPU_LOAD' : 'NORMAL',
      timestamp: new Date().toISOString(),
    };
  }
}
