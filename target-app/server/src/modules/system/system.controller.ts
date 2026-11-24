import {
  Controller,
  Get,
  Post,
  HttpCode,
  HttpStatus,
  Query,
  Req,
  Res,
  Inject,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { ApiTags, ApiOperation, ApiQuery, ApiResponse } from '@nestjs/swagger';
import { exec } from 'child_process';
import { promisify } from 'util';
import {
  DEFENSE_SERVICE_TOKEN,
  IDefenseService,
} from '../defense/defense.constants';
import { DatabaseService } from '../../database/database.service';
import { DynamicRateLimitGuard } from '../defense/guards/dynamic-rate-limit.guard';

const execAsync = promisify(exec);

@ApiTags('System')
@Controller('system')
export class SystemController {
  private readonly logger = new Logger(SystemController.name);

  constructor(
    @Inject(DEFENSE_SERVICE_TOKEN)
    private readonly defenseService: IDefenseService,
    private readonly databaseService: DatabaseService,
    private readonly rateLimitGuard: DynamicRateLimitGuard,
  ) {}

  @Get('ping')
  @ApiOperation({
    summary: 'Đo độ trễ phản hồi (Latency Ping)',
    description:
      'Gửi timestamp của client để server tính toán độ trễ mili-giây (latency_ms) phục vụ đo lường trước/trong khi bị tấn công DoS.',
  })
  @ApiQuery({
    name: 't',
    required: false,
    description: 'Timestamp mili-giây từ client (`Date.now()`)',
  })
  @ApiQuery({
    name: 'echo',
    required: false,
    description: 'Chuỗi thông điệp phản hồi',
  })
  @ApiResponse({ status: 200, description: 'Phản hồi pong thành công' })
  ping(
    @Query('t') clientTimestamp?: string,
    @Query('echo') echoMsg?: string,
    @Req() req?: Request,
  ) {
    const serverTime = Date.now();
    let estimatedLatencyMs: number | undefined = undefined;

    if (clientTimestamp) {
      const clientTime = parseInt(clientTimestamp, 10);
      if (!isNaN(clientTime)) {
        estimatedLatencyMs = Math.max(0, serverTime - clientTime);
      }
    }

    const clientIp =
      req?.headers['x-forwarded-for'] ||
      req?.socket.remoteAddress ||
      '127.0.0.1';

    return {
      status: 'success',
      message: 'pong',
      server_time: serverTime,
      server_iso: new Date(serverTime).toISOString(),
      client_ip: String(clientIp).replace('::ffff:', ''),
      echo: echoMsg,
      latency_ms: estimatedLatencyMs,
    };
  }

  @Get('network-ping')
  @ApiOperation({
    summary: 'Kiểm tra kết nối mạng (Mô phỏng lỗ hổng OS Command Injection)',
    description:
      'Khi Khiên L3 BẬT: Chặn các ký tự điều hướng shell `;`, `|`, `&`, `$`, backticks (mã lỗi 400 Bad Request). Khi Khiên L3 TẮT: Nối chuỗi thực thi trực tiếp qua Shell (VULNERABLE), phục vụ kịch bản leo quyền Reverse Shell.',
  })
  @ApiQuery({
    name: 'host',
    required: true,
    example: '127.0.0.1',
    description:
      'Địa chỉ IP hoặc Hostname cần ping (Thử payload `127.0.0.1; id` để test Command Injection)',
  })
  @ApiResponse({
    status: 200,
    description: 'Thực thi kiểm tra mạng thành công (kèm output shell)',
  })
  @ApiResponse({
    status: 400,
    description:
      'Bị Khiên Input Sanitization chặn đứng do phát hiện ký tự Shell nguy hiểm',
  })
  async networkPing(
    @Query('host') host: string,
    @Res({ passthrough: true }) res?: Response,
  ) {
    if (!host) {
      throw new BadRequestException('Vui lòng truyền tham số ?host=<target>');
    }

    const shellDangerousChars = [
      ';',
      '|',
      '&',
      '`',
      '$',
      '(',
      ')',
      '>',
      '<',
      '\n',
    ];
    const isProtected = this.defenseService.isSanitizationEnabled();
    const isInjectionDetected = shellDangerousChars.some((char) =>
      host.includes(char),
    );

    // Khi Khiên L3 BẬT: Bộ lọc phát hiện các ký tự điều hướng shell nguy hiểm và chặn lại
    if (isProtected && isInjectionDetected) {
      this.logger.warn(
        `[SYSTEM] Command Injection attack BLOCKED by L3 Shield for host payload: [${host}]`,
      );
      throw new BadRequestException({
        statusCode: 400,
        message:
          'L3 Sanitization Shield: Phát hiện ký tự điều hướng lệnh Shell nguy hiểm!',
        shield: 'L3_COMMAND_INJECTION_BLOCKED',
      });
    }

    // Khi Khiên L3 TẮT (hoặc input an toàn): Thực thi trực tiếp qua shell
    if (!isProtected && isInjectionDetected) {
      this.logger.warn(
        `[SYSTEM] Command Injection EXPLOITED (L3 Shield OFF) for host payload: [${host}]`,
      );
      res?.setHeader(
        'X-Security-Warning',
        'Command-Injection-Bypassed-Shield-Off',
      );
    }

    let stdout = '';
    let stderr = '';

    try {
      const result = await execAsync(`ping -c 1 ${host}`, { timeout: 10000 });
      stdout = result.stdout || '';
      stderr = result.stderr || '';
    } catch (err: any) {
      stdout = err.stdout ? String(err.stdout) : '';
      stderr = err.stderr ? String(err.stderr) : err.message || '';
    }

    return {
      status: 'success',
      message: isInjectionDetected
        ? '⚠️ [CẢNH BÁO AN NINH] Lệnh hệ điều hành đã được thực thi qua lỗ hổng Command Injection (Khiên L3 đang tắt)!'
        : 'Thực thi kiểm tra kết nối mạng thành công',
      host,
      command: `ping -c 1 ${host}`,
      output: (stdout || stderr || '').trim(),
      stdout: stdout.trim(),
      stderr: stderr.trim(),
      defense_mode: isProtected
        ? 'SECURED_SANITIZED'
        : 'VULNERABLE_DIRECT_EXEC',
      command_injection_bypassed: isInjectionDetected,
    };
  }

  @Get('health')
  @ApiOperation({ summary: 'Kiểm tra trạng thái sống của máy chủ & Khiên L3' })
  @ApiResponse({ status: 200, description: 'Server đang online' })
  health() {
    return {
      status: 'online',
      service: 'PBL4 Target Server (NestJS)',
      uptime_seconds: process.uptime(),
      memory_usage: process.memoryUsage(),
      defense_status: this.defenseService.getStatus(),
      timestamp: new Date().toISOString(),
    };
  }

  @Post('reset')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Khôi phục toàn bộ Target App về trạng thái sạch ban đầu (Reset 1-chạm)',
    description:
      'Thực hiện: 1. Reset Database (xóa orders, giỏ hàng, re-seed toàn bộ data mặc định); 2. Xóa bộ đếm Rate Limiting trong RAM; 3. Đưa cấu hình Khiên L3 về mặc định.',
  })
  @ApiResponse({
    status: 200,
    description:
      'Hệ thống Target App đã được khôi phục trạng thái sạch ban đầu thành công',
  })
  reset() {
    const dbResult = this.databaseService.resetDatabase();
    this.rateLimitGuard.resetRecords();
    const defenseFlags = this.defenseService.resetFlags();

    this.logger.log(
      '[SYSTEM RESET] Complete 1-touch reset executed successfully.',
    );

    return {
      status: 'success',
      message:
        'Target App đã được khôi phục về trạng thái sạch ban đầu (Reset 1-chạm)',
      reset_summary: {
        database: dbResult,
        rate_limit_cleared: true,
        defense_flags_reset: defenseFlags,
      },
      timestamp: new Date().toISOString(),
    };
  }
}
