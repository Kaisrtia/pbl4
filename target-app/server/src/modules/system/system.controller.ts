import { Controller, Get, Query, Req, Inject } from '@nestjs/common';
import type { Request } from 'express';
import { ApiTags, ApiOperation, ApiQuery, ApiResponse } from '@nestjs/swagger';
import {
  DEFENSE_SERVICE_TOKEN,
  IDefenseService,
} from '../defense/defense.constants';

@ApiTags('System')
@Controller('system')
export class SystemController {
  constructor(
    @Inject(DEFENSE_SERVICE_TOKEN)
    private readonly defenseService: IDefenseService,
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
}
