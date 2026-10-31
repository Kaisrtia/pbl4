import { Controller, Get, Query, Req, Inject } from '@nestjs/common';
import type { Request } from 'express';
import {
  DEFENSE_SERVICE_TOKEN,
  IDefenseService,
} from '../defense/defense.constants';

@Controller('system')
export class SystemController {
  constructor(
    @Inject(DEFENSE_SERVICE_TOKEN)
    private readonly defenseService: IDefenseService,
  ) {}

  @Get('ping')
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
