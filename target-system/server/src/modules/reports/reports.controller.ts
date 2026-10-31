import {
  Controller,
  Get,
  Post,
  Query,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ReportsService } from './reports.service';
import { DynamicRateLimitGuard } from '../defense/guards/dynamic-rate-limit.guard';

@Controller('reports')
@UseGuards(DynamicRateLimitGuard)
export class ReportsController {
  constructor(private readonly reportsService: ReportsService) {}

  @Get('analytics')
  async getAnalytics(
    @Query('iterations') iterations?: string,
    @Query('delay_ms') delayMs?: string,
  ) {
    const iter = iterations ? parseInt(iterations, 10) : 100000;
    const delay = delayMs ? parseInt(delayMs, 10) : 0;
    return this.reportsService.generateHeavyAnalytics(iter, delay);
  }

  @Post('heavy')
  @HttpCode(HttpStatus.OK)
  async postHeavyLoad(
    @Body('iterations') iterations?: number,
    @Body('delay_ms') delayMs?: number,
  ) {
    const iter = iterations || 100000;
    const delay = delayMs || 0;
    return this.reportsService.generateHeavyAnalytics(iter, delay);
  }
}
