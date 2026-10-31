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
import {
  ApiTags,
  ApiOperation,
  ApiQuery,
  ApiBody,
  ApiResponse,
} from '@nestjs/swagger';
import { ReportsService } from './reports.service';
import { DynamicRateLimitGuard } from '../defense/guards/dynamic-rate-limit.guard';

@ApiTags('Reports')
@Controller('reports')
@UseGuards(DynamicRateLimitGuard)
export class ReportsController {
  constructor(private readonly reportsService: ReportsService) {}

  @Get('analytics')
  @ApiOperation({
    summary: 'Tác vụ tính toán CPU nặng (Mô phỏng L7 DoS)',
    description:
      'Chạy lặp băm SHA-256 từ 1.000 đến 2.000.000 vòng để tiêu tốn chu kỳ CPU máy chủ mục tiêu. Được bảo vệ bởi DynamicRateLimitGuard khi Khiên L3 bật.',
  })
  @ApiQuery({
    name: 'iterations',
    required: false,
    example: 100000,
    description: 'Số vòng lặp băm SHA-256 (mặc định 100.000)',
  })
  @ApiQuery({
    name: 'delay_ms',
    required: false,
    example: 0,
    description: 'Độ trễ giả lập nhân tạo (ms, tối đa 5000ms)',
  })
  @ApiResponse({ status: 200, description: 'Tính toán hoàn tất' })
  @ApiResponse({ status: 429, description: 'Bị Rate Limit chặn đứng' })
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
  @ApiOperation({ summary: 'Tác vụ CPU nặng qua phương thức POST' })
  @ApiBody({
    required: false,
    schema: {
      type: 'object',
      properties: {
        iterations: { type: 'number', example: 100000 },
        delay_ms: { type: 'number', example: 0 },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'Tính toán hoàn tất' })
  @ApiResponse({ status: 429, description: 'Bị Rate Limit chặn đứng' })
  async postHeavyLoad(
    @Body('iterations') iterations?: number,
    @Body('delay_ms') delayMs?: number,
  ) {
    const iter = iterations || 100000;
    const delay = delayMs || 0;
    return this.reportsService.generateHeavyAnalytics(iter, delay);
  }
}
