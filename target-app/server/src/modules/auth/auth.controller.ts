import {
  Controller,
  Post,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { DynamicRateLimitGuard } from '../defense/guards/dynamic-rate-limit.guard';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @UseGuards(DynamicRateLimitGuard)
  @ApiOperation({
    summary: 'Đăng nhập người dùng & Cấp JWT 30 ngày',
    description:
      "Khi Khiên L3 TẮT: Hỗ trợ bypass SQL Injection với payload `admin' --`. Khi Khiên L3 BẬT: Sử dụng Prepared Statement và chặn mã 401.",
  })
  @ApiResponse({
    status: 200,
    description: 'Đăng nhập thành công, trả về access_token 30 ngày.',
  })
  @ApiResponse({
    status: 401,
    description:
      'Tài khoản hoặc mật khẩu không chính xác (hoặc bị Khiên L3 chặn đứng).',
  })
  @ApiResponse({
    status: 429,
    description: 'Bị giới hạn tần suất gửi yêu cầu (Rate Limit).',
  })
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }
}
