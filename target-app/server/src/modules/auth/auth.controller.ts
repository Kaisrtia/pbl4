import {
  Controller,
  Get,
  Post,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
  Req,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { DynamicRateLimitGuard } from '../defense/guards/dynamic-rate-limit.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

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

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Lấy thông tin tài khoản người dùng đang đăng nhập',
    description:
      'Yêu cầu Bearer JWT Token hợp lệ trong Header Authorization. Trả về mã 401 nếu chưa đăng nhập hoặc token đã hết hạn.',
  })
  @ApiResponse({
    status: 200,
    description: 'Xác thực JWT thành công, trả về thông tin người dùng.',
  })
  @ApiResponse({
    status: 401,
    description: 'Chưa đăng nhập, thiếu token hoặc token không hợp lệ.',
  })
  getProfile(@Req() req: any) {
    return {
      status: 'success',
      user: req.user,
    };
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Alias cho endpoint GET /api/auth/profile',
  })
  getMe(@Req() req: any) {
    return this.getProfile(req);
  }
}
