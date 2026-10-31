import {
  Controller,
  Post,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { DynamicRateLimitGuard } from '../defense/guards/dynamic-rate-limit.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @UseGuards(DynamicRateLimitGuard)
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }
}
