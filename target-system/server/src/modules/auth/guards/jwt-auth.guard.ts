import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { envConfig } from '../../../config/env.config';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly jwtService: JwtService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const authHeader = request.headers['authorization'];

    if (!authHeader) {
      throw new UnauthorizedException(
        'Thiếu Header Authorization: Bearer <token>',
      );
    }

    const [scheme, token] = authHeader.split(' ');
    if (scheme !== 'Bearer' || !token) {
      throw new UnauthorizedException(
        'Định dạng Token không hợp lệ. Yêu cầu: Bearer <token>',
      );
    }

    try {
      const payload = this.jwtService.verify(token, {
        secret: envConfig.jwtSecret,
      });

      // Gắn thông tin người dùng đã xác thực vào request
      request.user = payload;
      return true;
    } catch (err: any) {
      if (err.name === 'TokenExpiredError') {
        throw new UnauthorizedException('Token đã hết hạn');
      }
      throw new UnauthorizedException('Token chữ ký không hợp lệ');
    }
  }
}
