import {
  Injectable,
  UnauthorizedException,
  Inject,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from './dto/login.dto';
import { DatabaseService } from '../../database/database.service';
import {
  DEFENSE_SERVICE_TOKEN,
  IDefenseService,
} from '../defense/defense.constants';
import { envConfig } from '../../config/env.config';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly db: DatabaseService,
    private readonly jwtService: JwtService,
    @Inject(DEFENSE_SERVICE_TOKEN)
    private readonly defenseService: IDefenseService,
  ) {}

  async login(dto: LoginDto) {
    const isProtected = this.defenseService.isAntiSqliEnabled();
    let users: any[] = [];

    if (isProtected) {
      // KHIÊN BẬT: Sử dụng Parameterized Query an toàn
      this.logger.log(
        `[AUTH] Processing login with PREPARED STATEMENT for user: [${dto.username}]`,
      );
      users = this.db.query(
        'SELECT id, username, role, full_name, email FROM users WHERE username = ? AND password = ?',
        [dto.username, dto.password],
      );
    } else {
      // KHIÊN TẮT: Sử dụng Raw SQL nối chuỗi (Cho phép khai thác SQL Injection)
      this.logger.warn(
        `[AUTH] Processing login with RAW QUERY (VULNERABLE) for user: [${dto.username}]`,
      );
      const rawSql = `SELECT id, username, role, full_name, email FROM users WHERE username = '${dto.username}' AND password = '${dto.password}'`;
      try {
        users = this.db.rawQuery(rawSql);
      } catch (err: any) {
        this.logger.error(`Raw query SQL syntax error: ${err.message}`);
        throw new UnauthorizedException('Lỗi cú pháp truy vấn cơ sở dữ liệu');
      }
    }

    if (!users || users.length === 0) {
      throw new UnauthorizedException(
        'Tài khoản hoặc mật khẩu không chính xác',
      );
    }

    const user = users[0];
    const isSqliExploited =
      !isProtected &&
      (dto.username.includes("'") || dto.username.includes('--'));

    // Tạo JWT token thật ký bằng bí mật và có thời hạn 30 ngày
    const jwtPayload = {
      sub: user.id,
      username: user.username,
      role: user.role,
      fullName: user.full_name,
      email: user.email,
    };

    const accessToken = this.jwtService.sign(jwtPayload);

    return {
      status: 'success',
      message: isSqliExploited
        ? '⚠️ [CẢNH BÁO AN NINH] Đăng nhập thành công qua lỗ hổng SQL Injection (Khiên L3 đang tắt)!'
        : 'Đăng nhập thành công',
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        fullName: user.full_name,
        email: user.email,
      },
      defense_mode: isProtected
        ? 'SECURED_PREPARED_QUERY'
        : 'VULNERABLE_RAW_SQL',
      sqli_bypassed: isSqliExploited,
      token_type: 'Bearer',
      access_token: accessToken,
      token: accessToken, // Tương thích ngược với các script gọi .token
      expires_in: envConfig.jwtExpiresIn,
    };
  }
}
