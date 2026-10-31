import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { envConfig } from '../../config/env.config';

@Module({
  imports: [
    JwtModule.register({
      secret: envConfig.jwtSecret,
      signOptions: {
        expiresIn: envConfig.jwtExpiresIn as any,
      },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtAuthGuard],
  exports: [AuthService, JwtModule, JwtAuthGuard],
})
export class AuthModule {}
