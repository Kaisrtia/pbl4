import { Router, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { db } from '../db/database';
import { config } from '../config/env';
import { authenticateToken, AuthenticatedRequest } from '../middleware/auth.middleware';
import { LoginRequest, LoginResponse } from '@shared/schemas';

export const authRouter = Router();

/**
 * POST /api/login
 * Xử lý xác thực người dùng
 * - Khi L3 Defense tắt (mặc định): Cho phép khai thác lỗ hổng SQL Injection (SQLi)
 * - Khi L3 Defense bật: Sử dụng Parameterized Queries ngăn chặn SQLi
 */
authRouter.post('/login', (req: Request<{}, {}, LoginRequest>, res: Response<LoginResponse>) => {
  const { username, password, rememberMe } = req.body;

  if (!username || !password) {
    res.status(400).json({
      success: false,
      message: 'Vui lòng cung cấp đầy đủ tên đăng nhập và mật khẩu.',
      error: 'MISSING_FIELDS',
    });
    return;
  }

  // Cho phép SQLi nếu Defense Lớp 3 (App) đang tắt
  const allowSqli = !config.defenseL3App;
  const result = db.findUserByCredentials(username, password, allowSqli);

  // Đánh dấu telemetry nếu nghi vấn tấn công SQLi
  if (result.isSqliSuspected) {
    (req as any).telemetryMeta = {
      isSuspicious: true,
      attackTag: 'SQL_INJECTION',
    };
  }

  // Xử lý khi đăng nhập thất bại
  if (!result.user) {
    res.status(401).json({
      success: false,
      message: 'Tên đăng nhập hoặc mật khẩu không chính xác.',
      error: 'INVALID_CREDENTIALS',
    });
    return;
  }

  // Tạo JWT Access Token
  const tokenPayload = {
    id: result.user.id,
    username: result.user.username,
    email: result.user.email,
    role: result.user.role,
    fullName: result.user.fullName,
  };

  const expiresIn = (rememberMe ? '7d' : config.jwtExpiresIn) as any;
  const token = jwt.sign(tokenPayload, config.jwtSecret, { expiresIn });

  res.status(200).json({
    success: true,
    message: result.isSqliSuspected && allowSqli
      ? 'Đăng nhập thành công qua SQL Injection Bypass!'
      : 'Đăng nhập thành công!',
    token,
    accessToken: token,
    expiresIn: rememberMe ? 604800 : 7200,
    user: result.user,
  });
});

/**
 * GET /api/me
 * Lấy thông tin tài khoản hiện tại từ Token
 */
authRouter.get('/me', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
  res.status(200).json({
    success: true,
    user: req.user,
  });
});
