import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config/env';
import { User } from '@shared/schemas';

export interface AuthenticatedRequest extends Request {
  user?: Omit<User, 'password'>;
}

/**
 * Middleware xác thực JWT token cho các API yêu cầu đăng nhập
 */
export function authenticateToken(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

  if (!token) {
    res.status(401).json({
      success: false,
      message: 'Không tìm thấy Token xác thực trong Header (Authorization: Bearer <token>). Vui lòng đăng nhập.',
      error: 'UNAUTHORIZED',
    });
    return;
  }

  try {
    const decoded = jwt.verify(token, config.jwtSecret) as any;
    req.user = {
      id: decoded.id,
      username: decoded.username,
      email: decoded.email,
      role: decoded.role,
      fullName: decoded.fullName,
    };
    next();
  } catch (err: any) {
    res.status(403).json({
      success: false,
      message: 'Token xác thực không hợp lệ hoặc đã hết hạn.',
      error: 'FORBIDDEN',
    });
  }
}
