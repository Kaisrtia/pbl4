import { Router, Response } from 'express';
import { db } from '../db/database';
import { authenticateToken, AuthenticatedRequest } from '../middleware/auth.middleware';
import { ResourceItem } from '@shared/schemas';

export const resourceRouter = Router();

/**
 * GET /api/resources
 * Trả về danh sách tài nguyên mật trong hệ thống (Yêu cầu Token xác thực)
 * Query parameters hỗ trợ:
 * - category: lọc theo danh mục ('financial', 'security', 'database', 'store', 'documentation')
 * - public_only: nếu = 'true' chỉ trả tài nguyên công khai
 */
resourceRouter.get('/', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
  const category = typeof req.query.category === 'string' ? req.query.category : undefined;
  const isPublicOnly = req.query.public_only === 'true';

  const resources = db.getAllResources({
    category,
    isPublicOnly,
  });

  res.status(200).json({
    success: true,
    count: resources.length,
    authenticated_user: {
      username: req.user?.username,
      role: req.user?.role,
    },
    resources,
  });
});

/**
 * GET /api/resources/:id
 * Lấy chi tiết một tài nguyên mật theo ID (Yêu cầu Token xác thực)
 */
resourceRouter.get('/:id', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
  const resourceId = req.params.id;
  const resource = db.getResourceById(resourceId);

  if (!resource) {
    res.status(404).json({
      success: false,
      message: `Không tìm thấy tài nguyên với ID: ${resourceId}`,
      error: 'RESOURCE_NOT_FOUND',
    });
    return;
  }

  // Nếu tài nguyên không công khai và user là guest, có thể cảnh báo hoặc hạn chế nếu cần
  res.status(200).json({
    success: true,
    resource,
  });
});
