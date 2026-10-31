import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  Inject,
  Logger,
} from '@nestjs/common';
import path from 'path';
import fs from 'fs';
import { DatabaseService } from '../../database/database.service';
import {
  DEFENSE_SERVICE_TOKEN,
  IDefenseService,
} from '../defense/defense.constants';
import { envConfig } from '../../config/env.config';
import type { DocumentItem } from '@shared/schemas/shop-api';

export type { DocumentItem };

@Injectable()
export class DocumentsService {
  private readonly logger = new Logger(DocumentsService.name);
  private readonly publicDir = path.resolve(
    process.cwd(),
    envConfig.publicFilesDir,
  );

  constructor(
    private readonly db: DatabaseService,
    @Inject(DEFENSE_SERVICE_TOKEN)
    private readonly defenseService: IDefenseService,
  ) {}

  /**
   * Lấy danh sách tài liệu kỹ thuật (Datasheets, Pinout, Schematics)
   */
  getDocuments(params?: {
    search?: string;
    productId?: number;
    includeConfidential?: boolean;
  }): DocumentItem[] {
    let sql = `
      SELECT 
        d.id,
        d.product_id,
        d.title,
        d.file_name,
        d.file_size_kb,
        d.is_confidential,
        d.created_at,
        p.name as product_name,
        p.sku as product_sku
      FROM documents d
      LEFT JOIN products p ON d.product_id = p.id
      WHERE 1=1
    `;
    const queryParams: any[] = [];

    // Mặc định ẩn tài liệu bảo mật khỏi danh sách công khai trừ khi có cờ yêu cầu
    if (!params?.includeConfidential) {
      sql += ' AND d.is_confidential = 0';
    }

    // Lọc theo sản phẩm
    if (params?.productId) {
      sql += ' AND d.product_id = ?';
      queryParams.push(params.productId);
    }

    // Tìm kiếm theo tiêu đề hoặc tên file
    if (params?.search && params.search.trim() !== '') {
      sql += ' AND (d.title LIKE ? OR d.file_name LIKE ?)';
      const keyword = `%${params.search.trim()}%`;
      queryParams.push(keyword, keyword);
    }

    sql += ' ORDER BY d.id ASC';

    const rows = this.db.query(sql, queryParams);
    return rows.map((r: any) => this.formatDocument(r));
  }

  /**
   * Lấy thông tin chi tiết một tài liệu theo ID
   */
  getDocumentById(id: number): DocumentItem {
    const rows = this.db.query(
      `
      SELECT 
        d.id,
        d.product_id,
        d.title,
        d.file_name,
        d.file_size_kb,
        d.is_confidential,
        d.created_at,
        p.name as product_name,
        p.sku as product_sku
      FROM documents d
      LEFT JOIN products p ON d.product_id = p.id
      WHERE d.id = ?
    `,
      [id],
    );

    if (!rows || rows.length === 0) {
      throw new NotFoundException(`Không tìm thấy tài liệu có ID [${id}]`);
    }

    return this.formatDocument(rows[0]);
  }

  /**
   * Xác định file trên ổ đĩa để tải về, đồng thời kiểm tra chính sách bảo mật L3
   */
  resolveFileForDownload(id: number): {
    filePath: string;
    fileName: string;
    isConfidential: boolean;
  } {
    const doc = this.getDocumentById(id);
    const filePath = path.resolve(this.publicDir, doc.file_name);

    if (!fs.existsSync(filePath)) {
      throw new NotFoundException(
        `File vật lý [${doc.file_name}] không tồn tại trên máy chủ`,
      );
    }

    // Kiểm tra chính sách phòng thủ L3 đối với tài liệu mật (Confidential)
    if (doc.is_confidential) {
      const isL3Active = this.defenseService.isSanitizationEnabled();
      if (isL3Active) {
        this.logger.warn(
          `[SECURITY] Unauthorized download attempt for confidential document [${doc.title}] BLOCKED by L3 Shield!`,
        );
        throw new ForbiddenException({
          statusCode: 403,
          error: 'Forbidden',
          message:
            'L3 Shield: Tài liệu tuyệt mật (Blueprint/Confidential) bị khóa! Quyền truy cập bị từ chối.',
          shield: 'L3_CONFIDENTIAL_POLICY_ACTIVE',
        });
      } else {
        this.logger.warn(
          `[SECURITY VULNERABILITY] Confidential document [${doc.title}] LEAKED because L3 Shield is OFF!`,
        );
      }
    }

    return {
      filePath,
      fileName: doc.file_name,
      isConfidential: doc.is_confidential,
    };
  }

  private formatDocument(row: any): DocumentItem {
    return {
      id: row.id,
      product_id: row.product_id,
      product_name: row.product_name || undefined,
      product_sku: row.product_sku || undefined,
      title: row.title,
      file_name: row.file_name,
      file_size_kb: row.file_size_kb,
      is_confidential: Boolean(row.is_confidential),
      download_url: `/api/documents/${row.id}/download`,
      created_at: row.created_at,
    };
  }
}
