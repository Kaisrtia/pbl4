import {
  Controller,
  Get,
  Param,
  Query,
  Res,
  ParseIntPipe,
} from '@nestjs/common';
import type { Response } from 'express';
import { DocumentsService } from './documents.service';

@Controller('documents')
export class DocumentsController {
  constructor(private readonly documentsService: DocumentsService) {}

  /**
   * 1. GET /api/documents
   * Lấy danh sách tài liệu kỹ thuật (phục vụ tab "Tài liệu kỹ thuật" trên Header)
   */
  @Get()
  getDocuments(
    @Query('search') search?: string,
    @Query('product_id') productIdStr?: string,
    @Query('include_confidential') includeConfidential?: string,
  ) {
    const productId = productIdStr ? parseInt(productIdStr, 10) : undefined;
    const shouldIncludeConfidential = includeConfidential === 'true';

    const docs = this.documentsService.getDocuments({
      search,
      productId,
      includeConfidential: shouldIncludeConfidential,
    });

    return {
      status: 'success',
      total: docs.length,
      data: docs,
    };
  }

  /**
   * 2. GET /api/documents/:id
   * Lấy chi tiết thông tin một tài liệu
   */
  @Get(':id')
  getDocumentById(@Param('id', ParseIntPipe) id: number) {
    return {
      status: 'success',
      data: this.documentsService.getDocumentById(id),
    };
  }

  /**
   * 3. GET /api/documents/:id/download
   * Tải file tài liệu về máy (Datasheet PDF hoặc Blueprint)
   */
  @Get(':id/download')
  downloadDocument(
    @Param('id', ParseIntPipe) id: number,
    @Res() res: Response,
  ) {
    const { filePath, fileName, isConfidential } =
      this.documentsService.resolveFileForDownload(id);

    if (isConfidential) {
      res.setHeader(
        'X-Security-Warning',
        'Confidential-Document-Exfiltrated-Shield-Off',
      );
    }

    return res.download(filePath, fileName);
  }
}
