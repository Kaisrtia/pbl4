import {
  Controller,
  Get,
  Param,
  Query,
  Res,
  ParseIntPipe,
} from '@nestjs/common';
import type { Response } from 'express';
import {
  ApiTags,
  ApiOperation,
  ApiQuery,
  ApiParam,
  ApiResponse,
} from '@nestjs/swagger';
import { DocumentsService } from './documents.service';

@ApiTags('Documents')
@Controller('documents')
export class DocumentsController {
  constructor(private readonly documentsService: DocumentsService) {}

  /**
   * 1. GET /api/documents
   * Lấy danh sách tài liệu kỹ thuật (phục vụ tab "Tài liệu kỹ thuật" trên Header)
   */
  @Get()
  @ApiOperation({
    summary: 'Lấy danh sách tài liệu kỹ thuật (Datasheet, Pinout, Blueprint)',
    description:
      'Mặc định ẩn các tài liệu tuyệt mật (Confidential) trừ khi truyền `include_confidential=true`.',
  })
  @ApiQuery({
    name: 'search',
    required: false,
    description: 'Tìm theo tiêu đề hoặc tên file',
  })
  @ApiQuery({
    name: 'product_id',
    required: false,
    description: 'Lọc tài liệu theo ID sản phẩm',
  })
  @ApiQuery({
    name: 'include_confidential',
    required: false,
    description: 'Hiện cả tài liệu tuyệt mật (true/false)',
  })
  @ApiResponse({
    status: 200,
    description: 'Lấy danh sách tài liệu thành công',
  })
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
  @ApiOperation({ summary: 'Lấy thông tin chi tiết một tài liệu theo ID' })
  @ApiParam({ name: 'id', example: 1, description: 'ID tài liệu' })
  @ApiResponse({ status: 200, description: 'Tìm thấy tài liệu' })
  @ApiResponse({ status: 404, description: 'Không tìm thấy tài liệu' })
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
  @ApiOperation({
    summary: 'Tải file tài liệu kỹ thuật về máy',
    description:
      'Đối với tài liệu tuyệt mật (Confidential): Khi Khiên L3 BẬT -> chặn 403 Forbidden. Khi Khiên L3 TẮT -> cho phép tải lậu (mô phỏng rò rỉ dữ liệu).',
  })
  @ApiParam({ name: 'id', example: 1, description: 'ID tài liệu cần tải' })
  @ApiResponse({ status: 200, description: 'Tải file thành công' })
  @ApiResponse({
    status: 403,
    description: 'Bị Khiên L3 chặn tải tài liệu tuyệt mật',
  })
  @ApiResponse({ status: 404, description: 'Không tìm thấy file vật lý' })
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
