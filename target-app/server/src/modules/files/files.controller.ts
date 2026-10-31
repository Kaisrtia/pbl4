import {
  Controller,
  Get,
  Query,
  Res,
  BadRequestException,
} from '@nestjs/common';
import type { Response } from 'express';
import { ApiTags, ApiOperation, ApiQuery, ApiResponse } from '@nestjs/swagger';
import { FilesService } from './files.service';

@ApiTags('Files')
@Controller('files')
export class FilesController {
  constructor(private readonly filesService: FilesService) {}

  @Get('download')
  @ApiOperation({
    summary: 'Tải file công khai (Mô phỏng tấn công Path Traversal)',
    description:
      'Khi Khiên L3 BẬT: Chặn các payload chứa `..`, `/`, `\\` (mã lỗi 400 Bad Request). Khi Khiên L3 TẮT: Nối chuỗi đường dẫn trực tiếp cho phép đọc file tùy ý.',
  })
  @ApiQuery({
    name: 'name',
    example: 'sample_report.txt',
    description:
      'Tên file cần tải (Thử payload `../../etc/passwd` để test Path Traversal)',
  })
  @ApiResponse({ status: 200, description: 'Tải file thành công' })
  @ApiResponse({
    status: 400,
    description: 'Bị Khiên Input Sanitization chặn đứng',
  })
  @ApiResponse({ status: 404, description: 'Không tìm thấy file' })
  downloadFile(@Query('name') filename: string, @Res() res: Response) {
    if (!filename) {
      throw new BadRequestException('Vui lòng truyền tham số ?name=<filename>');
    }

    const { fullPath, isTraversalDetected } =
      this.filesService.resolveFilePath(filename);

    if (isTraversalDetected) {
      res.setHeader('X-Security-Warning', 'Path-Traversal-Bypassed-Shield-Off');
    }

    return res.sendFile(fullPath);
  }
}
