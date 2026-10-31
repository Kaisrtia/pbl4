import {
  Controller,
  Get,
  Query,
  Res,
  BadRequestException,
} from '@nestjs/common';
import type { Response } from 'express';
import { FilesService } from './files.service';

@Controller('files')
export class FilesController {
  constructor(private readonly filesService: FilesService) {}

  @Get('download')
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
