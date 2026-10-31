import {
  Injectable,
  BadRequestException,
  NotFoundException,
  Inject,
  Logger,
} from '@nestjs/common';
import path from 'path';
import fs from 'fs';
import {
  DEFENSE_SERVICE_TOKEN,
  IDefenseService,
} from '../defense/defense.constants';
import { envConfig } from '../../config/env.config';

@Injectable()
export class FilesService {
  private readonly logger = new Logger(FilesService.name);
  private readonly publicDir = path.resolve(
    process.cwd(),
    envConfig.publicFilesDir,
  );

  constructor(
    @Inject(DEFENSE_SERVICE_TOKEN)
    private readonly defenseService: IDefenseService,
  ) {
    // Đảm bảo thư mục public file tồn tại và có file mẫu
    if (!fs.existsSync(this.publicDir)) {
      fs.mkdirSync(this.publicDir, { recursive: true });
      fs.writeFileSync(
        path.join(this.publicDir, 'sample_report.txt'),
        'PBL4 DevSec Shop - Sample Public Document Content\nGenerated for testing purposes.',
      );
    }
  }

  resolveFilePath(filename: string): {
    fullPath: string;
    isTraversalDetected: boolean;
  } {
    const isProtected = this.defenseService.isSanitizationEnabled();
    const hasTraversalPattern =
      filename.includes('..') ||
      filename.includes('/') ||
      filename.includes('\\');

    if (isProtected && hasTraversalPattern) {
      this.logger.warn(
        `[FILES] Path Traversal attack BLOCKED by L3 Shield for payload: [${filename}]`,
      );
      throw new BadRequestException({
        statusCode: 400,
        error: 'Bad Request',
        message:
          'L3 Sanitization Shield: Tên file chứa ký tự điều hướng thư mục bất hợp pháp!',
        shield: 'L3_INPUT_SANITIZATION_ACTIVE',
      });
    }

    // Nếu khiên tắt, cho phép ghép chuỗi tự do (VULNERABLE)
    const targetPath = path.resolve(this.publicDir, filename);

    if (!fs.existsSync(targetPath)) {
      throw new NotFoundException(`Không tìm thấy file: ${filename}`);
    }

    return {
      fullPath: targetPath,
      isTraversalDetected: hasTraversalPattern,
    };
  }
}
