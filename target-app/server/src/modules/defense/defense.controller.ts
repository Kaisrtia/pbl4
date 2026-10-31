import {
  Controller,
  Get,
  Post,
  Body,
  Inject,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import {
  DEFENSE_SERVICE_TOKEN,
  IDefenseService,
  DefenseFlags,
} from './defense.constants';

@ApiTags('Defense')
@Controller('defense')
export class DefenseController {
  constructor(
    @Inject(DEFENSE_SERVICE_TOKEN)
    private readonly defenseService: IDefenseService,
  ) {}

  @Get('status')
  @ApiOperation({
    summary: 'Lấy trạng thái Khiên L3 hiện tại',
    description:
      'Trả về trạng thái của Master Shield và các cờ con: anti_sqli, rate_limit, input_sanitization.',
  })
  @ApiResponse({ status: 200, description: 'Lấy trạng thái thành công' })
  getStatus() {
    return {
      status: 'success',
      flags: this.defenseService.getStatus(),
      timestamp: new Date().toISOString(),
    };
  }

  @Post('toggle')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Bật / Tắt Khiên L3 (Nút Lab Control)',
    description:
      'Gửi body rỗng `{}` để đảo toàn bộ Master L3 (bật/tắt cả 3 khiên con), hoặc gửi `{ "flag": "anti_sqli" }` để đảo riêng 1 khiên con.',
  })
  @ApiBody({
    required: false,
    schema: {
      type: 'object',
      properties: {
        flag: {
          type: 'string',
          enum: ['anti_sqli', 'rate_limit', 'input_sanitization'],
          description:
            'Cờ con muốn toggle riêng (bỏ trống để toggle Master L3)',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Đã đảo trạng thái khiên thành công',
  })
  toggle(@Body() body: { flag?: keyof Omit<DefenseFlags, 'l3_master'> }) {
    if (body && body.flag) {
      const newState = this.defenseService.toggleFlag(body.flag);
      return {
        status: 'success',
        message: `Đã đảo trạng thái khiên [${body.flag}] thành ${newState}`,
        current_state: this.defenseService.getStatus(),
      };
    }

    // Mặc định toggle toàn bộ L3 master
    const masterState = this.defenseService.toggleMaster();
    return {
      status: 'success',
      message: `Đã đảo trạng thái Khiên L3 (Master) thành ${masterState ? 'BẬT (SECURED)' : 'TẮT (VULNERABLE)'}`,
      current_state: this.defenseService.getStatus(),
    };
  }

  @Post('set')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Gán trạng thái cụ thể cho các cờ phòng thủ' })
  @ApiResponse({ status: 200, description: 'Cập nhật cờ thành công' })
  setFlags(@Body() flags: Partial<DefenseFlags>) {
    const updated = this.defenseService.setFlags(flags);
    return {
      status: 'success',
      current_state: updated,
    };
  }
}
