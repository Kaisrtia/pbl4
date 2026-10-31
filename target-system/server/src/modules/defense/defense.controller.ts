import {
  Controller,
  Get,
  Post,
  Body,
  Inject,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  DEFENSE_SERVICE_TOKEN,
  IDefenseService,
  DefenseFlags,
} from './defense.constants';

@Controller('defense')
export class DefenseController {
  constructor(
    @Inject(DEFENSE_SERVICE_TOKEN)
    private readonly defenseService: IDefenseService,
  ) {}

  @Get('status')
  getStatus() {
    return {
      status: 'success',
      flags: this.defenseService.getStatus(),
      timestamp: new Date().toISOString(),
    };
  }

  @Post('toggle')
  @HttpCode(HttpStatus.OK)
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
  setFlags(@Body() flags: Partial<DefenseFlags>) {
    const updated = this.defenseService.setFlags(flags);
    return {
      status: 'success',
      message: 'Cập nhật cờ phòng thủ thành công',
      current_state: updated,
    };
  }
}
