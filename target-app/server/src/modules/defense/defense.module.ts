import { Module, Global } from '@nestjs/common';
import { DefenseService } from './defense.service';
import { DefenseController } from './defense.controller';
import { DEFENSE_SERVICE_TOKEN } from './defense.constants';
import { DynamicRateLimitGuard } from './guards/dynamic-rate-limit.guard';

@Global()
@Module({
  controllers: [DefenseController],
  providers: [
    {
      provide: DEFENSE_SERVICE_TOKEN,
      useClass: DefenseService,
    },
    DefenseService,
    DynamicRateLimitGuard,
  ],
  exports: [DEFENSE_SERVICE_TOKEN, DefenseService, DynamicRateLimitGuard],
})
export class DefenseModule {}
