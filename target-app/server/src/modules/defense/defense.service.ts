import { Injectable, Logger } from '@nestjs/common';
import { DefenseFlags, IDefenseService } from './defense.constants';
import { envConfig } from '../../config/env.config';

@Injectable()
export class DefenseService implements IDefenseService {
  private readonly logger = new Logger(DefenseService.name);

  private flags: DefenseFlags = {
    l3_master: envConfig.initialDefense.l3Master,
    anti_sqli: envConfig.initialDefense.antiSqli,
    rate_limit: envConfig.initialDefense.rateLimit,
    input_sanitization: envConfig.initialDefense.inputSanitization,
  };

  getStatus(): DefenseFlags {
    return { ...this.flags };
  }

  toggleMaster(): boolean {
    const newState = !this.flags.l3_master;
    this.flags.l3_master = newState;
    // Khi bật/tắt master, đồng bộ toàn bộ các cờ con
    this.flags.anti_sqli = newState;
    this.flags.rate_limit = newState;
    this.flags.input_sanitization = newState;

    this.logger.log(
      `[DEFENSE MASTER] L3 Shield toggled to: ${newState ? 'SECURED (ON)' : 'VULNERABLE (OFF)'}`,
    );
    return newState;
  }

  toggleFlag(flag: keyof Omit<DefenseFlags, 'l3_master'>): boolean {
    if (flag in this.flags) {
      this.flags[flag] = !this.flags[flag];
      // Nếu bất kỳ cờ nào bật, coi như master L3 có hiệu lực một phần
      this.flags.l3_master =
        this.flags.anti_sqli &&
        this.flags.rate_limit &&
        this.flags.input_sanitization;
      this.logger.log(
        `[DEFENSE TOGGLE] Flag [${flag}] set to: ${this.flags[flag]}`,
      );
      return this.flags[flag];
    }
    return false;
  }

  setFlags(newFlags: Partial<DefenseFlags>): DefenseFlags {
    this.flags = {
      ...this.flags,
      ...newFlags,
    };
    this.logger.log(
      `[DEFENSE UPDATE] Flags updated: ${JSON.stringify(this.flags)}`,
    );
    return this.getStatus();
  }

  isAntiSqliEnabled(): boolean {
    return this.flags.l3_master || this.flags.anti_sqli;
  }

  isRateLimitEnabled(): boolean {
    return this.flags.l3_master || this.flags.rate_limit;
  }

  isSanitizationEnabled(): boolean {
    return this.flags.l3_master || this.flags.input_sanitization;
  }
}
