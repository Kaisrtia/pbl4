export interface DefenseFlags {
  l3_master: boolean;
  anti_sqli: boolean;
  rate_limit: boolean;
  input_sanitization: boolean;
}

export interface IDefenseService {
  getStatus(): DefenseFlags;
  toggleMaster(): boolean;
  toggleFlag(flag: keyof Omit<DefenseFlags, 'l3_master'>): boolean;
  setFlags(flags: Partial<DefenseFlags>): DefenseFlags;
  isAntiSqliEnabled(): boolean;
  isRateLimitEnabled(): boolean;
  isSanitizationEnabled(): boolean;
}

export const DEFENSE_SERVICE_TOKEN = 'IDefenseService';
