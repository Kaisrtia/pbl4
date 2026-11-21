import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException } from '@nestjs/common';
import { SystemController } from './system.controller';
import {
  DEFENSE_SERVICE_TOKEN,
  IDefenseService,
} from '../defense/defense.constants';

describe('SystemController', () => {
  let controller: SystemController;
  let mockDefenseService: Partial<IDefenseService>;

  beforeEach(async () => {
    mockDefenseService = {
      getStatus: vi.fn().mockReturnValue({
        l3_master: true,
        anti_sqli: true,
        rate_limit: true,
        input_sanitization: true,
      }),
      isSanitizationEnabled: vi.fn().mockReturnValue(true),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [SystemController],
      providers: [
        {
          provide: DEFENSE_SERVICE_TOKEN,
          useValue: mockDefenseService,
        },
      ],
    }).compile();

    controller = module.get<SystemController>(SystemController);
  });

  describe('ping', () => {
    it('should return pong with latency calculation', () => {
      const now = Date.now();
      const res = controller.ping(String(now - 20), 'hello');
      expect(res.status).toBe('success');
      expect(res.message).toBe('pong');
      expect(res.echo).toBe('hello');
      expect(res.latency_ms).toBeGreaterThanOrEqual(20);
    });
  });

  describe('health', () => {
    it('should return online status and defense status', () => {
      const res = controller.health();
      expect(res.status).toBe('online');
      expect(res.defense_status).toBeDefined();
    });
  });

  describe('networkPing', () => {
    it('should throw BadRequestException when host query parameter is missing', async () => {
      await expect(controller.networkPing('')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should block command injection payload when defense shield is ON', async () => {
      vi.mocked(mockDefenseService.isSanitizationEnabled!).mockReturnValue(true);

      await expect(
        controller.networkPing('127.0.0.1; id'),
      ).rejects.toThrow(BadRequestException);

      try {
        await controller.networkPing('127.0.0.1; id');
      } catch (err: any) {
        expect(err.getResponse()).toEqual({
          statusCode: 400,
          message:
            'L3 Sanitization Shield: Phát hiện ký tự điều hướng lệnh Shell nguy hiểm!',
          shield: 'L3_COMMAND_INJECTION_BLOCKED',
        });
      }
    });

    it('should block command injection payload with pipe | when shield is ON', async () => {
      vi.mocked(mockDefenseService.isSanitizationEnabled!).mockReturnValue(true);

      await expect(
        controller.networkPing('127.0.0.1 | whoami'),
      ).rejects.toThrow(BadRequestException);
    });

    it('should allow normal host ping when shield is ON', async () => {
      vi.mocked(mockDefenseService.isSanitizationEnabled!).mockReturnValue(true);

      const res = await controller.networkPing('127.0.0.1');
      expect(res.status).toBe('success');
      expect(res.defense_mode).toBe('SECURED_SANITIZED');
      expect(res.command_injection_bypassed).toBe(false);
      expect(res.host).toBe('127.0.0.1');
    });

    it('should execute command injection payload when shield is OFF (vulnerable mode)', async () => {
      vi.mocked(mockDefenseService.isSanitizationEnabled!).mockReturnValue(false);

      const mockRes = {
        setHeader: vi.fn(),
      } as any;

      const res = await controller.networkPing('127.0.0.1; echo "pbl4_test"', mockRes);
      expect(res.status).toBe('success');
      expect(res.defense_mode).toBe('VULNERABLE_DIRECT_EXEC');
      expect(res.command_injection_bypassed).toBe(true);
      expect(res.output).toContain('pbl4_test');
      expect(mockRes.setHeader).toHaveBeenCalledWith(
        'X-Security-Warning',
        'Command-Injection-Bypassed-Shield-Off',
      );
    });
  });
});
