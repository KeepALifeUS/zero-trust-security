/**
 * Zero-Trust Guard Tests
 * Enterprise Testing Standards
 */

import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ZeroTrustGuard } from './zero-trust.guard';
import { ZeroTrustService } from '../services/zero-trust.service';
import { RiskLevel } from '../types/zero-trust.types';

describe('ZeroTrustGuard', () => {
  let guard: ZeroTrustGuard;
  let zeroTrustService: jest.Mocked<ZeroTrustService>;
  let reflector: jest.Mocked<Reflector>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ZeroTrustGuard,
        {
          provide: 'ZERO_TRUST_CONFIG',
          useValue: {
            enabled: true,
            strictMode: false,
            trustScoreThreshold: 50,
            maxSessionDuration: 86400000,
          },
        },
        {
          provide: Reflector,
          useValue: {
            getAllAndOverride: jest.fn(),
          },
        },
        {
          provide: ZeroTrustService,
          useValue: {
            getSessionInfo: jest.fn(),
            authorize: jest.fn(),
          },
        },
      ],
    }).compile();

    guard = module.get<ZeroTrustGuard>(ZeroTrustGuard);
    zeroTrustService = module.get(ZeroTrustService) as jest.Mocked<ZeroTrustService>;
    reflector = module.get(Reflector) as jest.Mocked<Reflector>;
  });

  describe('canActivate', () => {
    it('should allow access when Zero-Trust is disabled', async () => {
      const disabledGuard = new ZeroTrustGuard(
        { enabled: false } as any,
        reflector,
        zeroTrustService
      );

      const context = createMockExecutionContext();

      const result = await disabledGuard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should allow access when skip metadata is set', async () => {
      reflector.getAllAndOverride.mockReturnValue(true);

      const context = createMockExecutionContext();

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should throw UnauthorizedException when no session found', async () => {
      reflector.getAllAndOverride.mockReturnValue(false);

      const context = createMockExecutionContext({
        headers: {},
      });

      await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException when session is invalid', async () => {
      reflector.getAllAndOverride.mockReturnValue(false);
      zeroTrustService.getSessionInfo.mockReturnValue(null);

      const context = createMockExecutionContext({
        headers: {
          'x-session-id': 'session-123',
        },
      });

      await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
    });

    it('should allow access when session is valid and authorized', async () => {
      reflector.getAllAndOverride.mockReturnValue(false);
      zeroTrustService.getSessionInfo.mockReturnValue({
        sessionId: 'session-123',
        userId: 'user-123',
        deviceId: 'device-123',
        createdAt: new Date(),
        lastActivity: new Date(),
        trustScore: 75,
        riskLevel: RiskLevel.LOW,
        active: true,
      });

      zeroTrustService.authorize.mockResolvedValue({
        allowed: true,
        reason: 'Access granted',
        ttl: 3600,
      });

      const context = createMockExecutionContext({
        headers: {
          'x-session-id': 'session-123',
        },
      });

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
      expect(zeroTrustService.authorize).toHaveBeenCalled();
    });

    it('should throw ForbiddenException when authorization denied', async () => {
      reflector.getAllAndOverride.mockReturnValue(false);
      zeroTrustService.getSessionInfo.mockReturnValue({
        sessionId: 'session-123',
        userId: 'user-123',
        deviceId: 'device-123',
        createdAt: new Date(),
        lastActivity: new Date(),
        trustScore: 30,
        riskLevel: RiskLevel.HIGH,
        active: true,
      });

      zeroTrustService.authorize.mockResolvedValue({
        allowed: false,
        reason: 'Insufficient trust score',
        ttl: 0,
      });

      const context = createMockExecutionContext({
        headers: {
          'x-session-id': 'session-123',
        },
      });

      await expect(guard.canActivate(context)).rejects.toThrow(ForbiddenException);
    });

    it('should enforce minimum trust score when specified', async () => {
      reflector.getAllAndOverride
        .mockReturnValueOnce(false) // SKIP_ZERO_TRUST
        .mockReturnValueOnce({ minimumTrustScore: 80 }); // Options

      zeroTrustService.getSessionInfo.mockReturnValue({
        sessionId: 'session-123',
        userId: 'user-123',
        deviceId: 'device-123',
        createdAt: new Date(),
        lastActivity: new Date(),
        trustScore: 60,
        riskLevel: RiskLevel.MEDIUM,
        active: true,
      });

      const context = createMockExecutionContext({
        headers: {
          'x-session-id': 'session-123',
        },
      });

      await expect(guard.canActivate(context)).rejects.toThrow(ForbiddenException);
    });
  });
});

// Helper functions
function createMockExecutionContext(requestOptions: any = {}): ExecutionContext {
  const request = {
    headers: requestOptions.headers || {},
    cookies: requestOptions.cookies || {},
    method: requestOptions.method || 'GET',
    path: requestOptions.path || '/api/test',
    route: { path: '/api/test' },
    ip: '192.168.1.1',
    query: {},
    ...requestOptions,
  };

  const response = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
  };

  return {
    switchToHttp: () => ({
      getRequest: () => request,
      getResponse: () => response,
    }),
    getHandler: jest.fn(),
    getClass: jest.fn(),
  } as any;
}
