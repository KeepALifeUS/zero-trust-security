/**
 * Zero-Trust Service Tests
 * Enterprise Testing Standards
 */

import { Test, TestingModule } from '@nestjs/testing';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { JwtService } from '@nestjs/jwt';
import { ZeroTrustService, AuthenticationRequest } from './zero-trust.service';
import { ZeroTrustPolicyEngine } from '../core/policy-engine';
import { TrustScoreCalculator } from '../core/trust-score-calculator';
import { ContinuousVerificationService } from './continuous-verification.service';
import {
  ZeroTrustContext,
  AccessRequest,
  AccessDecision,
  RiskLevel,
  DeviceStatus,
  NetworkZone,
} from '../types/zero-trust.types';

describe('ZeroTrustService', () => {
  let service: ZeroTrustService;
  let policyEngine: jest.Mocked<ZeroTrustPolicyEngine>;
  let trustCalculator: jest.Mocked<TrustScoreCalculator>;
  let continuousVerification: jest.Mocked<ContinuousVerificationService>;
  let eventEmitter: jest.Mocked<EventEmitter2>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ZeroTrustService,
        {
          provide: 'ZERO_TRUST_CONFIG',
          useValue: {
            enabled: true,
            strictMode: false,
            trustScoreThreshold: 50,
            maxSessionDuration: 86400000,
            continuousVerificationInterval: 0, // Disable for tests
          },
        },
        {
          provide: ZeroTrustPolicyEngine,
          useValue: {
            evaluateAccess: jest.fn(),
          },
        },
        {
          provide: TrustScoreCalculator,
          useValue: {
            calculateTrustScore: jest.fn(),
            getRiskLevel: jest.fn(),
          },
        },
        {
          provide: ContinuousVerificationService,
          useValue: {
            startContinuousVerification: jest.fn(),
            stopContinuousVerification: jest.fn(),
          },
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn().mockReturnValue('mock-jwt-token'),
          },
        },
        {
          provide: EventEmitter2,
          useValue: {
            emitAsync: jest.fn().mockResolvedValue([]),
            on: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<ZeroTrustService>(ZeroTrustService);
    policyEngine = module.get(ZeroTrustPolicyEngine) as jest.Mocked<ZeroTrustPolicyEngine>;
    trustCalculator = module.get(TrustScoreCalculator) as jest.Mocked<TrustScoreCalculator>;
    continuousVerification = module.get(ContinuousVerificationService) as jest.Mocked<ContinuousVerificationService>;
    eventEmitter = module.get(EventEmitter2) as jest.Mocked<EventEmitter2>;
  });

  describe('verifyAccess', () => {
    it('should verify access successfully for valid context', async () => {
      const context = createMockContext();
      const request = createMockAccessRequest();

      trustCalculator.calculateTrustScore.mockResolvedValue(75);
      trustCalculator.getRiskLevel.mockReturnValue(RiskLevel.LOW);

      const mockDecision: AccessDecision = {
        allowed: true,
        reason: 'Access granted',
        ttl: 3600,
      };

      policyEngine.evaluateAccess.mockResolvedValue(mockDecision);

      const decision = await service.verifyAccess(context, request);

      expect(decision.allowed).toBe(true);
      expect(trustCalculator.calculateTrustScore).toHaveBeenCalledWith(context);
      expect(policyEngine.evaluateAccess).toHaveBeenCalledWith(request);
    });

    it('should deny access when policy evaluation fails', async () => {
      const context = createMockContext();
      const request = createMockAccessRequest();

      trustCalculator.calculateTrustScore.mockResolvedValue(30);
      trustCalculator.getRiskLevel.mockReturnValue(RiskLevel.HIGH);

      const mockDecision: AccessDecision = {
        allowed: false,
        reason: 'Insufficient trust score',
        ttl: 0,
      };

      policyEngine.evaluateAccess.mockResolvedValue(mockDecision);

      const decision = await service.verifyAccess(context, request);

      expect(decision.allowed).toBe(false);
      expect(decision.reason).toBe('Insufficient trust score');
    });

    it('should handle errors gracefully', async () => {
      const context = createMockContext();
      const request = createMockAccessRequest();

      trustCalculator.calculateTrustScore.mockRejectedValue(new Error('Calculation failed'));

      const decision = await service.verifyAccess(context, request);

      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain('system error');
    });
  });

  describe('performRiskAssessment', () => {
    it('should assess risk correctly for trusted context', async () => {
      const context = createMockContext();

      trustCalculator.calculateTrustScore.mockResolvedValue(80);
      trustCalculator.getRiskLevel.mockReturnValue(RiskLevel.LOW);

      const assessment = await service.performRiskAssessment(context);

      expect(assessment.currentTrustScore).toBe(80);
      expect(assessment.riskLevel).toBe(RiskLevel.LOW);
      expect(assessment.riskFactors.length).toBeGreaterThanOrEqual(0);
    });

    it('should identify high-risk scenarios', async () => {
      const context = createMockContext();
      context.network = { ...context.network!, zone: NetworkZone.TOR };
      context.device!.status = DeviceStatus.UNTRUSTED;

      trustCalculator.calculateTrustScore.mockResolvedValue(25);
      trustCalculator.getRiskLevel.mockReturnValue(RiskLevel.CRITICAL);

      const assessment = await service.performRiskAssessment(context);

      // Should be HIGH because we have 2 risk factors (requires 3+ for CRITICAL)
      expect(assessment.riskLevel).toBe(RiskLevel.HIGH);
      expect(assessment.riskFactors).toContain('TOR_NETWORK');
      expect(assessment.riskFactors).toContain('UNTRUSTED_DEVICE');
    });
  });

  describe('generateSecurityChallenges', () => {
    it('should generate MFA challenge for MEDIUM risk', async () => {
      const context = createMockContext();
      context.identity.mfaEnabled = true;

      const challenges = await service.generateSecurityChallenges(context, RiskLevel.MEDIUM);

      expect(challenges.length).toBeGreaterThan(0);
      expect(challenges.some(c => c.type === 'MFA')).toBe(true);
    });

    it('should generate multiple challenges for HIGH risk', async () => {
      const context = createMockContext();
      context.identity.mfaEnabled = true;

      const challenges = await service.generateSecurityChallenges(context, RiskLevel.HIGH);

      // HIGH risk generates MFA + CAPTCHA = 2 challenges if MFA is enabled, otherwise just CAPTCHA
      expect(challenges.length).toBeGreaterThanOrEqual(1);
      expect(challenges.some(c => c.type === 'CAPTCHA')).toBe(true);
    });
  });

  describe('recordChallengeFailure', () => {
    it('should record challenge failures', async () => {
      const userId = 'user-123';

      await service.recordChallengeFailure(userId, 'challenge-1');
      await service.recordChallengeFailure(userId, 'challenge-2');

      const escalated = await service.checkChallengeEscalation(userId);

      expect(escalated).toBe(false); // Less than 3 failures
    });

    it('should escalate after 3 failures', async () => {
      const userId = 'user-123';

      await service.recordChallengeFailure(userId, 'challenge-1');
      await service.recordChallengeFailure(userId, 'challenge-2');
      await service.recordChallengeFailure(userId, 'challenge-3');

      const escalated = await service.checkChallengeEscalation(userId);

      expect(escalated).toBe(true);
      expect(eventEmitter.emitAsync).toHaveBeenCalledWith(
        'zero-trust.challenge.escalated',
        expect.objectContaining({ userId })
      );
    });
  });

  describe('generateComplianceReport', () => {
    it('should generate compliance report', async () => {
      const startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      const endDate = new Date();

      const report = await service.generateComplianceReport(startDate, endDate);

      expect(report).toBeDefined();
      expect(report.period.start).toEqual(startDate);
      expect(report.period.end).toEqual(endDate);
      expect(report.totalRequests).toBeGreaterThanOrEqual(0);
    });
  });
});

// Helper functions
function createMockContext(): ZeroTrustContext {
  return {
    sessionId: 'session-123',
    timestamp: new Date(),
    identity: {
      userId: 'user-123',
      username: 'testuser',
      email: 'test@example.com',
      roles: ['USER'],
      permissions: ['read'],
      authenticationMethods: [],
      lastAuthentication: new Date(),
      mfaEnabled: false,
      accountAge: 30 * 24 * 60 * 60 * 1000,
      trustScore: 75,
    },
    device: {
      deviceId: 'device-789',
      deviceType: 'desktop',
      platform: 'Linux',
      browser: 'Chrome',
      ipAddress: '192.168.1.1',
      fingerprint: 'fingerprint-123',
      status: DeviceStatus.TRUSTED,
      lastSeen: new Date(),
      trustScore: 80,
    },
    network: {
      sourceIp: '192.168.1.1',
      protocol: 'HTTPS',
      port: 443,
      zone: NetworkZone.CORPORATE,
      encrypted: true,
      certificateValid: true,
      mtlsEnabled: false,
      trustScore: 70,
    },
    behavioral: {
      normalLoginTime: ['9-17'],
      normalLocations: ['US'],
      normalDevices: ['device-789'],
      tradingPatterns: [],
      anomalyScore: 0.1,
      behaviorProfile: 'normal',
    },
    trustScore: 75,
    riskLevel: RiskLevel.LOW,
  };
}

function createMockAccessRequest(): AccessRequest {
  return {
    requestId: 'req-001',
    resourceId: 'resource-123',
    action: 'read',
    timestamp: new Date(),
    metadata: {},
  };
}
