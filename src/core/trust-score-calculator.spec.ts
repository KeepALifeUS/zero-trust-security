/**
 * Trust Score Calculator Tests
 * Enterprise Testing Standards
 */

import { Test, TestingModule } from '@nestjs/testing';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { TrustScoreCalculator } from './trust-score-calculator';
import {
  ZeroTrustContext,
  RiskLevel,
  TrustLevel,
  DeviceStatus,
  NetworkZone,
  AuthenticationMethod,
} from '../types/zero-trust.types';

describe('TrustScoreCalculator', () => {
  let calculator: TrustScoreCalculator;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TrustScoreCalculator,
        {
          provide: EventEmitter2,
          useValue: {
            emit: jest.fn(),
            emitAsync: jest.fn().mockResolvedValue([]),
            on: jest.fn(),
          },
        },
      ],
    }).compile();

    calculator = module.get<TrustScoreCalculator>(TrustScoreCalculator);
  });

  describe('calculateTrustScore', () => {
    it('should calculate trust score for trusted context', async () => {
      const context = createTrustedContext();

      const score = await calculator.calculateTrustScore(context);

      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(100);
      expect(score).toBeGreaterThan(60);
    });

    it('should return lower score for untrusted device', async () => {
      const context = createTrustedContext();
      context.device!.status = DeviceStatus.UNTRUSTED;

      const score = await calculator.calculateTrustScore(context);

      expect(score).toBeLessThan(60);
    });

    it('should return lower score for TOR network', async () => {
      const context = createTrustedContext();
      context.network!.zone = NetworkZone.TOR;

      const score = await calculator.calculateTrustScore(context);

      expect(score).toBeLessThan(60);
    });

    it('should return higher score for MFA authentication', async () => {
      const context = createTrustedContext();
      context.identity.mfaEnabled = true;
      context.identity.authenticationMethods = [
        AuthenticationMethod.PASSWORD,
        AuthenticationMethod.MFA_TOTP,
      ];

      const score = await calculator.calculateTrustScore(context);

      expect(score).toBeGreaterThan(60);
    });
  });

  describe('getRiskLevel', () => {
    it('should return MINIMAL risk for high trust score', () => {
      const riskLevel = calculator.getRiskLevel(85);

      expect(riskLevel).toBe(RiskLevel.MINIMAL); // 85 >= 80
    });

    it('should return LOW risk for good trust score', () => {
      const riskLevel = calculator.getRiskLevel(65);

      expect(riskLevel).toBe(RiskLevel.LOW); // 65 in range 60-79
    });

    it('should return MEDIUM risk for medium trust score', () => {
      const riskLevel = calculator.getRiskLevel(50);

      expect(riskLevel).toBe(RiskLevel.MEDIUM); // 50 in range 40-59
    });

    it('should return HIGH risk for low trust score', () => {
      const riskLevel = calculator.getRiskLevel(30);

      expect(riskLevel).toBe(RiskLevel.HIGH); // 30 in range 20-39
    });

    it('should return CRITICAL risk for very low trust score', () => {
      const riskLevel = calculator.getRiskLevel(10);

      expect(riskLevel).toBe(RiskLevel.CRITICAL); // 10 < 20
    });
  });

  describe('determineTrustLevel', () => {
    it('should return HIGH trust level for high score', () => {
      const trustLevel = calculator.determineTrustLevel(85);

      expect(trustLevel).toBe(TrustLevel.HIGH);
    });

    it('should return MEDIUM trust level for medium score', () => {
      const trustLevel = calculator.determineTrustLevel(55);

      expect(trustLevel).toBe(TrustLevel.MEDIUM);
    });

    it('should return LOW trust level for low score', () => {
      const trustLevel = calculator.determineTrustLevel(30);

      expect(trustLevel).toBe(TrustLevel.LOW); // 30 is in the 26-50 range
    });

    it('should return CRITICAL trust level for very low score', () => {
      const trustLevel = calculator.determineTrustLevel(10);

      expect(trustLevel).toBe(TrustLevel.CRITICAL); // 10 is <= 25
    });
  });

  describe('Score Components', () => {
    it('should consider device trust in calculation', async () => {
      const trustedContext = createTrustedContext();
      const untrustedContext = createTrustedContext();
      untrustedContext.device!.status = DeviceStatus.UNTRUSTED;

      const trustedScore = await calculator.calculateTrustScore(trustedContext);
      const untrustedScore = await calculator.calculateTrustScore(untrustedContext);

      expect(trustedScore).toBeGreaterThan(untrustedScore);
    });

    it('should consider network trust in calculation', async () => {
      const corporateContext = createTrustedContext();
      const torContext = createTrustedContext();
      torContext.network!.zone = NetworkZone.TOR;

      const corporateScore = await calculator.calculateTrustScore(corporateContext);
      const torScore = await calculator.calculateTrustScore(torContext);

      expect(corporateScore).toBeGreaterThan(torScore);
    });

    it('should consider behavioral trust in calculation', async () => {
      const normalContext = createTrustedContext();
      const anomalousContext = createTrustedContext();
      anomalousContext.behavioral!.anomalyScore = 0.9;

      const normalScore = await calculator.calculateTrustScore(normalContext);
      const anomalousScore = await calculator.calculateTrustScore(anomalousContext);

      expect(normalScore).toBeGreaterThan(anomalousScore);
    });
  });
});

// Helper functions
function createTrustedContext(): ZeroTrustContext {
  return {
    sessionId: 'session-123',
    timestamp: new Date(),
    identity: {
      userId: 'user-123',
      username: 'testuser',
      email: 'test@example.com',
      roles: ['USER'],
      permissions: ['read'],
      authenticationMethods: [AuthenticationMethod.PASSWORD],
      lastAuthentication: new Date(),
      mfaEnabled: false,
      accountAge: 90 * 24 * 60 * 60 * 1000, // 90 days
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
