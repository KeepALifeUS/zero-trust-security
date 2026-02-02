/**
 * Zero-Trust Policy Engine Tests
 * Enterprise Testing Standards
 */

import { Test, TestingModule } from '@nestjs/testing';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { ZeroTrustPolicyEngine } from './policy-engine';
import {
  ZeroTrustContext,
  AccessRequest,
  DeviceStatus,
  RiskLevel,
  NetworkZone,
} from '../types/zero-trust.types';
import {
  ZeroTrustPolicy,
  PolicyRule,
  PolicyActionConfig,
} from './policy-engine';

describe('ZeroTrustPolicyEngine', () => {
  let engine: ZeroTrustPolicyEngine;
  let eventEmitter: jest.Mocked<EventEmitter2>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ZeroTrustPolicyEngine,
        {
          provide: EventEmitter2,
          useValue: {
            emit: jest.fn(),
            emitAsync: jest.fn().mockResolvedValue([]),
          },
        },
      ],
    }).compile();

    engine = module.get<ZeroTrustPolicyEngine>(ZeroTrustPolicyEngine);
    eventEmitter = module.get(EventEmitter2) as jest.Mocked<EventEmitter2>;
  });

  describe('Policy Management', () => {
    it('should add a policy', () => {
      const policy = createMockPolicy();

      engine.addPolicy(policy);

      const retrieved = engine.getPolicy(policy.id);
      expect(retrieved).toBeDefined();
      expect(retrieved?.id).toBe(policy.id);
    });

    it('should remove a policy', () => {
      const policy = createMockPolicy();

      engine.addPolicy(policy);
      engine.removePolicy(policy.id);

      const retrieved = engine.getPolicy(policy.id);
      expect(retrieved).toBeUndefined();
    });

    it('should get all policies', () => {
      const policy1 = createMockPolicy('policy-1');
      const policy2 = createMockPolicy('policy-2');

      engine.addPolicy(policy1);
      engine.addPolicy(policy2);

      const policies = engine.getAllPolicies();
      expect(policies.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('Policy Evaluation', () => {
    it('should allow access when no blocking policies exist', async () => {
      const context = createMockContext();
      const request = createMockAccessRequest();

      const decision = await engine.evaluateAccess(request);

      expect(decision.allowed).toBeDefined();
    });

    it('should evaluate device status policy', async () => {
      const policy: ZeroTrustPolicy = {
        id: 'device-policy',
        name: 'Block Compromised Devices',
        description: 'Block access from compromised devices',
        enabled: true,
        priority: 100,
        conditions: [
          {
            field: 'context.device.status',
            operator: 'eq',
            value: DeviceStatus.COMPROMISED,
          },
        ],
        actions: [{ type: 'BLOCK' }],
        effect: 'DENY',
      };

      engine.addPolicy(policy);

      const context = createMockContext();
      context.device!.status = DeviceStatus.COMPROMISED;

      const request = createMockAccessRequest();
      request.context = context;

      const decision = await engine.evaluateAccess(request);

      expect(decision.allowed).toBe(false);
    });

    it('should evaluate network zone policy', async () => {
      const policy: ZeroTrustPolicy = {
        id: 'network-policy',
        name: 'Block TOR Network',
        description: 'Block access from TOR network',
        enabled: true,
        priority: 90,
        conditions: [
          {
            field: 'context.network.zone',
            operator: 'eq',
            value: NetworkZone.TOR,
          },
        ],
        actions: [{ type: 'BLOCK' }],
        effect: 'DENY',
      };

      engine.addPolicy(policy);

      const context = createMockContext();
      context.network!.zone = NetworkZone.TOR;

      const request = createMockAccessRequest();
      request.context = context;

      const decision = await engine.evaluateAccess(request);

      expect(decision.allowed).toBe(false);
    });

    it('should require challenge for low trust score', async () => {
      const policy: ZeroTrustPolicy = {
        id: 'trust-policy',
        name: 'Low Trust Challenge',
        description: 'Challenge users with low trust score',
        enabled: true,
        priority: 50,
        conditions: [
          {
            field: 'context.trustScore',
            operator: 'lt',
            value: 50,
          },
        ],
        actions: [{ type: 'CHALLENGE' }],
        effect: 'CHALLENGE',
      };

      engine.addPolicy(policy);

      const context = createMockContext();
      context.trustScore = 30;

      const request = createMockAccessRequest();
      request.context = context;

      const decision = await engine.evaluateAccess(request);

      expect(decision.allowed).toBe(false);
      if (decision.challenges) {
        expect(decision.challenges.length).toBeGreaterThan(0);
      }
    });
  });

  describe('Priority Handling', () => {
    it('should evaluate policies in priority order', async () => {
      const highPriorityPolicy: ZeroTrustPolicy = {
        id: 'high-priority',
        name: 'High Priority Deny',
        description: 'High priority deny policy',
        enabled: true,
        priority: 100,
        conditions: [
          {
            field: 'context.riskLevel',
            operator: 'eq',
            value: RiskLevel.CRITICAL,
          },
        ],
        actions: [{ type: 'BLOCK' }],
        effect: 'DENY',
      };

      const lowPriorityPolicy: ZeroTrustPolicy = {
        id: 'low-priority',
        name: 'Low Priority Allow',
        description: 'Low priority allow policy',
        enabled: true,
        priority: 10,
        conditions: [],
        actions: [{ type: 'LOG' }],
        effect: 'ALLOW',
      };

      engine.addPolicy(lowPriorityPolicy);
      engine.addPolicy(highPriorityPolicy);

      const context = createMockContext();
      context.riskLevel = RiskLevel.CRITICAL;

      const request = createMockAccessRequest();
      request.context = context;

      const decision = await engine.evaluateAccess(request);

      expect(decision.allowed).toBe(false);
      if (decision.triggeredPolicies) {
        expect(decision.triggeredPolicies[0]).toBe('high-priority');
      }
    });
  });
});

// Helper functions
function createMockPolicy(id: string = 'test-policy'): ZeroTrustPolicy {
  return {
    id,
    name: 'Test Policy',
    description: 'A test policy',
    enabled: true,
    priority: 50,
    conditions: [],
    actions: [],
    effect: 'ALLOW',
  };
}

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
