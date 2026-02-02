/**
 * Zero-Trust Policy Engine
 * Enterprise Pattern
 *
 * Core engine for evaluating Zero-Trust policies
 * Implements "Never Trust, Always Verify" principle
 */

import { Injectable, Logger } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { v4 as uuidv4 } from 'uuid';

import {
  ZeroTrustContext,
  AccessRequest,
  AccessDecision,
  PolicyEvaluation,
  PolicyCondition,
  RequiredAction,
  SecurityChallenge,
  ZeroTrustEvent,
  ZeroTrustEventType,
  NetworkZone,
  DeviceStatus,
} from '../types/zero-trust.types';

export interface ZeroTrustPolicy {
  id: string;
  name: string;
  description: string;
  priority: number;
  enabled: boolean;
  conditions: PolicyRule[];
  actions: PolicyActionConfig[];
  effect: 'ALLOW' | 'DENY' | 'CHALLENGE';
}

export interface PolicyRule {
  field: string;
  operator: 'eq' | 'neq' | 'gt' | 'lt' | 'gte' | 'lte' | 'in' | 'nin' | 'regex';
  value: any;
  combineWith?: 'AND' | 'OR';
}

export interface PolicyActionConfig {
  type: 'LOG' | 'ALERT' | 'BLOCK' | 'CHALLENGE' | 'REQUIRE_MFA' | 'LIMIT_ACCESS';
  parameters?: Record<string, any>;
}

@Injectable()
export class ZeroTrustPolicyEngine {
  private readonly logger = new Logger(ZeroTrustPolicyEngine.name);
  private policies: Map<string, ZeroTrustPolicy> = new Map();
  private policyCache: Map<string, PolicyEvaluation> = new Map();

  constructor(private readonly eventEmitter: EventEmitter2) {
    this.initializeDefaultPolicies();
  }

  /**
   * Initialize default Zero-Trust policies
   */
  private initializeDefaultPolicies(): void {
    // Policy 1: Block compromised devices
    this.addPolicy({
      id: 'zt-001',
      name: 'Block Compromised Devices',
      description: 'Deny access from compromised or blacklisted devices',
      priority: 100,
      enabled: true,
      conditions: [
        { field: 'device.status', operator: 'in', value: [DeviceStatus.COMPROMISED, DeviceStatus.BLACKLISTED] },
      ],
      actions: [
        { type: 'BLOCK' },
        { type: 'ALERT', parameters: { severity: 'CRITICAL' } },
        { type: 'LOG' },
      ],
      effect: 'DENY',
    });

    // Policy 2: Require MFA for high-risk networks
    this.addPolicy({
      id: 'zt-002',
      name: 'MFA for Suspicious Networks',
      description: 'Require MFA when accessing from suspicious networks',
      priority: 90,
      enabled: true,
      conditions: [
        { field: 'network.zone', operator: 'in', value: [NetworkZone.SUSPICIOUS, NetworkZone.TOR, NetworkZone.PROXY] },
      ],
      actions: [
        { type: 'REQUIRE_MFA' },
        { type: 'LOG' },
      ],
      effect: 'CHALLENGE',
    });

    // Policy 3: Trust score threshold
    this.addPolicy({
      id: 'zt-003',
      name: 'Minimum Trust Score',
      description: 'Require minimum trust score for access',
      priority: 80,
      enabled: true,
      conditions: [
        { field: 'trustScore', operator: 'lt', value: 50 },
      ],
      actions: [
        { type: 'CHALLENGE' },
        { type: 'LIMIT_ACCESS' },
        { type: 'LOG' },
      ],
      effect: 'CHALLENGE',
    });

    // Policy 4: Behavioral anomaly detection
    this.addPolicy({
      id: 'zt-004',
      name: 'Behavioral Anomaly Response',
      description: 'Challenge access when behavioral anomalies detected',
      priority: 70,
      enabled: true,
      conditions: [
        { field: 'behavioral.anomalyScore', operator: 'gt', value: 0.7 },
      ],
      actions: [
        { type: 'CHALLENGE', parameters: { type: 'BIOMETRIC' } },
        { type: 'ALERT', parameters: { severity: 'HIGH' } },
        { type: 'LOG' },
      ],
      effect: 'CHALLENGE',
    });

    // Policy 5: Service-to-service mTLS requirement
    this.addPolicy({
      id: 'zt-005',
      name: 'Service Mesh mTLS',
      description: 'Require mTLS for service-to-service communication',
      priority: 95,
      enabled: true,
      conditions: [
        { field: 'network.mtlsEnabled', operator: 'eq', value: false },
        { field: 'context.type', operator: 'eq', value: 'SERVICE', combineWith: 'AND' },
      ],
      actions: [
        { type: 'BLOCK' },
        { type: 'LOG' },
      ],
      effect: 'DENY',
    });

    // Policy 6: Time-based access control
    this.addPolicy({
      id: 'zt-006',
      name: 'Time-based Access',
      description: 'Restrict access outside normal hours for non-admin users',
      priority: 60,
      enabled: true,
      conditions: [
        { field: 'identity.roles', operator: 'nin', value: ['ADMIN', 'SYSTEM'] },
        { field: 'time.outsideBusinessHours', operator: 'eq', value: true, combineWith: 'AND' },
      ],
      actions: [
        { type: 'CHALLENGE' },
        { type: 'LOG' },
      ],
      effect: 'CHALLENGE',
    });

    // Policy 7: Continuous verification requirement
    this.addPolicy({
      id: 'zt-007',
      name: 'Continuous Verification',
      description: 'Require continuous verification for sensitive operations',
      priority: 85,
      enabled: true,
      conditions: [
        { field: 'continuousVerification', operator: 'eq', value: false },
        { field: 'resource.sensitive', operator: 'eq', value: true, combineWith: 'AND' },
      ],
      actions: [
        { type: 'CHALLENGE' },
        { type: 'LOG' },
      ],
      effect: 'CHALLENGE',
    });

    this.logger.log(`Initialized ${this.policies.size} default Zero-Trust policies`);
  }

  /**
   * Add or update a policy
   */
  public addPolicy(policy: ZeroTrustPolicy): void {
    this.policies.set(policy.id, policy);
    this.clearPolicyCache();
    this.logger.debug(`Added/Updated policy: ${policy.name} (${policy.id})`);
  }

  /**
   * Remove a policy
   */
  public removePolicy(policyId: string): void {
    this.policies.delete(policyId);
    this.clearPolicyCache();
    this.logger.debug(`Removed policy: ${policyId}`);
  }

  /**
   * Get all policies
   */
  public getAllPolicies(): ZeroTrustPolicy[] {
    return Array.from(this.policies.values());
  }

  /**
   * Get specific policy
   */
  public getPolicy(policyId: string): ZeroTrustPolicy | undefined {
    return this.policies.get(policyId);
  }

  /**
   * Update policy
   */
  public updatePolicy(policyId: string, updates: Partial<ZeroTrustPolicy>): void {
    const policy = this.policies.get(policyId);
    if (policy) {
      Object.assign(policy, updates);
      this.clearPolicyCache();
      this.logger.log(`Updated policy: ${policyId}`);
    }
  }

  /**
   * Disable policy
   */
  public disablePolicy(policyId: string): void {
    const policy = this.policies.get(policyId);
    if (policy) {
      policy.enabled = false;
      this.clearPolicyCache();
      this.logger.log(`Disabled policy: ${policyId}`);
    }
  }

  /**
   * Evaluate access request (alias for evaluateAccess)
   */
  public async evaluate(_context: ZeroTrustContext, _request: AccessRequest): Promise<AccessDecision> {
    const fullRequest = { ..._request, _context };
    return this.evaluateAccess(fullRequest);
  }

  /**
   * Evaluate access request against all policies
   */
  public async evaluateAccess(request: AccessRequest): Promise<AccessDecision> {
    const startTime = Date.now();
    const context = request.context;

    // Check cache first
    if (context) {
      const cacheKey = this.generateCacheKey(request);
      const cachedResult = this.policyCache.get(cacheKey);
      if (cachedResult && this.isCacheValid(cachedResult)) {
        this.logger.debug(`Policy cache hit for ${cacheKey}`);
        return this.createAccessDecision(cachedResult, context);
      }
    }

    // Sort policies by priority (higher priority first)
    const sortedPolicies = Array.from(this.policies.values())
      .filter(p => p.enabled)
      .sort((a, b) => b.priority - a.priority);

    const evaluations: PolicyEvaluation[] = [];
    let finalEffect: 'ALLOW' | 'DENY' | 'CHALLENGE' = 'ALLOW';
    const requiredActions: RequiredAction[] = [];
    const challenges: SecurityChallenge[] = [];

    // Evaluate each policy
    if (!context) {
      return {
        allowed: false,
        reason: 'No context provided',
      };
    }

    for (const policy of sortedPolicies) {
      const evaluation = await this.evaluatePolicy(policy, context, request);
      evaluations.push(evaluation);

      // Process policy actions
      if (evaluation.result !== 'ALLOW') {
        for (const action of policy.actions) {
          await this.executeAction(action, context, requiredActions, challenges);
        }
      }

      // Deny takes precedence over everything
      if (evaluation.result === 'DENY') {
        finalEffect = 'DENY';
        break;
      }

      // Challenge takes precedence over allow
      if (evaluation.result === 'CHALLENGE' && finalEffect === 'ALLOW') {
        finalEffect = 'CHALLENGE';
      }
    }

    // Cache the evaluation result
    const policyEvaluation: PolicyEvaluation = {
      policyId: 'composite',
      policyName: 'Zero-Trust Composite Policy',
      result: finalEffect,
      reason: this.generateReason(evaluations),
      conditions: evaluations.flatMap(e => e.conditions),
      evaluatedAt: new Date(),
    };

    const cacheKey = this.generateCacheKey(request);
    this.policyCache.set(cacheKey, policyEvaluation);

    // Emit evaluation event
    await this.emitEvaluationEvent(context, finalEffect, evaluations);

    // Calculate trust score impact
    const trustScoreImpact = this.calculateTrustScoreImpact(finalEffect, evaluations);

    // Create and return access decision
    const decision: AccessDecision = {
      allowed: finalEffect === 'ALLOW',
      reason: policyEvaluation.reason || 'Access evaluated by Zero-Trust policies',
      requiredActions: requiredActions.length > 0 ? requiredActions : undefined,
      trustScoreImpact,
      ttl: this.calculateTTL(context, finalEffect),
      challenges: challenges.length > 0 ? challenges : undefined,
    };

    const duration = Date.now() - startTime;
    this.logger.debug(`Policy evaluation completed in ${duration}ms: ${finalEffect}`);

    return decision;
  }

  /**
   * Evaluate a single policy
   */
  private async evaluatePolicy(
    policy: ZeroTrustPolicy,
    context: ZeroTrustContext,
    request: AccessRequest,
  ): Promise<PolicyEvaluation> {
    const conditions: PolicyCondition[] = [];
    let result = true;
    let combineWithOr = false;

    for (const rule of policy.conditions) {
      const conditionResult = await this.evaluateCondition(rule, context, request);
      conditions.push({
        type: rule.field,
        operator: rule.operator as any,
        value: rule.value,
        result: conditionResult,
      });

      if (rule.combineWith === 'OR') {
        result = result || conditionResult;
        combineWithOr = true;
      } else {
        result = combineWithOr ? result || conditionResult : result && conditionResult;
        combineWithOr = false;
      }
    }

    const policyResult = result ? policy.effect : 'ALLOW';

    return {
      policyId: policy.id,
      policyName: policy.name,
      result: policyResult,
      reason: result ? policy.description : undefined,
      conditions,
      evaluatedAt: new Date(),
    };
  }

  /**
   * Evaluate a single condition
   */
  private async evaluateCondition(
    rule: PolicyRule,
    context: ZeroTrustContext,
    request: AccessRequest,
  ): Promise<boolean> {
    const value = this.extractValue(rule.field, context, request);

    switch (rule.operator) {
      case 'eq':
        return value === rule.value;
      case 'neq':
        return value !== rule.value;
      case 'gt':
        return value > rule.value;
      case 'lt':
        return value < rule.value;
      case 'gte':
        return value >= rule.value;
      case 'lte':
        return value <= rule.value;
      case 'in':
        return Array.isArray(rule.value) ? rule.value.includes(value) : false;
      case 'nin':
        return Array.isArray(rule.value) ? !rule.value.includes(value) : true;
      case 'regex':
        return new RegExp(rule.value).test(value);
      default:
        return false;
    }
  }

  /**
   * Extract value from context based on field path
   */
  private extractValue(field: string, context: ZeroTrustContext, request: AccessRequest): any {
    const parts = field.split('.');
    let value: any = { ...context, ...request };

    for (const part of parts) {
      if (value && typeof value === 'object') {
        value = value[part];
      } else {
        return undefined;
      }
    }

    return value;
  }

  /**
   * Execute policy action
   */
  private async executeAction(
    action: PolicyActionConfig,
    context: ZeroTrustContext,
    requiredActions: RequiredAction[],
    challenges: SecurityChallenge[],
  ): Promise<void> {
    switch (action.type) {
      case 'LOG':
        this.logger.log(`Policy action: ${action.type} for session ${context.sessionId}`);
        break;

      case 'ALERT':
        await this.eventEmitter.emitAsync('zero-trust.alert', {
          context,
          severity: action.parameters?.severity || 'MEDIUM',
          timestamp: new Date(),
        });
        break;

      case 'BLOCK':
        this.logger.warn(`Access blocked for session ${context.sessionId}`);
        break;

      case 'REQUIRE_MFA':
        requiredActions.push(RequiredAction.MFA_REQUIRED);
        break;

      case 'CHALLENGE':
        challenges.push({
          type: action.parameters?.type || 'CAPTCHA',
          challengeId: uuidv4(),
          expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
          attempts: 0,
          maxAttempts: 3,
        });
        break;

      case 'LIMIT_ACCESS':
        this.logger.log(`Access limited for session ${context.sessionId}`);
        break;
    }
  }

  /**
   * Calculate trust score impact
   */
  private calculateTrustScoreImpact(
    effect: 'ALLOW' | 'DENY' | 'CHALLENGE',
    evaluations: PolicyEvaluation[],
  ): number {
    let impact = 0;

    switch (effect) {
      case 'ALLOW':
        impact = 5; // Successful access increases trust
        break;
      case 'CHALLENGE':
        impact = -5; // Challenge slightly decreases trust
        break;
      case 'DENY':
        impact = -20; // Denial significantly decreases trust
        break;
    }

    // Adjust based on policy violations
    const violations = evaluations.filter(e => e.result === 'DENY').length;
    impact -= violations * 10;

    return Math.max(-100, Math.min(100, impact));
  }

  /**
   * Calculate TTL for the access decision
   */
  private calculateTTL(context: ZeroTrustContext, effect: 'ALLOW' | 'DENY' | 'CHALLENGE'): number {
    const baseTTL = 300000; // 5 minutes base TTL

    // Adjust based on trust score
    const trustMultiplier = (context.trustScore || 50) / 100;

    // Adjust based on effect
    let effectMultiplier = 1;
    switch (effect) {
      case 'ALLOW':
        effectMultiplier = 2;
        break;
      case 'CHALLENGE':
        effectMultiplier = 0.5;
        break;
      case 'DENY':
        effectMultiplier = 0.1;
        break;
    }

    return Math.floor(baseTTL * trustMultiplier * effectMultiplier);
  }

  /**
   * Generate cache key for policy evaluation
   */
  private generateCacheKey(request: AccessRequest): string {
    const context = request.context;
    if (!context || !context.device) {
      return `${context?.identity.userId || 'unknown'}:unknown:${request.resource}:${request.action}`;
    }
    return `${context.identity.userId}:${context.device.deviceId}:${request.resource}:${request.action}`;
  }

  /**
   * Check if cached evaluation is still valid
   */
  private isCacheValid(evaluation: PolicyEvaluation): boolean {
    const maxAge = 60000; // 1 minute cache validity
    return (Date.now() - evaluation.evaluatedAt.getTime()) < maxAge;
  }

  /**
   * Clear policy cache
   */
  private clearPolicyCache(): void {
    this.policyCache.clear();
    this.logger.debug('Policy cache cleared');
  }

  /**
   * Generate reason from evaluations
   */
  private generateReason(evaluations: PolicyEvaluation[]): string {
    const deniedPolicies = evaluations.filter(e => e.result === 'DENY');
    const challengedPolicies = evaluations.filter(e => e.result === 'CHALLENGE');

    if (deniedPolicies.length > 0) {
      return `Access denied by policies: ${deniedPolicies.map(p => p.policyName).join(', ')}`;
    }

    if (challengedPolicies.length > 0) {
      return `Additional verification required by policies: ${challengedPolicies.map(p => p.policyName).join(', ')}`;
    }

    return 'Access granted by Zero-Trust policies';
  }

  /**
   * Create access decision from cached evaluation
   */
  private createAccessDecision(evaluation: PolicyEvaluation, context: ZeroTrustContext): AccessDecision {
    return {
      allowed: evaluation.result === 'ALLOW',
      reason: evaluation.reason || 'Cached policy decision',
      trustScoreImpact: 0,
      ttl: this.calculateTTL(context, evaluation.result),
    };
  }

  /**
   * Emit evaluation event
   */
  private async emitEvaluationEvent(
    context: ZeroTrustContext,
    effect: 'ALLOW' | 'DENY' | 'CHALLENGE',
    evaluations: PolicyEvaluation[],
  ): Promise<void> {
    const event: ZeroTrustEvent = {
      eventId: uuidv4(),
      eventType: effect === 'DENY' ? ZeroTrustEventType.ACCESS_DENIED :
                 effect === 'CHALLENGE' ? ZeroTrustEventType.CHALLENGE_REQUIRED :
                 ZeroTrustEventType.LOGIN_SUCCESS,
      timestamp: new Date(),
      context,
      details: { evaluations, effect },
      impact: effect === 'ALLOW' ? 'POSITIVE' : 'NEGATIVE',
      trustScoreChange: this.calculateTrustScoreImpact(effect, evaluations),
    };

    await this.eventEmitter.emitAsync('zero-trust.evaluation', event);
  }
}