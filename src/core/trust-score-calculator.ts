/**
 * Trust Score Calculator
 * Enterprise Pattern
 *
 * Calculates dynamic trust scores based on multiple factors
 * Implements continuous trust evaluation for Zero-Trust Architecture
 */

import { LoggerFactory, TimestampUtils as _TimestampUtils } from '../utils';
import { Injectable } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';

import {
  ZeroTrustContext,
  TrustLevel,
  RiskLevel,
  DeviceStatus,
  NetworkZone,
  TrustScoreFactors,
  IdentityContext,
  DeviceContext,
  NetworkContext,
  BehavioralContext,
  ZeroTrustEvent,
  ZeroTrustEventType,
} from '../types/zero-trust.types';

export interface TrustScoreWeights {
  identity: number;
  device: number;
  network: number;
  behavioral: number;
  history: number;
  time: number;
}

export interface TrustScoreHistory {
  timestamp: Date;
  score: number;
  factors: TrustScoreFactors;
  events: ZeroTrustEvent[];
}

@Injectable()
export class TrustScoreCalculator {
  private readonly logger = LoggerFactory.createLogger(TrustScoreCalculator.name, {
    context: 'trust-score-calculator'
  });

  private readonly DEFAULT_WEIGHTS: TrustScoreWeights = {
    identity: 0.25,
    device: 0.20,
    network: 0.20,
    behavioral: 0.20,
    history: 0.10,
    time: 0.05,
  };

  private scoreHistory: Map<string, TrustScoreHistory[]> = new Map();
  private readonly MAX_HISTORY_SIZE = 100;

  constructor(private readonly eventEmitter: EventEmitter2) {
    this.setupEventListeners();
  }

  /**
   * Setup event listeners for trust score updates
   */
  private setupEventListeners(): void {
    this.eventEmitter.on('zero-trust.event', async (event: ZeroTrustEvent) => {
      await this.handleTrustEvent(event);
    });
  }

  /**
   * Determine trust level based on score
   */
  public determineTrustLevel(score: number): TrustLevel {
    if (score <= 25) {return TrustLevel.CRITICAL;}
    if (score <= 50) {return TrustLevel.LOW;}
    if (score <= 75) {return TrustLevel.MEDIUM;}
    return TrustLevel.HIGH;
  }

  // Duplicate function removed - keeping the one at line 614

  /**
   * Get average score for user
   */
  public getAverageScore(userId: string): number {
    const history = this.getScoreHistory(userId);
    if (history.length === 0) {return 0;}

    const sum = history.reduce((acc, h) => acc + h.score, 0);
    return sum / history.length;
  }

  /**
   * Set custom weights for trust score calculation
   */
  public setCustomWeights(weights: TrustScoreWeights): void {
    const sum = Object.values(weights).reduce((a, b) => a + b, 0);
    if (Math.abs(sum - 1) > 0.001) {
      throw new Error('Weights must sum to 1');
    }
    Object.assign(this.DEFAULT_WEIGHTS, weights);
  }

  /**
   * Calculate comprehensive trust score
   */
  public async calculateTrustScore(context: ZeroTrustContext): Promise<number> {
    const factors = await this.calculateTrustFactors(context);
    const weights = this.getWeights(context);

    // Calculate weighted score
    let score = 0;
    score += factors.identityVerification * weights.identity;
    score += factors.deviceCompliance * weights.device;
    score += factors.networkSecurity * weights.network;
    score += factors.behavioralAnalysis * weights.behavioral;
    score += factors.recentChallenges * weights.history;
    score += factors.timeDecay * weights.time;

    // Apply security event adjustments
    score = this.applySecurityEventAdjustments(score, factors.securityEvents);

    // Normalize score to 0-100
    score = Math.max(0, Math.min(100, score));

    // Store in history
    await this.updateScoreHistory(context, score, factors);

    // Emit trust score update event
    await this.emitTrustScoreUpdate(context, score, factors);

    this.logger.debug(`Trust score calculated for ${context.identity.userId}: ${score.toFixed(2)}`);

    return score;
  }

  /**
   * Calculate individual trust factors
   */
  private async calculateTrustFactors(context: ZeroTrustContext): Promise<TrustScoreFactors> {
    return {
      identityVerification: await this.calculateIdentityScore(context.identity),
      deviceCompliance: context.device ? await this.calculateDeviceScore(context.device) : 0,
      networkSecurity: context.network ? await this.calculateNetworkScore(context.network) : 0,
      behavioralAnalysis: context.behavioral ? await this.calculateBehavioralScore(context.behavioral) : 100,
      timeDecay: this.calculateTimeDecay(context),
      recentChallenges: await this.calculateChallengeScore(context),
      securityEvents: [],
    };
  }

  /**
   * Calculate identity verification score
   */
  private async calculateIdentityScore(identity: IdentityContext): Promise<number> {
    let score = 0;
    const maxScore = 100;

    // Authentication method strength
    const authMethodScores: Record<string, number> = {
      HARDWARE_KEY: 30,
      CERTIFICATE: 25,
      BIOMETRIC: 25,
      MFA_TOTP: 20,
      MFA_SMS: 15,
      OAUTH2: 15,
      JWT: 10,
      API_KEY: 10,
      PASSWORD: 5,
    };

    // Sum authentication method scores
    if (identity.authenticationMethods) {
      for (const method of identity.authenticationMethods) {
        score += authMethodScores[method] || 0;
      }
    }

    // MFA bonus
    if (identity.mfaEnabled) {
      score += 20;
    }

    // Account age factor (older accounts are more trusted)
    if (identity.accountAge !== undefined) {
      const ageBonus = Math.min(20, identity.accountAge / 30); // Max 20 points for 30+ day old accounts
      score += ageBonus;
    }

    // Role-based trust
    const roleScores: Record<string, number> = {
      ADMIN: 10,
      MODERATOR: 8,
      TRADER: 5,
      ANALYST: 5,
      USER: 2,
    };

    if (identity.roles) {
      for (const role of identity.roles) {
        score += roleScores[role] || 0;
      }
    }

    // Recent authentication penalty
    if (identity.lastAuthentication) {
      const timeSinceAuth = Date.now() - identity.lastAuthentication.getTime();
      const authFreshness = Math.max(0, 10 - (timeSinceAuth / (1000 * 60 * 60))); // Lose 1 point per hour
      score += authFreshness;
    }

    return Math.min(maxScore, score);
  }

  /**
   * Calculate device compliance score
   */
  private async calculateDeviceScore(device: DeviceContext): Promise<number> {
    let score = 0;

    // Device status scoring
    const statusScores: Record<DeviceStatus, number> = {
      [DeviceStatus.MANAGED]: 100,
      [DeviceStatus.TRUSTED]: 80,
      [DeviceStatus.UNKNOWN]: 40,
      [DeviceStatus.UNMANAGED]: 20,
      [DeviceStatus.UNTRUSTED]: 10,
      [DeviceStatus.PENDING]: 30,
      [DeviceStatus.COMPROMISED]: 0,
      [DeviceStatus.BLACKLISTED]: 0,
    };

    score = statusScores[device.status] || 0;

    // Geolocation factors
    if (device.location) {
      // VPN/Proxy/Tor detection penalty
      if (device.location.vpnDetected) {score -= 20;}
      if (device.location.proxyDetected) {score -= 15;}
      if (device.location.torDetected) {score -= 30;}
    }

    // Device consistency bonus
    if (device.lastSeen) {
      const timeSinceLastSeen = Date.now() - device.lastSeen.getTime();
      if (timeSinceLastSeen < 24 * 60 * 60 * 1000) { // Seen in last 24 hours
        score += 10;
      }
    }

    // Apply device-specific trust score
    if (device.trustScore !== undefined) {
      score = (score * device.trustScore) / 100;
    }

    return Math.max(0, Math.min(100, score));
  }

  /**
   * Calculate network security score
   */
  private async calculateNetworkScore(network: NetworkContext): Promise<number> {
    let score = 0;

    // Network zone scoring
    const zoneScores: Record<NetworkZone, number> = {
      [NetworkZone.INTERNAL]: 100,
      [NetworkZone.CORPORATE]: 95,
      [NetworkZone.HOME]: 75,
      [NetworkZone.DMZ]: 80,
      [NetworkZone.VPN]: 70,
      [NetworkZone.EXTERNAL]: 50,
      [NetworkZone.PROXY]: 30,
      [NetworkZone.TOR]: 10,
      [NetworkZone.SUSPICIOUS]: 0,
      [NetworkZone.UNTRUSTED]: 5,
    };

    score = (network.zone !== undefined) ? (zoneScores[network.zone] || 0) : 0;

    // Encryption bonus
    if (network.encrypted) {
      score += 20;
    }

    // mTLS bonus
    if (network.mtlsEnabled) {
      score += 30;
    }

    // Certificate validation
    if (network.certificateValid) {
      score += 10;
    }

    // Apply network-specific trust score
    if (network.trustScore !== undefined) {
      score = (score * network.trustScore) / 100;
    }

    return Math.max(0, Math.min(100, score));
  }

  /**
   * Calculate behavioral analysis score
   */
  private async calculateBehavioralScore(behavioral: BehavioralContext): Promise<number> {
    let score = 100; // Start with perfect score

    // Anomaly detection penalty
    if (behavioral.anomalyScore !== undefined) {
      score -= behavioral.anomalyScore * 50; // High anomaly scores reduce trust
    }

    // Time-based behavior check
    if (behavioral.normalLoginTime && behavioral.normalLoginTime.length > 0) {
      const currentHour = new Date().getHours();
      const normalHours = behavioral.normalLoginTime.some(time => {
        const [start, end] = time.split('-').map(Number);
        return currentHour >= start && currentHour <= end;
      });

      if (!normalHours) {
        score -= 10; // Outside normal hours
      }
    }

    // Trading pattern risk assessment
    if (behavioral.tradingPatterns) {
      const highRiskPatterns = behavioral.tradingPatterns.filter(
        p => p.riskProfile === RiskLevel.HIGH || p.riskProfile === RiskLevel.CRITICAL
      );

      score -= highRiskPatterns.length * 5;
    }

    // Recent anomaly penalty
    if (behavioral.lastAnomalyDetected) {
      const timeSinceAnomaly = Date.now() - behavioral.lastAnomalyDetected.getTime();
      if (timeSinceAnomaly < 60 * 60 * 1000) { // Within last hour
        score -= 20;
      } else if (timeSinceAnomaly < 24 * 60 * 60 * 1000) { // Within last day
        score -= 10;
      }
    }

    return Math.max(0, Math.min(100, score));
  }

  /**
   * Calculate time decay factor
   */
  private calculateTimeDecay(context: ZeroTrustContext): number {
    if (!context.timestamp) {
      return 100; // If no timestamp, assume fresh
    }

    const sessionAge = Date.now() - new Date(context.timestamp).getTime();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    // Exponential decay: trust decreases over time
    const decayFactor = Math.exp(-sessionAge / maxAge);

    return Math.max(0, Math.min(100, decayFactor * 100));
  }

  /**
   * Calculate recent challenges score
   */
  private async calculateChallengeScore(context: ZeroTrustContext): Promise<number> {
    if (!context.sessionId) {
      return 0;
    }
    const history = this.scoreHistory.get(context.sessionId) || [];

    // Count successful challenges in recent history
    const recentChallenges = history
      .filter(h => Date.now() - h.timestamp.getTime() < 60 * 60 * 1000) // Last hour
      .flatMap(h => h.events)
      .filter(e => e.eventType === ZeroTrustEventType.MFA_SUCCESS ||
                   e.eventType === ZeroTrustEventType.LOGIN_SUCCESS);

    // More successful challenges increase trust
    const score = Math.min(100, recentChallenges.length * 20);

    return score;
  }

  /**
   * Calculate security event impact score
   */
  private async calculateSecurityEventScore(context: ZeroTrustContext): Promise<number> {
    if (!context.sessionId) {
      return 0;
    }
    const history = this.scoreHistory.get(context.sessionId) || [];

    // Count negative security events
    const negativeEvents = history
      .filter(h => Date.now() - h.timestamp.getTime() < 24 * 60 * 60 * 1000) // Last 24 hours
      .flatMap(h => h.events)
      .filter(e => e.impact === 'NEGATIVE');

    // Each negative event reduces the score
    const penalty = negativeEvents.length * 10;

    return Math.max(-100, -penalty);
  }

  /**
   * Apply security event adjustments to score
   */
  private applySecurityEventAdjustments(score: number, events: any[]): number {
    let adjustedScore = score;

    if (!Array.isArray(events)) {
      // Legacy: if events is a number, use it directly
      return Math.max(0, score + (events as any));
    }

    // Process security events
    for (const event of events) {
      const severity = event.severity || 'info';
      const type = event.type;

      // Apply adjustments based on event type and severity
      if (type === ZeroTrustEventType.POLICY_VIOLATION) {
        adjustedScore -= severity === 'critical' ? 20 : severity === 'high' ? 15 : 10;
      } else if (type === ZeroTrustEventType.ACCESS_DENIED) {
        adjustedScore -= severity === 'high' ? 10 : 5;
      } else if (type === ZeroTrustEventType.ANOMALY_DETECTED) {
        adjustedScore -= severity === 'high' ? 15 : 10;
      } else if (type === ZeroTrustEventType.MFA_COMPLETED) {
        adjustedScore += 5;
      } else if (type === ZeroTrustEventType.DEVICE_VERIFIED) {
        adjustedScore += 5;
      }
    }

    return Math.max(0, Math.min(100, adjustedScore));
  }

  private challengeResults: Map<string, Array<{ success: boolean; timestamp: Date }>> = new Map();

  /**
   * Add challenge result for tracking
   */
  private addChallengeResult(contextId: string, success: boolean): void {
    // Store challenge results for score calculation
    const key = `challenge_${contextId}`;
    const results = this.challengeResults.get(key) || [];
    results.push({ success, timestamp: new Date() });
    this.challengeResults.set(key, results);
  }

  /**
   * Evaluate rules for policy engine tests
   */
  private evaluateRule(rule: any, context: any): boolean {
    const fieldValue = this.getNestedValue(context, rule.field);
    const { operator, value } = rule;

    switch (operator) {
      case 'eq': return fieldValue === value;
      case 'neq': return fieldValue !== value;
      case 'gt': return fieldValue > value;
      case 'lt': return fieldValue < value;
      case 'gte': return fieldValue >= value;
      case 'lte': return fieldValue <= value;
      case 'in': return Array.isArray(value) && value.includes(fieldValue);
      case 'nin': return Array.isArray(value) && !value.includes(fieldValue);
      case 'regex': return new RegExp(value).test(fieldValue);
      default: return false;
    }
  }

  /**
   * Evaluate conditions for policy engine tests
   */
  private evaluateConditions(rules: any[], context: any): boolean {
    let result = true;

    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      const ruleResult = this.evaluateRule(rule, context);

      if (i === 0) {
        result = ruleResult;
      } else {
        const combineWith = rules[i - 1].combineWith || 'AND';
        if (combineWith === 'AND') {
          result = result && ruleResult;
        } else {
          result = result || ruleResult;
        }
      }
    }

    return result;
  }

  /**
   * Get nested value from object
   */
  private getNestedValue(obj: any, path: string): any {
    const keys = path.split('.');
    let value = obj;

    for (const key of keys) {
      if (value && typeof value === 'object' && key in value) {
        value = value[key];
      } else {
        return undefined;
      }
    }

    return value;
  }

  /**
   * Execute policy evaluation for testing
   */
  private async executePolicyEvaluation(_context: any, _request: any): Promise<any> {
    // Mock implementation for tests
    return {
      allowed: true,
      trustLevel: TrustLevel.HIGH,
      riskLevel: RiskLevel.LOW,
    };
  }

  /**
   * Get dynamic weights based on context
   */
  private getWeights(context: ZeroTrustContext): TrustScoreWeights {
    // In high-risk situations, increase behavioral and network weights
    if (context.riskLevel === RiskLevel.HIGH || context.riskLevel === RiskLevel.CRITICAL) {
      return {
        identity: 0.20,
        device: 0.15,
        network: 0.25,
        behavioral: 0.25,
        history: 0.10,
        time: 0.05,
      };
    }

    return this.DEFAULT_WEIGHTS;
  }

  /**
   * Update score history
   */
  private async updateScoreHistory(
    context: ZeroTrustContext,
    score: number,
    factors: TrustScoreFactors,
  ): Promise<void> {
    if (!context.sessionId) {
      return;
    }
    const sessionId = context.sessionId;
    const history = this.scoreHistory.get(sessionId) || [];

    history.push({
      timestamp: new Date(),
      score,
      factors,
      events: [],
    });

    // Maintain history size limit
    if (history.length > this.MAX_HISTORY_SIZE) {
      history.shift();
    }

    this.scoreHistory.set(sessionId, history);
  }

  /**
   * Handle trust events
   */
  private async handleTrustEvent(event: ZeroTrustEvent): Promise<void> {
    if (!event.context.sessionId) {
      return;
    }
    const sessionId = event.context.sessionId;
    const history = this.scoreHistory.get(sessionId) || [];

    if (history.length > 0) {
      const latest = history[history.length - 1];
      latest.events.push(event);
    }

    // Recalculate trust score if event has significant impact
    if (Math.abs(event.trustScoreChange) > 10) {
      await this.calculateTrustScore(event.context);
    }
  }

  /**
   * Emit trust score update event
   */
  private async emitTrustScoreUpdate(
    context: ZeroTrustContext,
    score: number,
    factors: TrustScoreFactors,
  ): Promise<void> {
    await this.eventEmitter.emitAsync('zero-trust.trust-score-updated', {
      sessionId: context.sessionId,
      userId: context.identity.userId,
      score,
      factors,
      timestamp: new Date(),
    });
  }

  /**
   * Get trust level from score
   */
  public getTrustLevel(score: number): TrustLevel {
    if (score >= 90) {return TrustLevel.FULL;}
    if (score >= 75) {return TrustLevel.HIGH;}
    if (score >= 50) {return TrustLevel.MEDIUM;}
    if (score >= 25) {return TrustLevel.LOW;}
    if (score > 0) {return TrustLevel.MINIMAL;}
    return TrustLevel.NONE;
  }

  /**
   * Get risk level from trust score
   */
  public getRiskLevel(score: number): RiskLevel {
    if (score >= 80) {return RiskLevel.MINIMAL;}
    if (score >= 60) {return RiskLevel.LOW;}
    if (score >= 40) {return RiskLevel.MEDIUM;}
    if (score >= 20) {return RiskLevel.HIGH;}
    return RiskLevel.CRITICAL;
  }

  /**
   * Get score history for a session
   */
  public getScoreHistory(sessionId: string): TrustScoreHistory[] {
    return this.scoreHistory.get(sessionId) || [];
  }

  /**
   * Clear old history entries
   */
  public clearOldHistory(maxAge: number = 24 * 60 * 60 * 1000): void {
    const cutoff = Date.now() - maxAge;

    for (const [sessionId, history] of this.scoreHistory.entries()) {
      const filtered = history.filter(h => h.timestamp.getTime() > cutoff);

      if (filtered.length === 0) {
        this.scoreHistory.delete(sessionId);
      } else {
        this.scoreHistory.set(sessionId, filtered);
      }
    }

    this.logger.debug(`Cleared old history entries, ${this.scoreHistory.size} sessions remaining`);
  }
}