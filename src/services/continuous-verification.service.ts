/**
 * Continuous Verification Service
 * Enterprise Pattern
 *
 * Implements continuous authentication and verification
 * Core component of Zero-Trust Architecture
 */

import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { Interval } from '@nestjs/schedule';
import Redis from 'ioredis';
import { v4 as uuidv4 } from 'uuid';

import { TrustScoreCalculator } from '../core/trust-score-calculator';
import {
  ZeroTrustContext,
  ZeroTrustEvent,
  ZeroTrustEventType,
  RiskLevel,
  DeviceContext,
  BehavioralContext,
  RequiredAction,
  SecurityChallenge,
} from '../types/zero-trust.types';

export interface VerificationSchedule {
  sessionId: string;
  nextVerification: Date;
  verificationInterval: number;
  failedAttempts: number;
  lastVerification: Date;
  riskLevel: RiskLevel;
}

export interface VerificationResult {
  success: boolean;
  trustScoreChange: number;
  newRiskLevel: RiskLevel;
  nextVerification: Date;
  challenges?: SecurityChallenge[];
  requiredActions?: RequiredAction[];
}

export interface BehavioralAnomaly {
  type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  detectedAt: Date;
  confidence: number;
}

@Injectable()
export class ContinuousVerificationService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(ContinuousVerificationService.name);
  private redis!: Redis;
  private verificationSchedules: Map<string, VerificationSchedule> = new Map();
  private activeSessions: Map<string, ZeroTrustContext> = new Map();
  private behavioralBaselines: Map<string, BehavioralContext> = new Map();

  private readonly VERIFICATION_INTERVALS = {
    [RiskLevel.MINIMAL]: 3600000,    // 1 hour
    [RiskLevel.LOW]: 1800000,         // 30 minutes
    [RiskLevel.MODERATE]: 900000,     // 15 minutes (alias for MEDIUM)
    [RiskLevel.MEDIUM]: 900000,       // 15 minutes
    [RiskLevel.HIGH]: 300000,         // 5 minutes
    [RiskLevel.CRITICAL]: 60000,      // 1 minute
  };

  private readonly MAX_FAILED_VERIFICATIONS = 3;
  private verificationTimer: NodeJS.Timer | null = null;

  constructor(
    private readonly eventEmitter: EventEmitter2,
    private readonly trustScoreCalculator: TrustScoreCalculator,
  ) {}

  async onModuleInit() {
    this.redis = new Redis({
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD,
      db: 2, // Use separate DB for Zero-Trust
      keyPrefix: 'zt:verification:',
    });

    await this.loadActiveSessionsFromRedis();
    this.startVerificationScheduler();
    this.setupEventListeners();

    this.logger.log('Continuous Verification Service initialized');
  }

  async onModuleDestroy() {
    if (this.verificationTimer) {
      clearInterval(this.verificationTimer as any);
    }

    await this.saveActiveSessionsToRedis();
    await this.redis.quit();

    this.logger.log('Continuous Verification Service destroyed');
  }

  /**
   * Setup event listeners
   */
  private setupEventListeners(): void {
    // Listen for new sessions
    this.eventEmitter.on('session.created', async (context: ZeroTrustContext) => {
      await this.startContinuousVerification(context);
    });

    // Listen for session termination
    this.eventEmitter.on('session.terminated', async (sessionId: string) => {
      await this.stopContinuousVerification(sessionId);
    });

    // Listen for security events
    this.eventEmitter.on('zero-trust.event', async (event: ZeroTrustEvent) => {
      await this.handleSecurityEvent(event);
    });
  }

  /**
   * Start continuous verification for a session
   */
  public async startContinuousVerification(context: ZeroTrustContext): Promise<void> {
    if (!context.sessionId) {
      throw new Error('Session ID is required for continuous verification');
    }

    const sessionId = context.sessionId;

    // Store active session
    this.activeSessions.set(sessionId, context);

    // Calculate initial verification interval based on risk
    const riskLevel = this.trustScoreCalculator.getRiskLevel(context.trustScore || 50);
    const interval = this.VERIFICATION_INTERVALS[riskLevel];

    // Create verification schedule
    const schedule: VerificationSchedule = {
      sessionId,
      nextVerification: new Date(Date.now() + interval),
      verificationInterval: interval,
      failedAttempts: 0,
      lastVerification: new Date(),
      riskLevel,
    };

    this.verificationSchedules.set(sessionId, schedule);

    // Store behavioral baseline (if available)
    if (context.behavioral) {
      this.behavioralBaselines.set(sessionId, context.behavioral);
    }

    // Save to Redis for persistence
    await this.saveSessionToRedis(sessionId, context, schedule);

    this.logger.debug(`Started continuous verification for session ${sessionId} with interval ${interval}ms`);

    // Emit verification started event
    await this.eventEmitter.emitAsync('zero-trust.verification.started', {
      sessionId,
      riskLevel,
      interval,
    });
  }

  /**
   * Stop continuous verification for a session
   */
  public async stopContinuousVerification(sessionId: string): Promise<void> {
    this.activeSessions.delete(sessionId);
    this.verificationSchedules.delete(sessionId);
    this.behavioralBaselines.delete(sessionId);

    await this.removeSessionFromRedis(sessionId);

    this.logger.debug(`Stopped continuous verification for session ${sessionId}`);

    // Emit verification stopped event
    await this.eventEmitter.emitAsync('zero-trust.verification.stopped', { sessionId });
  }

  /**
   * Perform verification for a session
   */
  public async verifySession(sessionId: string): Promise<VerificationResult> {
    const context = this.activeSessions.get(sessionId);
    const schedule = this.verificationSchedules.get(sessionId);

    if (!context || !schedule) {
      return {
        success: false,
        trustScoreChange: -20,
        newRiskLevel: RiskLevel.CRITICAL,
        nextVerification: new Date(),
      };
    }

    try {
      // Perform various verification checks
      const deviceValid = context.device ? await this.verifyDevice(context.device) : true;
      const behaviorNormal = context.behavioral ? await this.verifyBehavior(context.behavioral, sessionId) : true;
      const networkSecure = await this.verifyNetwork(context);

      // Check for anomalies
      const anomalies = await this.detectAnomalies(context, sessionId);

      // Calculate new trust score
      const newTrustScore = await this.trustScoreCalculator.calculateTrustScore(context);
      const trustScoreChange = newTrustScore - (context.trustScore || 50);

      // Update context
      context.trustScore = newTrustScore;
      context.lastVerification = new Date();

      // Determine new risk level
      const newRiskLevel = this.trustScoreCalculator.getRiskLevel(newTrustScore);

      // Prepare result
      const result: VerificationResult = {
        success: deviceValid && behaviorNormal && networkSecure && anomalies.length === 0,
        trustScoreChange,
        newRiskLevel,
        nextVerification: new Date(Date.now() + this.VERIFICATION_INTERVALS[newRiskLevel]),
      };

      // Handle failed verification
      if (!result.success) {
        schedule.failedAttempts++;

        if (schedule.failedAttempts >= this.MAX_FAILED_VERIFICATIONS) {
          // Session is compromised, terminate it
          await this.terminateSession(sessionId, 'Max verification failures reached');
        } else {
          // Require additional challenges
          result.challenges = await this.generateChallenges(context, anomalies);
          result.requiredActions = await this.generateRequiredActions(context, anomalies);
        }
      } else {
        // Reset failed attempts on success
        schedule.failedAttempts = 0;
      }

      // Update schedule
      schedule.lastVerification = new Date();
      schedule.nextVerification = result.nextVerification;
      schedule.riskLevel = newRiskLevel;
      schedule.verificationInterval = this.VERIFICATION_INTERVALS[newRiskLevel];

      // Emit verification result
      await this.emitVerificationResult(sessionId, result);

      return result;
    } catch (error) {
      this.logger.error(`Verification failed for session ${sessionId}:`, error);
      return {
        success: false,
        trustScoreChange: -30,
        newRiskLevel: RiskLevel.CRITICAL,
        nextVerification: new Date(),
      };
    }
  }

  /**
   * Verify device integrity
   */
  private async verifyDevice(device: DeviceContext): Promise<boolean> {
    // Check if device is still trusted
    if (device.status === 'COMPROMISED' || device.status === 'BLACKLISTED') {
      return false;
    }

    // Check device fingerprint hasn't changed
    const currentFingerprint = await this.calculateDeviceFingerprint(device);
    if (currentFingerprint !== device.fingerprint) {
      this.logger.warn(`Device fingerprint mismatch for device ${device.deviceId}`);
      return false;
    }

    // Check for suspicious location changes
    if (device.location) {
      if (device.location.vpnDetected || device.location.torDetected) {
        return false;
      }
    }

    return true;
  }

  /**
   * Verify behavioral patterns
   */
  private async verifyBehavior(
    current: BehavioralContext,
    sessionId: string,
  ): Promise<boolean> {
    const baseline = this.behavioralBaselines.get(sessionId);
    if (!baseline) {
      return true; // No baseline to compare
    }

    // Check for significant anomaly score increase
    if (current.anomalyScore !== undefined && baseline.anomalyScore !== undefined) {
      if (current.anomalyScore > baseline.anomalyScore * 1.5) {
        this.logger.warn(`Behavioral anomaly detected for session ${sessionId}`);
        return false;
      }
    }

    // Check for unusual trading patterns
    if (current.tradingPatterns && baseline.tradingPatterns) {
      const unusualPatterns = current.tradingPatterns.filter(pattern => {
        const baselinePattern = baseline.tradingPatterns?.find(p => p.symbol === pattern.symbol);
        if (!baselinePattern) {return true;} // New pattern

        // Check for significant deviations
        return (
          pattern.averageVolume > baselinePattern.averageVolume * 2 ||
          pattern.riskProfile !== baselinePattern.riskProfile
        );
      });

      if (unusualPatterns.length > 0) {
        this.logger.warn(`Unusual trading patterns detected for session ${sessionId}`);
        return false;
      }
    }

    return true;
  }

  /**
   * Verify network security
   */
  private async verifyNetwork(context: ZeroTrustContext): Promise<boolean> {
    const network = context.network;
    if (!network) {
      return true; // No network context to verify
    }

    // Check for suspicious network changes
    if (network.zone === 'SUSPICIOUS' || network.zone === 'TOR') {
      return false;
    }

    // Verify encryption is maintained
    if (network.encrypted === false) {
      return false;
    }

    // Check for certificate validity if applicable
    if (network.certificateValid === false) {
      return false;
    }

    return true;
  }

  /**
   * Detect anomalies in the session
   */
  private async detectAnomalies(
    context: ZeroTrustContext,
    sessionId: string,
  ): Promise<BehavioralAnomaly[]> {
    const anomalies: BehavioralAnomaly[] = [];

    // Check for impossible travel
    if (context.device && context.device.location) {
      const lastLocation = await this.getLastKnownLocation(sessionId);
      if (lastLocation) {
        const distance = this.calculateDistance(lastLocation, context.device.location);
        const timeDiff = Date.now() - lastLocation.timestamp;
        const speed = distance / (timeDiff / 3600000); // km/h

        if (speed > 1000) { // Faster than commercial flight
          anomalies.push({
            type: 'IMPOSSIBLE_TRAVEL',
            severity: 'HIGH',
            description: `Travel speed ${speed.toFixed(0)} km/h exceeds possibility`,
            detectedAt: new Date(),
            confidence: 0.95,
          });
        }
      }
    }

    // Check for concurrent sessions from different locations
    if (context.device && context.device.location) {
      const otherSessions = await this.getOtherUserSessions(context.identity.userId);
      for (const otherSession of otherSessions) {
        if (otherSession.sessionId !== sessionId && otherSession.context.device && otherSession.context.device.location) {
          const distance = this.calculateDistance(
            context.device.location,
            otherSession.context.device.location,
          );

          if (distance > 100) { // More than 100km apart
            anomalies.push({
              type: 'CONCURRENT_DISTANT_SESSIONS',
              severity: 'CRITICAL',
              description: `Concurrent sessions ${distance.toFixed(0)}km apart`,
              detectedAt: new Date(),
              confidence: 0.9,
            });
          }
        }
      }
    }

    // Check for unusual activity patterns
    const activityPattern = await this.analyzeActivityPattern(context, sessionId);
    if (activityPattern.anomalyScore > 0.8) {
      anomalies.push({
        type: 'UNUSUAL_ACTIVITY',
        severity: activityPattern.anomalyScore > 0.9 ? 'HIGH' : 'MEDIUM',
        description: activityPattern.description,
        detectedAt: new Date(),
        confidence: activityPattern.anomalyScore,
      });
    }

    return anomalies;
  }

  /**
   * Generate security challenges based on anomalies
   */
  private async generateChallenges(
    context: ZeroTrustContext,
    anomalies: BehavioralAnomaly[],
  ): Promise<SecurityChallenge[]> {
    const challenges: SecurityChallenge[] = [];

    // Determine challenge type based on risk and anomalies
    const hasHighRisk = anomalies.some(a => a.severity === 'HIGH' || a.severity === 'CRITICAL');

    if (hasHighRisk) {
      // Require strong authentication
      challenges.push({
        type: 'BIOMETRIC',
        challengeId: uuidv4(),
        expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
        attempts: 0,
        maxAttempts: 3,
      });
    }

    // Always require MFA for anomalies
    if (anomalies.length > 0) {
      challenges.push({
        type: 'MFA',
        challengeId: uuidv4(),
        expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
        attempts: 0,
        maxAttempts: 3,
      });
    }

    return challenges;
  }

  /**
   * Generate required actions based on context
   */
  private async generateRequiredActions(
    context: ZeroTrustContext,
    anomalies: BehavioralAnomaly[],
  ): Promise<RequiredAction[]> {
    const actions: RequiredAction[] = [];

    // Device verification for device anomalies
    if (anomalies.some(a => a.type === 'DEVICE_CHANGE')) {
      actions.push(RequiredAction.DEVICE_VERIFICATION);
    }

    // Location verification for travel anomalies
    if (anomalies.some(a => a.type === 'IMPOSSIBLE_TRAVEL')) {
      actions.push(RequiredAction.LOCATION_VERIFICATION);
    }

    // Re-authentication for critical anomalies
    if (anomalies.some(a => a.severity === 'CRITICAL')) {
      actions.push(RequiredAction.REAUTHENTICATE);
    }

    return actions;
  }

  /**
   * Terminate a compromised session
   */
  private async terminateSession(sessionId: string, reason: string): Promise<void> {
    this.logger.warn(`Terminating session ${sessionId}: ${reason}`);

    const context = this.activeSessions.get(sessionId);
    if (context) {
      // Emit termination event
      const event: ZeroTrustEvent = {
        eventId: uuidv4(),
        eventType: ZeroTrustEventType.ACCESS_DENIED,
        timestamp: new Date(),
        context,
        details: { reason },
        impact: 'NEGATIVE',
        trustScoreChange: -50,
      };

      await this.eventEmitter.emitAsync('zero-trust.event', event);
      await this.eventEmitter.emitAsync('session.terminated', sessionId);
    }

    await this.stopContinuousVerification(sessionId);
  }

  /**
   * Start verification scheduler
   */
  private startVerificationScheduler(): void {
    // Run every minute to check for pending verifications
    this.verificationTimer = setInterval(async () => {
      await this.processPendingVerifications();
    }, 60000); // 1 minute
  }

  /**
   * Process pending verifications
   */
  @Interval(60000)
  private async processPendingVerifications(): Promise<void> {
    const now = Date.now();

    for (const [sessionId, schedule] of this.verificationSchedules.entries()) {
      if (schedule.nextVerification.getTime() <= now) {
        this.logger.debug(`Processing verification for session ${sessionId}`);
        await this.verifySession(sessionId);
      }
    }
  }

  /**
   * Calculate device fingerprint
   */
  private async calculateDeviceFingerprint(device: DeviceContext): Promise<string> {
    const components = [
      device.deviceType,
      device.platform,
      device.browser || '',
      device.ipAddress,
    ];

    // Simple fingerprint calculation (should be more sophisticated in production)
    return Buffer.from(components.join('|')).toString('base64');
  }

  /**
   * Calculate distance between two locations
   */
  private calculateDistance(
    loc1: any,
    loc2: any,
  ): number {
    const R = 6371; // Earth radius in km
    const dLat = this.toRad(loc2.latitude - loc1.latitude);
    const dLon = this.toRad(loc2.longitude - loc1.longitude);

    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(this.toRad(loc1.latitude)) *
      Math.cos(this.toRad(loc2.latitude)) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);

    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
  }

  private toRad(deg: number): number {
    return deg * (Math.PI / 180);
  }

  /**
   * Get last known location for a session
   */
  private async getLastKnownLocation(sessionId: string): Promise<any> {
    const data = await this.redis.get(`location:${sessionId}`);
    return data ? JSON.parse(data) : null;
  }

  /**
   * Get other sessions for a user
   */
  private async getOtherUserSessions(userId: string): Promise<any[]> {
    const sessions: any[] = [];
    for (const [sessionId, context] of this.activeSessions.entries()) {
      if (context.identity.userId === userId) {
        sessions.push({ sessionId, context });
      }
    }
    return sessions;
  }

  /**
   * Analyze activity pattern
   */
  private async analyzeActivityPattern(
    context: ZeroTrustContext,
    sessionId: string,
  ): Promise<{ anomalyScore: number; description: string }> {
    // Simplified activity pattern analysis
    const baseline = this.behavioralBaselines.get(sessionId);
    if (!baseline || !context.behavioral) {
      return { anomalyScore: 0, description: 'No baseline available' };
    }

    const anomalyScore = context.behavioral.anomalyScore || 0;
    let description = 'Normal activity';

    // Check for sudden changes
    if (anomalyScore > 0.5) {
      description = 'Elevated activity detected';
    }

    if (anomalyScore > 0.8) {
      description = 'Highly unusual activity pattern detected';
    }

    return { anomalyScore, description };
  }

  /**
   * Handle security events
   */
  private async handleSecurityEvent(event: ZeroTrustEvent): Promise<void> {
    if (!event.context.sessionId) {
      return;
    }

    const schedule = this.verificationSchedules.get(event.context.sessionId);
    if (!schedule) {return;}

    // Adjust verification interval based on event
    if (event.impact === 'NEGATIVE') {
      // Increase verification frequency for negative events
      schedule.verificationInterval = Math.max(
        60000, // Minimum 1 minute
        schedule.verificationInterval * 0.5,
      );
      schedule.nextVerification = new Date(Date.now() + schedule.verificationInterval);
    }
  }

  /**
   * Emit verification result
   */
  private async emitVerificationResult(
    sessionId: string,
    result: VerificationResult,
  ): Promise<void> {
    await this.eventEmitter.emitAsync('zero-trust.verification.completed', {
      sessionId,
      result,
      timestamp: new Date(),
    });
  }

  /**
   * Save session to Redis
   */
  private async saveSessionToRedis(
    sessionId: string,
    context: ZeroTrustContext,
    schedule: VerificationSchedule,
  ): Promise<void> {
    await this.redis.setex(
      `session:${sessionId}`,
      86400, // 24 hours TTL
      JSON.stringify({ context, schedule }),
    );
  }

  /**
   * Load active sessions from Redis
   */
  private async loadActiveSessionsFromRedis(): Promise<void> {
    const keys = await this.redis.keys('session:*');

    for (const key of keys) {
      const data = await this.redis.get(key);
      if (data) {
        const { context, schedule } = JSON.parse(data);
        const sessionId = key.replace('zt:verification:session:', '');

        this.activeSessions.set(sessionId, context);
        this.verificationSchedules.set(sessionId, schedule);
      }
    }

    this.logger.log(`Loaded ${this.activeSessions.size} active sessions from Redis`);
  }

  /**
   * Save active sessions to Redis
   */
  private async saveActiveSessionsToRedis(): Promise<void> {
    for (const [sessionId, context] of this.activeSessions.entries()) {
      const schedule = this.verificationSchedules.get(sessionId);
      if (schedule) {
        await this.saveSessionToRedis(sessionId, context, schedule);
      }
    }
  }

  /**
   * Remove session from Redis
   */
  private async removeSessionFromRedis(sessionId: string): Promise<void> {
    await this.redis.del(`session:${sessionId}`);
    await this.redis.del(`location:${sessionId}`);
  }
}