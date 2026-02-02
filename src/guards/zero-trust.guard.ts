/**
 * Zero-Trust Guard
 * Enterprise Pattern
 *
 * NestJS guard implementing Zero-Trust access control
 * Enforces "Never Trust, Always Verify" principle
 */

import { LoggerFactory, TimestampUtils as _TimestampUtils } from '../utils';
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  ForbiddenException,
  Inject,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';

import { ZeroTrustService } from '../services/zero-trust.service';
import { ZeroTrustConfig, AccessDecision } from '../types/zero-trust.types';

export const ZERO_TRUST_METADATA = 'zero-trust';
export const SKIP_ZERO_TRUST = 'skip-zero-trust';
export const RESOURCE_METADATA = 'resource';
export const ACTION_METADATA = 'action';

export interface ZeroTrustOptions {
  resource?: string;
  action?: string;
  requireMfa?: boolean;
  minimumTrustScore?: number;
  skipVerification?: boolean;
}

@Injectable()
export class ZeroTrustGuard implements CanActivate {
  private readonly logger = LoggerFactory.createLogger(ZeroTrustGuard.name, {
    context: 'zero-trust-guard'
  });

  constructor(
    @Inject('ZERO_TRUST_CONFIG') private readonly config: ZeroTrustConfig,
    private readonly reflector: Reflector,
    private readonly zeroTrustService: ZeroTrustService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Check if Zero-Trust is enabled
    if (!this.config.enabled) {
      return true;
    }

    // Check if Zero-Trust should be skipped for this route
    const skipZeroTrust = this.reflector.getAllAndOverride<boolean>(SKIP_ZERO_TRUST, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (skipZeroTrust) {
      return true;
    }

    // Get Zero-Trust options from metadata
    const options = this.reflector.getAllAndOverride<ZeroTrustOptions>(ZERO_TRUST_METADATA, [
      context.getHandler(),
      context.getClass(),
    ]) || {};

    // Skip verification if explicitly set
    if (options.skipVerification) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();

    // Extract session information
    const sessionId = this.extractSessionId(request);
    if (!sessionId) {
      throw new UnauthorizedException('No session found');
    }

    // Get session info
    const sessionInfo = this.zeroTrustService.getSessionInfo(sessionId);
    if (!sessionInfo) {
      throw new UnauthorizedException('Invalid session');
    }

    // Check if session is active
    if (!sessionInfo.active) {
      throw new UnauthorizedException('Session is not active');
    }

    // Check trust score requirement
    if (options.minimumTrustScore !== undefined) {
      if (sessionInfo.trustScore < options.minimumTrustScore) {
        throw new ForbiddenException(
          `Insufficient trust score. Required: ${options.minimumTrustScore}, Current: ${sessionInfo.trustScore}`,
        );
      }
    }

    // Determine resource and action
    const resource = options.resource || this.extractResource(request);
    const action = options.action || this.extractAction(request);

    // Extract additional metadata
    const metadata = this.extractMetadata(request);

    try {
      // Perform Zero-Trust authorization
      const decision: AccessDecision = await this.zeroTrustService.authorize(
        sessionId,
        resource,
        action,
        metadata,
      );

      if (!decision.allowed) {
        // Handle challenges if present
        if (decision.challenges && decision.challenges.length > 0) {
          const response = context.switchToHttp().getResponse();
          response.status(401);
          response.json({
            error: 'Additional verification required',
            challenges: decision.challenges,
            requiredActions: decision.requiredActions,
          });
          return false;
        }

        // Access denied
        this.logger.warn(
          `Access denied for session ${sessionId}: ${decision.reason}`,
        );
        throw new ForbiddenException(decision.reason);
      }

      // Check if strict mode is enabled
      if (this.config.strictMode) {
        // In strict mode, require continuous verification
        if (!sessionInfo.trustScore || sessionInfo.trustScore < this.config.trustScoreThreshold) {
          throw new ForbiddenException('Trust score below threshold in strict mode');
        }

        // Check session age
        const sessionAge = Date.now() - new Date(sessionInfo.createdAt).getTime();
        if (sessionAge > this.config.maxSessionDuration) {
          throw new UnauthorizedException('Session expired in strict mode');
        }
      }

      // Attach session info to request for downstream use
      (request as any).zeroTrust = {
        sessionId,
        userId: sessionInfo.userId,
        trustScore: sessionInfo.trustScore,
        riskLevel: sessionInfo.riskLevel,
        decision,
      };

      return true;
    } catch (error) {
      if (error instanceof UnauthorizedException || error instanceof ForbiddenException) {
        throw error;
      }

      this.logger.error(`Zero-Trust authorization failed: ${error instanceof Error ? error.message : String(error)}`, error instanceof Error ? error.stack : undefined);
      throw new ForbiddenException('Authorization failed');
    }
  }

  /**
   * Extract session ID from request
   */
  private extractSessionId(request: Request): string | null {
    // Check Authorization header
    const authHeader = request.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      // Parse JWT to get session ID (simplified)
      try {
        const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
        return payload.sessionId;
      } catch {
        return null;
      }
    }

    // Check session cookie
    const sessionCookie = request.cookies?.['zero-trust-session'];
    if (sessionCookie) {
      return sessionCookie;
    }

    // Check custom header
    const customHeader = request.headers['x-session-id'] as string;
    if (customHeader) {
      return customHeader;
    }

    return null;
  }

  /**
   * Extract resource from request
   */
  private extractResource(request: Request): string {
    // Create resource identifier from route
    const method = request.method;
    const path = request.route?.path || request.path;
    return `${method}:${path}`;
  }

  /**
   * Extract action from request
   */
  private extractAction(request: Request): string {
    // Map HTTP method to action
    const methodActions: Record<string, string> = {
      GET: 'read',
      POST: 'create',
      PUT: 'update',
      PATCH: 'update',
      DELETE: 'delete',
    };

    return methodActions[request.method] || 'access';
  }

  /**
   * Extract metadata from request
   */
  private extractMetadata(request: Request): Record<string, any> {
    return {
      ip: request.ip,
      userAgent: request.headers['user-agent'],
      referer: request.headers.referer,
      origin: request.headers.origin,
      method: request.method,
      path: request.path,
      query: request.query,
      timestamp: new Date(),
    };
  }
}