/**
 * Zero-Trust Interceptor
 * Enterprise Pattern
 *
 * NestJS interceptor for Zero-Trust request/response processing
 * Implements continuous verification and trust score updates
 */

import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
  Inject,
} from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { Request, Response } from 'express';
import { Observable } from 'rxjs';
import { map, tap } from 'rxjs/operators';

import { ZeroTrustService } from '../services/zero-trust.service';
import { ZeroTrustConfig } from '../types/zero-trust.types';


export interface ZeroTrustRequestInfo {
  sessionId: string;
  userId: string;
  trustScore: number;
  riskLevel: string;
  decision: any;
}

@Injectable()
export class ZeroTrustInterceptor implements NestInterceptor {
  private readonly logger = new Logger(ZeroTrustInterceptor.name);

  constructor(
    @Inject('ZERO_TRUST_CONFIG') private readonly config: ZeroTrustConfig,
    private readonly zeroTrustService: ZeroTrustService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    if (!this.config.enabled) {
      return next.handle();
    }

    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();
    const startTime = Date.now();

    // Extract Zero-Trust info from request (set by guard)
    const zeroTrustInfo = (request as any).zeroTrust as ZeroTrustRequestInfo;

    if (!zeroTrustInfo) {
      // No Zero-Trust info, proceed normally
      return next.handle();
    }

    // Add Zero-Trust headers to response
    this.addZeroTrustHeaders(response, zeroTrustInfo);

    return next.handle().pipe(
      tap(async () => {
        const duration = Date.now() - startTime;

        // Log request with Zero-Trust context
        this.logger.debug(
          `Request processed: ${request.method} ${request.path} - ` +
          `Session: ${zeroTrustInfo.sessionId}, Trust Score: ${zeroTrustInfo.trustScore}, ` +
          `Duration: ${duration}ms`,
        );

        // Update trust score based on successful request
        await this.updateTrustScoreOnSuccess(zeroTrustInfo.sessionId, duration);

        // Emit request completed event
        await this.emitRequestCompletedEvent(zeroTrustInfo, request, duration);
      }),
      map((data) => {
        // Add Zero-Trust metadata to response if configured
        if (this.config.adaptiveAuthenticationEnabled) {
          return this.enhanceResponseWithZeroTrustData(data, zeroTrustInfo);
        }
        return data;
      }),
    );
  }

  /**
   * Add Zero-Trust headers to response
   */
  private addZeroTrustHeaders(response: Response, info: ZeroTrustRequestInfo): void {
    response.setHeader('X-Zero-Trust-Session', info.sessionId);
    response.setHeader('X-Zero-Trust-Score', info.trustScore.toString());
    response.setHeader('X-Zero-Trust-Risk', info.riskLevel);

    // Add security headers
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('X-Frame-Options', 'DENY');
    response.setHeader('X-XSS-Protection', '1; mode=block');
    response.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

    // Add CSP header for enhanced security
    response.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
    );
  }

  /**
   * Update trust score on successful request
   */
  private async updateTrustScoreOnSuccess(sessionId: string, duration: number): Promise<void> {
    const sessionInfo = this.zeroTrustService.getSessionInfo(sessionId);

    if (sessionInfo) {
      // Successful requests increase trust slightly
      let trustScoreChange = 1;

      // Fast responses indicate legitimate usage
      if (duration < 100) {
        trustScoreChange += 1;
      }

      // Update trust score (handled internally by service)
      await this.eventEmitter.emitAsync('zero-trust.request-success', {
        sessionId,
        trustScoreChange,
        duration,
      });
    }
  }

  /**
   * Enhance response with Zero-Trust data
   */
  private enhanceResponseWithZeroTrustData(data: any, info: ZeroTrustRequestInfo): any {
    // If response is an object, add Zero-Trust metadata
    if (typeof data === 'object' && data !== null && !Array.isArray(data)) {
      return {
        ...data,
        _zeroTrust: {
          sessionId: info.sessionId,
          trustScore: info.trustScore,
          riskLevel: info.riskLevel,
          timestamp: new Date(),
        },
      };
    }

    return data;
  }

  /**
   * Emit request completed event
   */
  private async emitRequestCompletedEvent(
    info: ZeroTrustRequestInfo,
    request: Request,
    duration: number,
  ): Promise<void> {
    await this.eventEmitter.emitAsync('zero-trust.request-completed', {
      sessionId: info.sessionId,
      userId: info.userId,
      trustScore: info.trustScore,
      riskLevel: info.riskLevel,
      request: {
        method: request.method,
        path: request.path,
        ip: request.ip,
        userAgent: request.headers['user-agent'],
      },
      duration,
      timestamp: new Date(),
    });
  }
}