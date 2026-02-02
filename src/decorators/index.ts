/**
 * Zero-Trust Decorators
 * Enterprise Pattern
 *
 * Custom decorators for Zero-Trust Security implementation
 */

import { SetMetadata, applyDecorators, UseGuards } from '@nestjs/common';

import {
  ZERO_TRUST_METADATA,
  SKIP_ZERO_TRUST,
  RESOURCE_METADATA,
  ACTION_METADATA,
  ZeroTrustOptions,
  ZeroTrustGuard,
} from '../guards/zero-trust.guard';

/**
 * Apply Zero-Trust security to a route or controller
 */
export function ZeroTrust(options?: ZeroTrustOptions) {
  return applyDecorators(
    SetMetadata(ZERO_TRUST_METADATA, options || {}),
    UseGuards(ZeroTrustGuard),
  );
}

/**
 * Skip Zero-Trust verification for a route
 */
export function SkipZeroTrust() {
  return SetMetadata(SKIP_ZERO_TRUST, true);
}

/**
 * Set resource name for Zero-Trust authorization
 */
export function Resource(resource: string) {
  return SetMetadata(RESOURCE_METADATA, resource);
}

/**
 * Set action name for Zero-Trust authorization
 */
export function Action(action: string) {
  return SetMetadata(ACTION_METADATA, action);
}

/**
 * Require minimum trust score for access
 */
export function RequireTrustScore(score: number) {
  return ZeroTrust({ minimumTrustScore: score });
}

/**
 * Require MFA for access
 */
export function RequireMFA() {
  return ZeroTrust({ requireMfa: true });
}

/**
 * Apply Zero-Trust with specific resource and action
 */
export function SecureEndpoint(resource: string, action: string, minimumTrustScore?: number) {
  return applyDecorators(
    ZeroTrust({
      resource,
      action,
      minimumTrustScore,
    }),
  );
}

/**
 * Mark endpoint as requiring continuous verification
 */
export function ContinuousVerification() {
  return SetMetadata('continuous-verification', true);
}

/**
 * Apply strict Zero-Trust mode
 */
export function StrictZeroTrust() {
  return applyDecorators(
    ZeroTrust({
      minimumTrustScore: 80,
      requireMfa: true,
    }),
  );
}