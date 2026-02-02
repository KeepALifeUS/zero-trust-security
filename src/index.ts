/**
 * Zero-Trust Security Package
 * Enterprise Pattern
 *
 * Main export file for Zero-Trust Security Architecture
 */

// Module
export { ZeroTrustModule, ZeroTrustModuleOptions } from './zero-trust.module';

// Types
export * from './types/zero-trust.types';

// Core
export {
  ZeroTrustPolicyEngine,
  ZeroTrustPolicy,
  PolicyRule as PolicyConditionRule,    // Renamed to avoid conflict
  PolicyActionConfig as PolicyActionType      // Renamed to avoid conflict
} from './core/policy-engine';
export { TrustScoreCalculator, TrustScoreWeights, TrustScoreHistory } from './core/trust-score-calculator';

// Services
export { ZeroTrustService, AuthenticationRequest, AuthenticationResult, SessionInfo } from './services/zero-trust.service';
export { ContinuousVerificationService, VerificationSchedule, VerificationResult, BehavioralAnomaly } from './services/continuous-verification.service';
export { DeviceManagementService, DeviceRegistration, DeviceComplianceCheck } from './services/device-management.service';
export { MtlsService, ServiceIdentity, CertificateValidationResult, MtlsConnection } from './services/mtls.service';

// Guards
export { ZeroTrustGuard, ZeroTrustOptions, ZERO_TRUST_METADATA, SKIP_ZERO_TRUST, RESOURCE_METADATA, ACTION_METADATA } from './guards/zero-trust.guard';

// Interceptors
export { ZeroTrustInterceptor, ZeroTrustRequestInfo } from './interceptors/zero-trust.interceptor';

// Decorators
export * from './decorators';

// Utilities
export * from './utils';