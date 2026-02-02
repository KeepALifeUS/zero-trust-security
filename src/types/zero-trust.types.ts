/**
 * Zero-Trust Security Types
 * Enterprise Patterns
 *
 * Core types for implementing Zero-Trust Security Architecture
 * Following "Never Trust, Always Verify" principle
 */

export enum TrustLevel {
  NONE = 'NONE',
  ANONYMOUS = 'ANONYMOUS',          // Backward compatibility for API Gateway
  MINIMAL = 'MINIMAL',
  AUTHENTICATED = 'AUTHENTICATED',  // Backward compatibility for API Gateway
  LOW = 'LOW',
  TRUSTED = 'TRUSTED',              // Backward compatibility for API Gateway
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  VERIFIED = 'VERIFIED',            // Backward compatibility for API Gateway
  FULL = 'FULL',
  CRITICAL = 'CRITICAL',
}

export enum RiskLevel {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MODERATE = 'MODERATE',  // Backward compatibility alias for MEDIUM
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  MINIMAL = 'MINIMAL',
}

export enum AuthenticationMethod {
  PASSWORD = 'PASSWORD',
  API_KEY = 'API_KEY',
  JWT = 'JWT',
  OAUTH2 = 'OAUTH2',
  MFA_TOTP = 'MFA_TOTP',
  MFA_SMS = 'MFA_SMS',
  BIOMETRIC = 'BIOMETRIC',
  HARDWARE_KEY = 'HARDWARE_KEY',
  CERTIFICATE = 'CERTIFICATE',
}

export enum DeviceStatus {
  UNKNOWN = 'UNKNOWN',
  TRUSTED = 'TRUSTED',
  MANAGED = 'MANAGED',
  UNMANAGED = 'UNMANAGED',
  UNTRUSTED = 'UNTRUSTED',
  PENDING = 'PENDING',
  COMPROMISED = 'COMPROMISED',
  BLACKLISTED = 'BLACKLISTED',
}

export enum NetworkZone {
  INTERNAL = 'INTERNAL',
  CORPORATE = 'CORPORATE',
  HOME = 'HOME',
  DMZ = 'DMZ',
  EXTERNAL = 'EXTERNAL',
  VPN = 'VPN',
  PROXY = 'PROXY',
  TOR = 'TOR',
  SUSPICIOUS = 'SUSPICIOUS',
  UNTRUSTED = 'UNTRUSTED',
}

export interface DeviceContext {
  deviceId: string;
  deviceType?: string;
  platform?: string;
  browser?: string;
  ipAddress?: string;
  location?: GeolocationContext;
  fingerprint?: string;
  status: DeviceStatus;
  compliance?: boolean;
  lastSecurityCheck?: Date;
  encryptionEnabled?: boolean;
  patchLevel?: string;
  lastSeen?: Date;
  trustScore?: number;
}

export interface GeolocationContext {
  country: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
  timezone: string;
  isp: string;
  vpnDetected: boolean;
  proxyDetected: boolean;
  torDetected: boolean;
}

export interface IdentityContext {
  userId: string;
  sessionId?: string;
  username?: string;
  email?: string;
  roles?: string[];
  permissions?: string[];
  authenticationMethod?: string;
  authenticationMethods?: AuthenticationMethod[];
  lastAuthentication?: Date;
  mfaEnabled?: boolean;
  mfaVerified?: boolean;
  strongPassword?: boolean;
  accountAge?: number;
  trustScore?: number;
}

export interface NetworkContext {
  ipAddress?: string;
  sourceIp?: string;
  destinationIp?: string;
  protocol?: string;
  port?: number;
  zone?: NetworkZone;
  encrypted?: boolean;
  encryptedConnection?: boolean;
  vpnConnected?: boolean;
  certificateValid?: boolean;
  mtlsEnabled?: boolean;
  trustScore?: number;
}

export interface BehavioralContext {
  normalBehavior?: boolean;
  normalLoginTime?: string[];
  normalLocations?: string[];
  normalDevices?: string[];
  tradingPatterns?: TradingPattern[];
  anomalyScore?: number;
  lastActivity?: Date;
  lastAnomalyDetected?: Date;
  behaviorProfile?: string;
}

export interface TradingPattern {
  symbol: string;
  averageVolume: number;
  averageFrequency: number;
  preferredTimeframe: string;
  riskProfile: RiskLevel;
}

export interface ZeroTrustContext {
  contextId?: string;
  sessionId?: string;
  timestamp?: Date;
  identity: IdentityContext;
  device?: DeviceContext;
  network?: NetworkContext;
  behavioral?: BehavioralContext;
  trustScore?: number;
  riskLevel?: RiskLevel;
  continuousVerification?: boolean;
  lastVerification?: Date;
  nextVerification?: Date;
  policies?: PolicyEvaluation[];
  custom?: any;
}

export interface PolicyEvaluation {
  policyId: string;
  policyName: string;
  result: 'ALLOW' | 'DENY' | 'CHALLENGE';
  reason?: string;
  conditions: PolicyCondition[];
  evaluatedAt: Date;
}

export interface PolicyCondition {
  type: string;
  operator: 'eq' | 'neq' | 'gt' | 'lt' | 'gte' | 'lte' | 'in' | 'nin';
  value: any;
  result: boolean;
}

export interface AccessRequest {
  requestId?: string;
  resourceId?: string;
  resource?: string;
  action: string;
  context?: ZeroTrustContext;
  timestamp?: Date;
  metadata?: Record<string, any>;
}

export interface AccessDecision {
  allowed: boolean;
  trustLevel?: TrustLevel;
  riskLevel?: RiskLevel;
  reason: string;
  triggeredPolicies?: string[];
  requiredActions?: RequiredAction[] | string[];
  trustScoreImpact?: number;
  ttl?: number;
  challenges?: SecurityChallenge[];
}

export enum RequiredAction {
  MFA_REQUIRED = 'MFA_REQUIRED',
  REAUTHENTICATE = 'REAUTHENTICATE',
  DEVICE_VERIFICATION = 'DEVICE_VERIFICATION',
  LOCATION_VERIFICATION = 'LOCATION_VERIFICATION',
  BLOCK = 'BLOCK',
  ALERT_ADMIN = 'ALERT_ADMIN',
  QUARANTINE_DEVICE = 'QUARANTINE_DEVICE',
}

export interface RequiredActionDetails {
  type: RequiredAction | string;
  description: string;
  deadline: Date;
  metadata?: Record<string, any>;
}

/**
 * Policy Action Types
 * Actions that can be taken when a policy is triggered
 */
export enum PolicyAction {
  REQUIRE_MFA = 'REQUIRE_MFA',
  REQUIRE_REAUTHENTICATION = 'REQUIRE_REAUTHENTICATION',
  REQUIRE_DEVICE_VERIFICATION = 'REQUIRE_DEVICE_VERIFICATION',
  LOG_ACCESS = 'LOG_ACCESS',
  CONTINUOUS_VERIFICATION = 'CONTINUOUS_VERIFICATION',
  RATE_LIMIT = 'RATE_LIMIT',
  BLOCK_ACCESS = 'BLOCK_ACCESS',
  ALERT_SECURITY_TEAM = 'ALERT_SECURITY_TEAM',
  ADAPTIVE_CHALLENGE = 'ADAPTIVE_CHALLENGE',
}

/**
 * Policy Action Details
 * Details for policy actions with metadata
 */
export interface PolicyActionDetails {
  type: PolicyAction;
  metadata?: Record<string, any>;
}

/**
 * Policy Conditions
 * Conditions that must be met for policy to apply
 */
export interface PolicyConditions {
  minTrustScore?: number;
  requiredTrustLevel?: TrustLevel;
  maxRiskLevel?: RiskLevel;
  requireMfa?: boolean;
  requireDeviceCompliance?: boolean;
  allowedNetworkZones?: string[];
  allowedGeoLocations?: string[];
  blockedCountries?: string[];
  maxSessionAge?: number;
  timeWindowRestriction?: {
    daysOfWeek?: number[];
    startTime?: string;
    endTime?: string;
    timezone?: string;
  };
  customConditions?: Record<string, any>;
}

/**
 * Policy Rule
 * Complete policy rule definition for configuration
 * Used in config files and external API
 */
export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  priority?: number;
  conditions: PolicyConditions;
  actions: PolicyActionDetails[];
  metadata?: Record<string, any>;
}

/**
 * Policy Rule Configuration
 * Alias for PolicyRule for backward compatibility
 */
export type PolicyRuleConfig = PolicyRule;

export interface SecurityChallenge {
  id?: string;
  type: 'CAPTCHA' | 'MFA' | 'SECURITY_QUESTION' | 'BIOMETRIC' | string;
  challengeId?: string;
  description?: string;
  expiresAt?: Date;
  attempts?: number;
  maxAttempts?: number;
}

export interface TrustScoreFactors {
  identityVerification: number;
  deviceCompliance: number;
  networkSecurity: number;
  behavioralAnalysis: number;
  timeDecay: number;
  recentChallenges: number;
  securityEvents: any[];
}

export interface ZeroTrustEvent {
  eventId: string;
  eventType: ZeroTrustEventType;
  timestamp: Date;
  context: ZeroTrustContext;
  details: Record<string, any>;
  impact: 'POSITIVE' | 'NEGATIVE' | 'NEUTRAL';
  trustScoreChange: number;
}

export enum ZeroTrustEventType {
  // Authentication Events
  LOGIN_SUCCESS = 'LOGIN_SUCCESS',
  LOGIN_FAILURE = 'LOGIN_FAILURE',
  MFA_SUCCESS = 'MFA_SUCCESS',
  MFA_FAILURE = 'MFA_FAILURE',
  MFA_COMPLETED = 'MFA_COMPLETED',

  // Device Events
  NEW_DEVICE = 'NEW_DEVICE',
  DEVICE_COMPROMISED = 'DEVICE_COMPROMISED',
  DEVICE_COMPLIANCE_CHANGE = 'DEVICE_COMPLIANCE_CHANGE',
  DEVICE_VERIFIED = 'DEVICE_VERIFIED',

  // Network Events
  SUSPICIOUS_LOCATION = 'SUSPICIOUS_LOCATION',
  VPN_DETECTED = 'VPN_DETECTED',
  NETWORK_ANOMALY = 'NETWORK_ANOMALY',

  // Behavioral Events
  BEHAVIORAL_ANOMALY = 'BEHAVIORAL_ANOMALY',
  ANOMALY_DETECTED = 'ANOMALY_DETECTED',
  UNUSUAL_TRADING_PATTERN = 'UNUSUAL_TRADING_PATTERN',
  PRIVILEGE_ESCALATION = 'PRIVILEGE_ESCALATION',

  // Policy Events
  POLICY_VIOLATION = 'POLICY_VIOLATION',
  ACCESS_DENIED = 'ACCESS_DENIED',
  CHALLENGE_REQUIRED = 'CHALLENGE_REQUIRED',
}

export interface ZeroTrustConfig {
  enabled: boolean;
  strictMode: boolean;
  trustScoreThreshold: number;
  continuousVerificationInterval: number;
  maxSessionDuration: number;
  requireMfa: boolean;
  deviceComplianceRequired: boolean;
  networkZoneRestrictions: NetworkZone[];
  geoLocationRestrictions: string[];
  behavioralAnalysisEnabled: boolean;
  adaptiveAuthenticationEnabled: boolean;
}

export interface _ServiceMeshConfig {
  mtlsEnabled: boolean;
  certificateRotation: boolean;
  rotationInterval: number;
  serviceWhitelist: string[];
  encryptionAlgorithm: string;
  minTlsVersion: string;
}