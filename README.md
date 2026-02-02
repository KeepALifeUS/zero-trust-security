# Zero-Trust Security Architecture

Enterprise-grade Zero-Trust security framework built with NestJS. Implements the "Never Trust, Always Verify" principle with continuous verification, dynamic trust scoring, mutual TLS, and policy-based access control.

## Architecture

```
src/
├── core/
│   ├── trust-score-calculator.ts    # Dynamic trust score computation (6 weighted factors)
│   ├── trust-score-calculator.spec.ts
│   ├── policy-engine.ts             # Rule-based policy evaluation engine
│   └── policy-engine.spec.ts
├── services/
│   ├── zero-trust.service.ts        # Core authentication & authorization service
│   ├── zero-trust.service.spec.ts
│   ├── continuous-verification.service.ts  # Behavioral anomaly detection & session monitoring
│   ├── device-management.service.ts # Device compliance & fingerprinting
│   └── mtls.service.ts              # Mutual TLS for service-to-service auth
├── guards/
│   ├── zero-trust.guard.ts          # NestJS guard with trust score enforcement
│   └── zero-trust.guard.spec.ts
├── interceptors/
│   └── zero-trust.interceptor.ts    # Request/response trust context injection
├── decorators/
│   └── index.ts                     # @ZeroTrust(), @SkipZeroTrust() decorators
├── types/
│   └── zero-trust.types.ts          # Full type system (50+ interfaces/enums)
├── utils/
│   └── index.ts
├── zero-trust.module.ts             # NestJS dynamic module with forRoot/forRootAsync
└── index.ts
```

## Key Components

### Trust Score Calculator

Computes dynamic trust scores (0-100) based on six weighted factors:

- **Identity Verification** (30%) — authentication method strength, MFA status, account age
- **Device Compliance** (20%) — device trust status, encryption, patch level
- **Network Security** (20%) — network zone, encryption, VPN/proxy detection
- **Behavioral Analysis** (15%) — anomaly detection, usage patterns
- **Time Decay** (10%) — session freshness, last verification time
- **Recent Challenges** (5%) — security event history

### Policy Engine

Rule-based access control with configurable policies:

- Priority-based policy evaluation
- Conditions: trust score thresholds, risk levels, MFA requirements, network zones, geolocation, time windows
- Actions: require MFA, reauthenticate, block access, alert security team, adaptive challenges
- Supports custom conditions and metadata

### Continuous Verification Service

Real-time session monitoring with behavioral anomaly detection:

- Configurable verification schedules per risk level
- Behavioral profiling (login times, locations, devices, activity patterns)
- Anomaly scoring with automatic trust score adjustment
- Session termination on critical anomalies

### Device Management

Device lifecycle management with compliance enforcement:

- Device registration and fingerprinting
- Compliance checks (encryption, OS version, patch level, antivirus)
- Automatic trust adjustment based on compliance status
- Device quarantine and blacklisting

### Mutual TLS (mTLS)

Service-to-service authentication:

- Certificate registration, validation, and rotation
- Certificate chain verification
- Fingerprint-based peer verification
- TLS 1.2+ with strong cipher suites
- Connection lifecycle management

### Zero-Trust Guard

NestJS guard implementing per-request authorization:

- Decorator-based configuration (`@ZeroTrust()`, `@SkipZeroTrust()`)
- JWT session extraction from headers, cookies, or custom headers
- Trust score threshold enforcement
- Strict mode with continuous verification and session age limits
- Challenge-response flow for step-up authentication

## Usage

```typescript
import { ZeroTrustModule } from 'zero-trust-security';

@Module({
  imports: [
    ZeroTrustModule.forRoot({
      enabled: true,
      strictMode: true,
      trustScoreThreshold: 70,
      continuousVerificationInterval: 300000, // 5 minutes
      maxSessionDuration: 3600000, // 1 hour
      requireMfa: true,
      deviceComplianceRequired: true,
      behavioralAnalysisEnabled: true,
      adaptiveAuthenticationEnabled: true,
      networkZoneRestrictions: ['INTERNAL', 'CORPORATE', 'VPN'],
      geoLocationRestrictions: ['US', 'EU'],
    }),
  ],
})
export class AppModule {}
```

### Protecting Routes

```typescript
import { ZeroTrust, SkipZeroTrust } from 'zero-trust-security';

@Controller('admin')
export class AdminController {
  @Get('dashboard')
  @ZeroTrust({ minimumTrustScore: 80, requireMfa: true })
  getDashboard() {
    return { status: 'ok' };
  }

  @Get('health')
  @SkipZeroTrust()
  healthCheck() {
    return { healthy: true };
  }
}
```

## Tech Stack

- **Runtime:** Node.js with TypeScript
- **Framework:** NestJS 11
- **Authentication:** JWT, mTLS, MFA (TOTP, SMS, biometric, hardware key)
- **Crypto:** SHA-256 fingerprinting, TLS 1.2+, AES-256-GCM
- **Testing:** Jest with unit tests for core components

## License

MIT
