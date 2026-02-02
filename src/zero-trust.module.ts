/**
 * Zero-Trust Security Module
 * Enterprise Pattern
 *
 * Main module for Zero-Trust Security Architecture
 * Integrates all Zero-Trust components and services
 */

import { Module, DynamicModule, Global } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { JwtModule } from '@nestjs/jwt';
// ScheduleModule removed - must be at app root level
// HTTP module removed - axios is used directly

// Core components
import { ZeroTrustPolicyEngine } from './core/policy-engine';
import { TrustScoreCalculator } from './core/trust-score-calculator';
// Services
import { ZeroTrustGuard } from './guards/zero-trust.guard';
import { ZeroTrustInterceptor } from './interceptors/zero-trust.interceptor';
import { ContinuousVerificationService } from './services/continuous-verification.service';
import { DeviceManagementService } from './services/device-management.service';
import { MtlsService } from './services/mtls.service';
import { ZeroTrustService } from './services/zero-trust.service';
// Guards and Interceptors
// Configuration
import { ZeroTrustConfig } from './types/zero-trust.types';

export interface ZeroTrustModuleOptions {
  config?: Partial<ZeroTrustConfig>;
  redisUrl?: string;
  jwtSecret?: string;
  enableMtls?: boolean;
  enableContinuousVerification?: boolean;
  strictMode?: boolean;
}

@Global()
@Module({})
export class ZeroTrustModule {
  static forRoot(options: ZeroTrustModuleOptions = {}): DynamicModule {
    return {
      module: ZeroTrustModule,
      imports: [
        ConfigModule,
        EventEmitterModule.forRoot({
          wildcard: true,
          delimiter: '.',
          newListener: true,
          removeListener: false,
          maxListeners: 20,
          verboseMemoryLeak: false,
          ignoreErrors: false,
        }),
        // Note: ScheduleModule.forRoot() must be at app root level
        JwtModule.registerAsync({
          imports: [ConfigModule],
          inject: [ConfigService],
          useFactory: (configService: ConfigService) => ({
            secret: options.jwtSecret || configService.get<string>('JWT_SECRET', 'zero-trust-secret'),
            signOptions: {
              expiresIn: '1h',
              algorithm: 'HS512',
            },
          }),
        }),
      ],
      providers: [
        // Configuration provider
        {
          provide: 'ZERO_TRUST_CONFIG',
          useFactory: (_configService: ConfigService) => ({
            enabled: options.config?.enabled ?? true,
            strictMode: options.strictMode ?? false,
            trustScoreThreshold: options.config?.trustScoreThreshold ?? 50,
            continuousVerificationInterval: options.config?.continuousVerificationInterval ?? 300000,
            maxSessionDuration: options.config?.maxSessionDuration ?? 86400000,
            requireMfa: options.config?.requireMfa ?? true,
            deviceComplianceRequired: options.config?.deviceComplianceRequired ?? true,
            networkZoneRestrictions: options.config?.networkZoneRestrictions ?? [],
            geoLocationRestrictions: options.config?.geoLocationRestrictions ?? [],
            behavioralAnalysisEnabled: options.config?.behavioralAnalysisEnabled ?? true,
            adaptiveAuthenticationEnabled: options.config?.adaptiveAuthenticationEnabled ?? true,
            ...options.config,
          }),
          inject: [ConfigService],
        },

        // Redis configuration
        {
          provide: 'REDIS_CONFIG',
          useFactory: (configService: ConfigService) => ({
            url: options.redisUrl || configService.get<string>('REDIS_URL', 'redis://localhost:6379'),
          }),
          inject: [ConfigService],
        },

        // Core services
        ZeroTrustPolicyEngine,
        TrustScoreCalculator,
        ContinuousVerificationService,
        ZeroTrustService,
        DeviceManagementService,
        MtlsService,

        // Guards
        ZeroTrustGuard,

        // Interceptors
        ZeroTrustInterceptor,
      ],
      exports: [
        ZeroTrustService,
        ZeroTrustPolicyEngine,
        TrustScoreCalculator,
        ContinuousVerificationService,
        DeviceManagementService,
        MtlsService,
        ZeroTrustGuard,
        ZeroTrustInterceptor,
        'ZERO_TRUST_CONFIG',
      ],
    };
  }

  static forRootAsync(options: {
    imports?: any[];
    useFactory?: (...args: any[]) => Promise<ZeroTrustModuleOptions> | ZeroTrustModuleOptions;
    inject?: any[];
  }): DynamicModule {
    return {
      module: ZeroTrustModule,
      imports: [
        ConfigModule,
        EventEmitterModule.forRoot({
          wildcard: true,
          delimiter: '.',
          newListener: true,
          removeListener: false,
          maxListeners: 20,
          verboseMemoryLeak: false,
          ignoreErrors: false,
        }),
        // Note: ScheduleModule.forRoot() must be at app root level
        JwtModule.registerAsync({
          imports: [ConfigModule],
          inject: [ConfigService],
          useFactory: async (configService: ConfigService) => {
            const moduleOptions = await options.useFactory?.(configService) || {};
            return {
              secret: moduleOptions.jwtSecret || configService.get<string>('JWT_SECRET', 'zero-trust-secret'),
              signOptions: {
                expiresIn: '1h',
                algorithm: 'HS512',
              },
            };
          },
        }),
        ...(options.imports || []),
      ],
      providers: [
        // Async configuration provider
        {
          provide: 'ZERO_TRUST_CONFIG',
          useFactory: async (...args: any[]) => {
            const moduleOptions = await options.useFactory?.(...args) || {};
            return {
              enabled: moduleOptions.config?.enabled ?? true,
              strictMode: moduleOptions.strictMode ?? false,
              trustScoreThreshold: moduleOptions.config?.trustScoreThreshold ?? 50,
              continuousVerificationInterval: moduleOptions.config?.continuousVerificationInterval ?? 300000,
              maxSessionDuration: moduleOptions.config?.maxSessionDuration ?? 86400000,
              requireMfa: moduleOptions.config?.requireMfa ?? true,
              deviceComplianceRequired: moduleOptions.config?.deviceComplianceRequired ?? true,
              networkZoneRestrictions: moduleOptions.config?.networkZoneRestrictions ?? [],
              geoLocationRestrictions: moduleOptions.config?.geoLocationRestrictions ?? [],
              behavioralAnalysisEnabled: moduleOptions.config?.behavioralAnalysisEnabled ?? true,
              adaptiveAuthenticationEnabled: moduleOptions.config?.adaptiveAuthenticationEnabled ?? true,
              ...moduleOptions.config,
            };
          },
          inject: options.inject || [],
        },

        // Redis configuration
        {
          provide: 'REDIS_CONFIG',
          useFactory: async (...args: any[]) => {
            const moduleOptions = await options.useFactory?.(...args) || {};
            const configService = args.find(arg => arg instanceof ConfigService);
            return {
              url: moduleOptions.redisUrl || configService?.get<string>('REDIS_URL', 'redis://localhost:6379'),
            };
          },
          inject: options.inject || [],
        },

        // Core services
        ZeroTrustPolicyEngine,
        TrustScoreCalculator,
        ContinuousVerificationService,
        ZeroTrustService,
        DeviceManagementService,
        MtlsService,

        // Guards
        ZeroTrustGuard,

        // Interceptors
        ZeroTrustInterceptor,
      ],
      exports: [
        ZeroTrustService,
        ZeroTrustPolicyEngine,
        TrustScoreCalculator,
        ContinuousVerificationService,
        DeviceManagementService,
        MtlsService,
        ZeroTrustGuard,
        ZeroTrustInterceptor,
        'ZERO_TRUST_CONFIG',
      ],
    };
  }
}