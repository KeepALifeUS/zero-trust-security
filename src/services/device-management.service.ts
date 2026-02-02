/**
 * Device Management Service
 * Enterprise Pattern
 *
 * Manages device registration, compliance, and trust scoring
 * Part of Zero-Trust Architecture
 */

import * as crypto from 'crypto';

import { Injectable, Logger } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import Redis from 'ioredis';
import { v4 as uuidv4 } from 'uuid';

import { DeviceContext, DeviceStatus, GeolocationContext } from '../types/zero-trust.types';

export interface DeviceRegistration {
  deviceId: string;
  userId: string;
  deviceName: string;
  deviceType: string;
  platform: string;
  registeredAt: Date;
  lastSeen: Date;
  trustScore: number;
  status: DeviceStatus;
  metadata: Record<string, any>;
}

export interface DeviceComplianceCheck {
  deviceId: string;
  compliant: boolean;
  issues: string[];
  checkedAt: Date;
  nextCheckDue: Date;
}

@Injectable()
export class DeviceManagementService {
  private readonly logger = new Logger(DeviceManagementService.name);
  private redis!: Redis;
  private registeredDevices: Map<string, DeviceRegistration> = new Map();
  private complianceChecks: Map<string, DeviceComplianceCheck> = new Map();

  constructor(private readonly eventEmitter: EventEmitter2) {
    this.initializeRedis();
  }

  private initializeRedis(): void {
    this.redis = new Redis({
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD,
      db: 3, // Device management DB
      keyPrefix: 'zt:device:',
    });
  }

  /**
   * Register a new device
   */
  public async registerDevice(
    userId: string,
    deviceInfo: Partial<DeviceContext>,
    deviceName?: string,
  ): Promise<DeviceRegistration> {
    const deviceId = deviceInfo.deviceId || uuidv4();

    const registration: DeviceRegistration = {
      deviceId,
      userId,
      deviceName: deviceName || `${deviceInfo.platform} Device`,
      deviceType: deviceInfo.deviceType || 'unknown',
      platform: deviceInfo.platform || 'unknown',
      registeredAt: new Date(),
      lastSeen: new Date(),
      trustScore: 50, // Start with neutral trust
      status: DeviceStatus.UNMANAGED,
      metadata: {
        ipAddress: deviceInfo.ipAddress,
        browser: deviceInfo.browser,
        location: deviceInfo.location,
      },
    };

    // Store registration
    this.registeredDevices.set(deviceId, registration);
    await this.saveDeviceToRedis(registration);

    // Emit device registered event
    await this.eventEmitter.emitAsync('device.registered', registration);

    this.logger.log(`Device registered: ${deviceId} for user ${userId}`);
    return registration;
  }

  /**
   * Update device status
   */
  public async updateDeviceStatus(
    deviceId: string,
    status: DeviceStatus,
    reason?: string,
  ): Promise<void> {
    const device = this.registeredDevices.get(deviceId);

    if (!device) {
      this.logger.warn(`Device not found: ${deviceId}`);
      return;
    }

    const oldStatus = device.status;
    device.status = status;
    device.lastSeen = new Date();

    // Update trust score based on status
    switch (status) {
      case DeviceStatus.MANAGED:
        device.trustScore = Math.min(100, device.trustScore + 20);
        break;
      case DeviceStatus.TRUSTED:
        device.trustScore = Math.min(100, device.trustScore + 10);
        break;
      case DeviceStatus.COMPROMISED:
        device.trustScore = 0;
        break;
      case DeviceStatus.BLACKLISTED:
        device.trustScore = 0;
        break;
    }

    await this.saveDeviceToRedis(device);

    // Emit status change event
    await this.eventEmitter.emitAsync('device.status-changed', {
      deviceId,
      oldStatus,
      newStatus: status,
      reason,
      trustScore: device.trustScore,
    });

    this.logger.log(`Device ${deviceId} status changed from ${oldStatus} to ${status}`);
  }

  /**
   * Check device compliance
   */
  public async checkDeviceCompliance(deviceId: string): Promise<DeviceComplianceCheck> {
    const device = this.registeredDevices.get(deviceId);

    if (!device) {
      return {
        deviceId,
        compliant: false,
        issues: ['Device not registered'],
        checkedAt: new Date(),
        nextCheckDue: new Date(Date.now() + 60 * 60 * 1000),
      };
    }

    const issues: string[] = [];

    // Check various compliance criteria
    if (device.status === DeviceStatus.COMPROMISED || device.status === DeviceStatus.BLACKLISTED) {
      issues.push(`Device is ${device.status.toLowerCase()}`);
    }

    // Check if device has been seen recently
    const hoursSinceLastSeen = (Date.now() - device.lastSeen.getTime()) / (1000 * 60 * 60);
    if (hoursSinceLastSeen > 24) {
      issues.push('Device not seen in last 24 hours');
    }

    // Check trust score
    if (device.trustScore < 30) {
      issues.push('Low trust score');
    }

    // Check location if available
    if (device.metadata.location) {
      const location = device.metadata.location as GeolocationContext;
      if (location.vpnDetected || location.proxyDetected || location.torDetected) {
        issues.push('Suspicious network detected');
      }
    }

    const complianceCheck: DeviceComplianceCheck = {
      deviceId,
      compliant: issues.length === 0,
      issues,
      checkedAt: new Date(),
      nextCheckDue: new Date(Date.now() + (issues.length > 0 ? 30 : 60) * 60 * 1000),
    };

    this.complianceChecks.set(deviceId, complianceCheck);

    // Emit compliance check event
    await this.eventEmitter.emitAsync('device.compliance-checked', complianceCheck);

    return complianceCheck;
  }

  /**
   * Calculate device fingerprint
   */
  public calculateDeviceFingerprint(deviceInfo: Partial<DeviceContext>): string {
    const components = [
      deviceInfo.deviceType || '',
      deviceInfo.platform || '',
      deviceInfo.browser || '',
      deviceInfo.ipAddress || '',
    ];

    const hash = crypto.createHash('sha256');
    hash.update(components.join('|'));
    return hash.digest('hex');
  }

  /**
   * Verify device fingerprint
   */
  public async verifyDeviceFingerprint(
    deviceId: string,
    currentFingerprint: string,
  ): Promise<boolean> {
    const device = this.registeredDevices.get(deviceId);

    if (!device) {
      return false;
    }

    const storedFingerprint = await this.redis.get(`fingerprint:${deviceId}`);

    if (!storedFingerprint) {
      // Store fingerprint for future verification
      await this.redis.set(`fingerprint:${deviceId}`, currentFingerprint);
      return true;
    }

    return storedFingerprint === currentFingerprint;
  }

  /**
   * Get device by ID
   */
  public async getDevice(deviceId: string): Promise<DeviceRegistration | null> {
    let device = this.registeredDevices.get(deviceId);

    if (!device) {
      // Try to load from Redis
      const data = await this.redis.get(`registration:${deviceId}`);
      if (data) {
        device = JSON.parse(data);
        this.registeredDevices.set(deviceId, device!);
      }
    }

    return device || null;
  }

  /**
   * Get user devices
   */
  public async getUserDevices(userId: string): Promise<DeviceRegistration[]> {
    const devices: DeviceRegistration[] = [];

    for (const device of this.registeredDevices.values()) {
      if (device.userId === userId) {
        devices.push(device);
      }
    }

    return devices;
  }

  /**
   * Remove device
   */
  public async removeDevice(deviceId: string): Promise<void> {
    const device = this.registeredDevices.get(deviceId);

    if (device) {
      this.registeredDevices.delete(deviceId);
      await this.redis.del(`registration:${deviceId}`);
      await this.redis.del(`fingerprint:${deviceId}`);

      // Emit device removed event
      await this.eventEmitter.emitAsync('device.removed', { deviceId, userId: device.userId });

      this.logger.log(`Device removed: ${deviceId}`);
    }
  }

  /**
   * Update device trust score
   */
  public async updateTrustScore(deviceId: string, change: number): Promise<void> {
    const device = this.registeredDevices.get(deviceId);

    if (device) {
      const oldScore = device.trustScore;
      device.trustScore = Math.max(0, Math.min(100, device.trustScore + change));

      await this.saveDeviceToRedis(device);

      // Check if status should change based on trust score
      if (device.trustScore <= 20 && device.status !== DeviceStatus.COMPROMISED) {
        await this.updateDeviceStatus(deviceId, DeviceStatus.COMPROMISED, 'Low trust score');
      } else if (device.trustScore >= 80 && device.status === DeviceStatus.UNMANAGED) {
        await this.updateDeviceStatus(deviceId, DeviceStatus.TRUSTED, 'High trust score');
      }

      this.logger.debug(`Device ${deviceId} trust score changed from ${oldScore} to ${device.trustScore}`);
    }
  }

  /**
   * Save device to Redis
   */
  private async saveDeviceToRedis(device: DeviceRegistration): Promise<void> {
    await this.redis.setex(
      `registration:${device.deviceId}`,
      86400 * 7, // 7 days TTL
      JSON.stringify(device),
    );
  }
}