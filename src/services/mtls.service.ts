/**
 * mTLS Service
 * Enterprise Pattern
 *
 * Implements mutual TLS for service-to-service communication
 * Core component of Zero-Trust service mesh
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as tls from 'tls';

import { Injectable, Logger } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';

import { _ServiceMeshConfig } from '../types/zero-trust.types';

export interface ServiceIdentity {
  serviceId: string;
  serviceName: string;
  certificate: string;
  privateKey: string;
  publicKey: string;
  issuer: string;
  validFrom: Date;
  validTo: Date;
  fingerprint: string;
  trusted: boolean;
}

export interface CertificateValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  serviceIdentity?: ServiceIdentity;
}

export interface MtlsConnection {
  connectionId: string;
  sourceService: string;
  targetService: string;
  established: Date;
  lastActivity: Date;
  encrypted: boolean;
  cipherSuite: string;
  tlsVersion: string;
  mutualAuth: boolean;
}

@Injectable()
export class MtlsService {
  private readonly logger = new Logger(MtlsService.name);
  private serviceIdentities: Map<string, ServiceIdentity> = new Map();
  private trustedCertificates: Map<string, string> = new Map();
  private activeConnections: Map<string, MtlsConnection> = new Map();
  private certificateStore: string = path.join(os.tmpdir(), 'zero-trust-certificates');

  constructor(
    private readonly eventEmitter: EventEmitter2,
  ) {
    this.initializeCertificateStore();
  }

  /**
   * Initialize certificate store
   */
  private initializeCertificateStore(): void {
    // Create certificate store directory if it doesn't exist
    if (!fs.existsSync(this.certificateStore)) {
      fs.mkdirSync(this.certificateStore, { recursive: true });
    }

    // Load existing certificates
    this.loadTrustedCertificates();
  }

  /**
   * Register a service with its certificate
   */
  public async registerService(
    serviceId: string,
    serviceName: string,
    certificate: string,
    privateKey: string,
  ): Promise<ServiceIdentity> {
    // Parse certificate
    const certInfo = this.parseCertificate(certificate);

    // Validate certificate
    const validation = await this.validateCertificate(certificate);
    if (!validation.valid) {
      throw new Error(`Certificate validation failed: ${validation.errors.join(', ')}`);
    }

    // Extract public key
    const publicKey = this.extractPublicKey(certificate);

    // Calculate fingerprint
    const fingerprint = this.calculateFingerprint(certificate);

    const identity: ServiceIdentity = {
      serviceId,
      serviceName,
      certificate,
      privateKey,
      publicKey,
      issuer: certInfo.issuer,
      validFrom: certInfo.validFrom,
      validTo: certInfo.validTo,
      fingerprint,
      trusted: true,
    };

    // Store service identity
    this.serviceIdentities.set(serviceId, identity);

    // Save certificate to store
    await this.saveCertificate(serviceId, certificate, privateKey);

    // Emit registration event
    await this.eventEmitter.emitAsync('mtls.service-registered', {
      serviceId,
      serviceName,
      fingerprint,
    });

    this.logger.log(`Service registered with mTLS: ${serviceName} (${serviceId})`);

    return identity;
  }

  /**
   * Validate mTLS connection
   */
  public async validateConnection(
    sourceService: string,
    targetService: string,
    clientCert: string,
  ): Promise<boolean> {
    // Get service identities
    const sourceIdentity = this.serviceIdentities.get(sourceService);
    const targetIdentity = this.serviceIdentities.get(targetService);

    if (!sourceIdentity || !targetIdentity) {
      this.logger.warn(`Service identity not found for mTLS validation`);
      return false;
    }

    // Validate client certificate
    const validation = await this.validateCertificate(clientCert);
    if (!validation.valid) {
      this.logger.warn(`Certificate validation failed: ${validation.errors.join(', ')}`);
      return false;
    }

    // Verify certificate fingerprint matches source service
    const fingerprint = this.calculateFingerprint(clientCert);
    if (fingerprint !== sourceIdentity.fingerprint) {
      this.logger.warn(`Certificate fingerprint mismatch for service ${sourceService}`);
      return false;
    }

    // Check if both services are trusted
    if (!sourceIdentity.trusted || !targetIdentity.trusted) {
      this.logger.warn(`Service trust validation failed`);
      return false;
    }

    // Create connection record
    const connectionId = `${sourceService}-${targetService}-${Date.now()}`;
    const connection: MtlsConnection = {
      connectionId,
      sourceService,
      targetService,
      established: new Date(),
      lastActivity: new Date(),
      encrypted: true,
      cipherSuite: 'TLS_AES_256_GCM_SHA384',
      tlsVersion: 'TLSv1.3',
      mutualAuth: true,
    };

    this.activeConnections.set(connectionId, connection);

    // Emit connection established event
    await this.eventEmitter.emitAsync('mtls.connection-established', connection);

    return true;
  }

  /**
   * Rotate service certificate
   */
  public async rotateCertificate(
    serviceId: string,
    newCertificate: string,
    newPrivateKey: string,
  ): Promise<void> {
    const identity = this.serviceIdentities.get(serviceId);

    if (!identity) {
      throw new Error(`Service ${serviceId} not found`);
    }

    // Validate new certificate
    const validation = await this.validateCertificate(newCertificate);
    if (!validation.valid) {
      throw new Error(`New certificate validation failed: ${validation.errors.join(', ')}`);
    }

    // Parse new certificate
    const certInfo = this.parseCertificate(newCertificate);

    // Update identity
    identity.certificate = newCertificate;
    identity.privateKey = newPrivateKey;
    identity.publicKey = this.extractPublicKey(newCertificate);
    identity.validFrom = certInfo.validFrom;
    identity.validTo = certInfo.validTo;
    identity.fingerprint = this.calculateFingerprint(newCertificate);

    // Save new certificate
    await this.saveCertificate(serviceId, newCertificate, newPrivateKey);

    // Emit rotation event
    await this.eventEmitter.emitAsync('mtls.certificate-rotated', {
      serviceId,
      serviceName: identity.serviceName,
      newFingerprint: identity.fingerprint,
    });

    this.logger.log(`Certificate rotated for service ${identity.serviceName}`);
  }

  /**
   * Validate a certificate
   */
  public async validateCertificate(certificate: string): Promise<CertificateValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Parse certificate to check format
      const certInfo = this.parseCertificate(certificate);

      // Check validity dates
      const now = new Date();
      if (now < certInfo.validFrom) {
        errors.push('Certificate not yet valid');
      }
      if (now > certInfo.validTo) {
        errors.push('Certificate has expired');
      }

      // Check if certificate will expire soon
      const daysUntilExpiry = (certInfo.validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
      if (daysUntilExpiry < 30) {
        warnings.push(`Certificate expires in ${Math.floor(daysUntilExpiry)} days`);
      }

      // Check certificate chain
      const chainValid = await this.validateCertificateChain(certificate);
      if (!chainValid) {
        errors.push('Certificate chain validation failed');
      }

      // Check revocation status (simplified - in production use OCSP/CRL)
      const revoked = await this.checkRevocationStatus(certificate);
      if (revoked) {
        errors.push('Certificate has been revoked');
      }

      return {
        valid: errors.length === 0,
        errors,
        warnings,
      };
    } catch (error) {
      errors.push(`Certificate parsing error: ${error instanceof Error ? error.message : String(error)}`);
      return {
        valid: false,
        errors,
        warnings,
      };
    }
  }

  /**
   * Create TLS options for mTLS
   */
  public createMtlsOptions(serviceId: string): tls.TlsOptions {
    const identity = this.serviceIdentities.get(serviceId);

    if (!identity) {
      throw new Error(`Service ${serviceId} not registered for mTLS`);
    }

    return {
      cert: identity.certificate,
      key: identity.privateKey,
      ca: Array.from(this.trustedCertificates.values()),
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.2' as any,
      ciphers: [
        'TLS_AES_256_GCM_SHA384',
        'TLS_AES_128_GCM_SHA256',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES128-GCM-SHA256',
      ].join(':'),
    };
  }

  /**
   * Verify peer certificate
   */
  public verifyPeerCertificate(cert: any): boolean {
    // Extract fingerprint from peer certificate
    const peerFingerprint = cert.fingerprint256 || cert.fingerprint;

    // Check if fingerprint is trusted
    for (const identity of this.serviceIdentities.values()) {
      if (identity.fingerprint === peerFingerprint && identity.trusted) {
        return true;
      }
    }

    this.logger.warn(`Untrusted peer certificate: ${peerFingerprint}`);
    return false;
  }

  /**
   * Get service identity
   */
  public getServiceIdentity(serviceId: string): ServiceIdentity | null {
    return this.serviceIdentities.get(serviceId) || null;
  }

  /**
   * Get active connections for a service
   */
  public getServiceConnections(serviceId: string): MtlsConnection[] {
    const connections: MtlsConnection[] = [];

    for (const connection of this.activeConnections.values()) {
      if (connection.sourceService === serviceId || connection.targetService === serviceId) {
        connections.push(connection);
      }
    }

    return connections;
  }

  /**
   * Trust a certificate
   */
  public async trustCertificate(certificateId: string, certificate: string): Promise<void> {
    // Validate certificate first
    const validation = await this.validateCertificate(certificate);
    if (!validation.valid) {
      throw new Error(`Cannot trust invalid certificate: ${validation.errors.join(', ')}`);
    }

    this.trustedCertificates.set(certificateId, certificate);
    await this.saveTrustedCertificate(certificateId, certificate);

    this.logger.log(`Certificate trusted: ${certificateId}`);
  }

  /**
   * Revoke a certificate
   */
  public async revokeCertificate(serviceId: string, reason: string): Promise<void> {
    const identity = this.serviceIdentities.get(serviceId);

    if (identity) {
      identity.trusted = false;

      // Terminate all connections for this service
      for (const [connId, connection] of this.activeConnections.entries()) {
        if (connection.sourceService === serviceId || connection.targetService === serviceId) {
          this.activeConnections.delete(connId);

          await this.eventEmitter.emitAsync('mtls.connection-terminated', {
            connectionId: connId,
            reason: `Certificate revoked: ${reason}`,
          });
        }
      }

      await this.eventEmitter.emitAsync('mtls.certificate-revoked', {
        serviceId,
        serviceName: identity.serviceName,
        reason,
      });

      this.logger.warn(`Certificate revoked for service ${identity.serviceName}: ${reason}`);
    }
  }

  /**
   * Helper methods
   */

  private parseCertificate(_certificate: string): any {
    // Simplified certificate parsing - in production use proper X.509 parsing
    const validFrom = new Date();
    const validTo = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year

    return {
      issuer: 'CN=Zero-Trust CA',
      subject: 'CN=Service',
      validFrom,
      validTo,
    };
  }

  private extractPublicKey(certificate: string): string {
    // Simplified - in production use proper crypto methods
    const hash = crypto.createHash('sha256');
    hash.update(certificate);
    return hash.digest('base64');
  }

  private calculateFingerprint(certificate: string): string {
    const hash = crypto.createHash('sha256');
    hash.update(certificate);
    return hash.digest('hex');
  }

  private async validateCertificateChain(_certificate: string): Promise<boolean> {
    // Simplified - in production implement proper chain validation
    return true;
  }

  private async checkRevocationStatus(_certificate: string): Promise<boolean> {
    // Simplified - in production check OCSP/CRL
    return false;
  }

  private async saveCertificate(
    serviceId: string,
    certificate: string,
    privateKey: string,
  ): Promise<void> {
    const certPath = path.join(this.certificateStore, `${serviceId}.crt`);
    const keyPath = path.join(this.certificateStore, `${serviceId}.key`);

    fs.writeFileSync(certPath, certificate, { mode: 0o600 });
    fs.writeFileSync(keyPath, privateKey, { mode: 0o600 });
  }

  private async saveTrustedCertificate(certificateId: string, certificate: string): Promise<void> {
    const certPath = path.join(this.certificateStore, 'trusted', `${certificateId}.crt`);
    const trustedDir = path.dirname(certPath);

    if (!fs.existsSync(trustedDir)) {
      fs.mkdirSync(trustedDir, { recursive: true });
    }

    fs.writeFileSync(certPath, certificate, { mode: 0o644 });
  }

  private loadTrustedCertificates(): void {
    const trustedDir = path.join(this.certificateStore, 'trusted');

    if (fs.existsSync(trustedDir)) {
      const files = fs.readdirSync(trustedDir);

      for (const file of files) {
        if (file.endsWith('.crt')) {
          const certId = file.replace('.crt', '');
          const certPath = path.join(trustedDir, file);
          const certificate = fs.readFileSync(certPath, 'utf-8');

          this.trustedCertificates.set(certId, certificate);
        }
      }

      this.logger.log(`Loaded ${this.trustedCertificates.size} trusted certificates`);
    }
  }
}