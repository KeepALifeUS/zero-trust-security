/**
 * Zero-Trust Utilities
 * Enterprise Pattern
 *
 * Utility functions for Zero-Trust Security
 */

import * as crypto from 'crypto';

import { RiskLevel, TrustLevel } from '../types/zero-trust.types';

/**
 * Calculate risk score from trust score
 */
export function calculateRiskScore(trustScore: number): number {
  return Math.max(0, Math.min(100, 100 - trustScore));
}

/**
 * Get risk level from trust score
 */
export function getRiskLevelFromTrustScore(trustScore: number): RiskLevel {
  if (trustScore >= 80) {return RiskLevel.MINIMAL;}
  if (trustScore >= 60) {return RiskLevel.LOW;}
  if (trustScore >= 40) {return RiskLevel.MEDIUM;}
  if (trustScore >= 20) {return RiskLevel.HIGH;}
  return RiskLevel.CRITICAL;
}

/**
 * Get trust level from score
 */
export function getTrustLevelFromScore(score: number): TrustLevel {
  if (score >= 90) {return TrustLevel.FULL;}
  if (score >= 75) {return TrustLevel.HIGH;}
  if (score >= 50) {return TrustLevel.MEDIUM;}
  if (score >= 25) {return TrustLevel.LOW;}
  if (score > 0) {return TrustLevel.MINIMAL;}
  return TrustLevel.NONE;
}

/**
 * Generate secure random token
 */
export function generateSecureToken(length: number = 32): string {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Calculate hash of data
 */
export function calculateHash(data: string, algorithm: string = 'sha256'): string {
  const hash = crypto.createHash(algorithm);
  hash.update(data);
  return hash.digest('hex');
}

/**
 * Verify hash
 */
export function verifyHash(data: string, hash: string, algorithm: string = 'sha256'): boolean {
  const calculatedHash = calculateHash(data, algorithm);
  return crypto.timingSafeEqual(Buffer.from(calculatedHash), Buffer.from(hash));
}

/**
 * Generate session ID
 */
export function generateSessionId(): string {
  const timestamp = Date.now().toString(36);
  const random = crypto.randomBytes(16).toString('hex');
  return `zt_${timestamp}_${random}`;
}

/**
 * Parse JWT token (simplified)
 */
export function parseJwtToken(token: string): any {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    const payload = Buffer.from(parts[1], 'base64').toString('utf-8');
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

/**
 * Calculate time-based OTP (simplified)
 */
export function calculateTOTP(secret: string, window: number = 30): string {
  const counter = Math.floor(Date.now() / 1000 / window);
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(Buffer.from(counter.toString()));
  const hash = hmac.digest('hex');
  return hash.substring(0, 6);
}

/**
 * Verify TOTP
 */
export function verifyTOTP(token: string, secret: string, window: number = 30, tolerance: number = 1): boolean {
  const currentToken = calculateTOTP(secret, window);

  if (token === currentToken) {
    return true;
  }

  // Check previous and next windows for tolerance
  for (let i = 1; i <= tolerance; i++) {
    const pastToken = calculateTOTP(secret, window);
    const futureToken = calculateTOTP(secret, window);

    if (token === pastToken || token === futureToken) {
      return true;
    }
  }

  return false;
}

/**
 * Sanitize user input
 */
export function sanitizeInput(input: string): string {
  // Remove potential XSS vectors
  return input
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '')
    .trim();
}

/**
 * Validate email format
 */
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Validate IP address
 */
export function isValidIP(ip: string): boolean {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

/**
 * Check if IP is private
 */
export function isPrivateIP(ip: string): boolean {
  const privateRanges = [
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^192\.168\./,
    /^127\./,
    /^::1$/,
    /^fe80::/,
  ];

  return privateRanges.some(range => range.test(ip));
}

/**
 * Calculate exponential backoff delay
 */
export function calculateBackoffDelay(attempt: number, baseDelay: number = 1000, maxDelay: number = 30000): number {
  const delay = Math.min(baseDelay * Math.pow(2, attempt), maxDelay);
  // Add jitter to avoid thundering herd
  const jitter = Math.random() * 1000;
  return delay + jitter;
}

/**
 * Format trust score for display
 */
export function formatTrustScore(score: number): string {
  if (score >= 90) {return `${score.toFixed(1)}% (Excellent)`;}
  if (score >= 75) {return `${score.toFixed(1)}% (Good)`;}
  if (score >= 50) {return `${score.toFixed(1)}% (Fair)`;}
  if (score >= 25) {return `${score.toFixed(1)}% (Poor)`;}
  return `${score.toFixed(1)}% (Critical)`;
}

/**
 * Format risk level for display
 */
export function formatRiskLevel(level: RiskLevel): string {
  const icons: Record<RiskLevel, string> = {
    [RiskLevel.CRITICAL]: '🔴',
    [RiskLevel.HIGH]: '🟠',
    [RiskLevel.MODERATE]: '🟡',  // Alias for MEDIUM
    [RiskLevel.MEDIUM]: '🟡',
    [RiskLevel.LOW]: '🟢',
    [RiskLevel.MINIMAL]: '✅',
  };

  return `${icons[level]} ${level}`;
}