/**
 * BiometricData type definitions for TypeScript
 * Augments the BiometricData Mongoose model with static methods
 */

import mongoose from 'mongoose';

/**
 * Fingerprint template subdocument interface
 */
export interface IFingerprintTemplate {
  finger: 'thumb' | 'index' | 'middle' | 'ring' | 'pinky';
  hand: 'left' | 'right';
  hash: string;
  quality: number;
  enrolledAt: Date;
  lastUsed: Date;
}

/**
 * Facial template subdocument interface
 */
export interface IFacialTemplate {
  hash: string;
  quality: number;
  enrolledAt: Date;
  lastUsed: Date;
  metadata: {
    captureDevice?: string;
    lighting?: string;
    angle?: string;
  };
}

/**
 * Voice template subdocument interface
 */
export interface IVoiceTemplate {
  hash: string;
  quality: number;
  enrolledAt: Date;
  lastUsed: Date;
  metadata: {
    sampleDuration?: number;
    frequency?: string;
  };
}

/**
 * Device fingerprint subdocument interface
 */
export interface IDeviceFingerprint {
  deviceId: string;
  deviceType: string;
  browser: string;
  os: string;
  screenResolution: string;
  timezone: string;
  language: string;
  hash: string;
  trusted: boolean;
  firstSeen: Date;
  lastSeen: Date;
}

/**
 * Audit log entry subdocument interface
 */
export interface IAuditLog {
  action: string;
  biometricType: string;
  success: boolean;
  timestamp: Date;
  ipAddress: string;
  deviceId: string;
  blockchainHash?: string;
}

/**
 * BiometricData document interface
 */
export interface IBiometricData extends mongoose.Document {
  userId: mongoose.Types.ObjectId;
  tenantId: string;
  fingerprint: {
    enabled: boolean;
    templates: IFingerprintTemplate[];
    algorithm: string;
  };
  facial: {
    enabled: boolean;
    templates: IFacialTemplate[];
    algorithm: string;
  };
  voice: {
    enabled: boolean;
    templates: IVoiceTemplate[];
    algorithm: string;
  };
  behavioral: {
    enabled: boolean;
    keystrokeDynamics?: {
      pattern: string;
      accuracy: number;
      sampleSize: number;
    };
    mouseMovement?: {
      pattern: string;
      accuracy: number;
      sampleSize: number;
    };
    navigationPattern?: {
      pattern: string;
      accuracy: number;
      sampleSize: number;
    };
  };
  deviceFingerprints: IDeviceFingerprint[];
  encryption: {
    algorithm: string;
    keyVersion: number;
    salt?: string;
    iv?: string;
  };
  blockchain: {
    enabled: boolean;
    ledgerId?: string;
    lastBlockHash?: string;
  };
  security: {
    requireAllBiometrics: boolean;
    minimumBiometrics: number;
    maxFailedAttempts: number;
    lockoutDuration: number;
    failedAttempts: number;
    lockedUntil?: Date;
  };
  auditLog: IAuditLog[];
  isActive: boolean;
  enrollmentComplete: boolean;
  lastVerification?: Date;
  verificationCount: number;
  // Instance methods
  encryptBiometric(data: unknown): { encrypted: string; authTag: string };
  decryptBiometric(encryptedData: string, authTag: string): unknown;
  hashBiometricTemplate(template: unknown): { hash: string; salt: string };
  verifyBiometricTemplate(template: unknown, storedHash: string, salt: string): boolean;
  addFingerprintTemplate(finger: string, hand: string, template: unknown, quality: number): Promise<boolean>;
  verifyFingerprint(template: unknown): Promise<boolean>;
  addFacialTemplate(template: unknown, quality: number, metadata?: unknown): Promise<boolean>;
  verifyFacial(template: unknown): Promise<boolean>;
  addVoiceTemplate(template: unknown, quality: number, metadata?: unknown): Promise<boolean>;
  verifyVoice(template: unknown): Promise<boolean>;
  registerDevice(deviceInfo: unknown): Promise<string>;
  isDeviceTrusted(deviceHash: string): boolean;
  logAudit(action: string, biometricType: string, success: boolean, ipAddress: string, deviceId: string, blockchainHash?: string): Promise<void>;
  isLocked(): boolean;
  incrementFailedAttempts(): Promise<void>;
  resetFailedAttempts(): Promise<void>;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * BiometricData model static methods interface
 */
export interface IBiometricDataModel extends mongoose.Model<IBiometricData> {
  findByUser(userId: mongoose.Types.ObjectId | string, tenantId: string): mongoose.Query<IBiometricData | null, IBiometricData>;
  createForUser(userId: mongoose.Types.ObjectId | string, tenantId: string): Promise<IBiometricData>;
}

export default IBiometricDataModel;
