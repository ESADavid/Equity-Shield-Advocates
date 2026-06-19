/**
 * Permission type definitions for TypeScript
 * Augments the Permission Mongoose model with static methods
 */

import mongoose from 'mongoose';

/**
 * Permission document interface
 */
export interface IPermission extends mongoose.Document {
  tenantId: string;
  name: string;
  code: string;
  description: string;
  category: 'system' | 'financial' | 'data' | 'operational' | 'security' | 'user_management' | 'blockchain' | 'emergency';
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  security: {
    requiresBiometric: boolean;
    biometricTypes: Array<'fingerprint' | 'facial' | 'voice' | 'behavioral'>;
    minimumBiometrics: number;
    requiresMFA: boolean;
    requiresApproval: boolean;
    approvalCount: number;
    requiresAudit: boolean;
    requiresBlockchainLog: boolean;
  };
  timeRestrictions: {
    enabled: boolean;
    allowedDays: Array<'monday' | 'tuesday' | 'wednesday' | 'thursday' | 'friday' | 'saturday' | 'sunday'>;
    allowedHours?: {
      start: string;
      end: string;
    };
    timezone: string;
  };
  contextRestrictions: {
    enabled: boolean;
    allowedIpRanges: string[];
    allowedCountries: string[];
    requiresVPN: boolean;
    requiresSecureNetwork: boolean;
    allowedDeviceTypes: Array<'desktop' | 'mobile' | 'tablet' | 'server'>;
    trustedDevicesOnly: boolean;
  };
  dependencies: {
    requiredPermissions: mongoose.Types.ObjectId[];
    conflictingPermissions: mongoose.Types.ObjectId[];
  };
  usageLimits: {
    enabled: boolean;
    maxUsesPerDay?: number;
    maxUsesPerWeek?: number;
    maxUsesPerMonth?: number;
    cooldownPeriod?: number;
  };
  isActive: boolean;
  isSystemPermission: boolean;
  createdBy?: mongoose.Types.ObjectId;
  modifiedBy?: mongoose.Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
  // Instance methods
  isAllowedAtTime(date?: Date): boolean;
  isAllowedFromContext(context: unknown): { allowed: boolean; reasons: string[] };
  getRequiredBiometrics(): string[];
}

/**
 * Permission model static methods interface
 */
export interface IPermissionModel extends mongoose.Model<IPermission> {
  findByCode(code: string, tenantId: string): mongoose.Query<IPermission | null, IPermission>;
  findByCategory(category: string, tenantId: string): mongoose.Query<IPermission[], IPermission>;
  findByRiskLevel(riskLevel: string, tenantId: string): mongoose.Query<IPermission[], IPermission>;
  getSystemPermissions(tenantId: string): mongoose.Query<IPermission[], IPermission>;
  createDefaultPermissions(tenantId: string, createdBy: mongoose.Types.ObjectId): Promise<IPermission[]>;
}

export default IPermissionModel;
