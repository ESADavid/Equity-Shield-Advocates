/**
 * Global type declarations for Oscar Broome Revenue
 * Augments Mongoose models with custom static methods
 */

import mongoose from 'mongoose';
import type { IBiometricData } from './biometric.js';
import type { IPermission } from './permission.js';

/**
 * Augment Mongoose's global Model interface to include our custom static methods
 * for the BiometricData model
 */
declare module 'mongoose' {
  interface Model<T extends Document, TQueryHelpers = {}> {
    findByUser(userId: mongoose.Types.ObjectId | string, tenantId: string): mongoose.Query<T | null, T>;
    createForUser(userId: mongoose.Types.ObjectId | string, tenantId: string): Promise<T>;
  }
}

/**
 * Augment Mongoose's global Model interface to include our custom static methods
 * for the Permission model
 */
declare module 'mongoose' {
  interface Model<T extends Document, TQueryHelpers = {}> {
    findByCode(code: string, tenantId: string): mongoose.Query<T | null, T>;
    findByCategory(category: string, tenantId: string): mongoose.Query<T[], T>;
    findByRiskLevel(riskLevel: string, tenantId: string): mongoose.Query<T[], T>;
    getSystemPermissions(tenantId: string): mongoose.Query<T[], T>;
    createDefaultPermissions(tenantId: string, createdBy: mongoose.Types.ObjectId): Promise<T[]>;
  }
}

/**
 * Type declaration for global module exports
 */
declare global {
  // Re-export types for external use
  type BiometricDataModel = mongoose.Model<IBiometricData>;
  type PermissionModel = mongoose.Model<IPermission>;
}

export {};
