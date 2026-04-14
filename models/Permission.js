import mongoose from 'mongoose';
import logger from '../utils/loggerWrapper.js';

const permissionSchema = new mongoose.Schema(
  {
    tenantId: {
      type: String,
      required: true,
      index: true,
    },

    // Permission Details
    name: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    code: {
      type: String,
      required: true,
      unique: true,
      uppercase: true,
      trim: true,
    },
    description: {
      type: String,
      required: true,
    },
    category: {
      type: String,
      required: true,
      enum: [
        'system',
        'financial',
        'data',
        'operational',
        'security',
        'user_management',
        'blockchain',
        'emergency',
      ],
    },

    // Risk Level
    riskLevel: {
      type: String,
      required: true,
      enum: ['low', 'medium', 'high', 'critical'],
      default: 'medium',
    },

    // Security Requirements
    security: {
      requiresBiometric: {
        type: Boolean,
        default: false,
      },
      biometricTypes: [
        {
          type: String,
          enum: ['fingerprint', 'facial', 'voice', 'behavioral'],
        },
      ],
      minimumBiometrics: {
        type: Number,
        default: 1,
        min: 0,
        max: 4,
      },
      requiresMFA: {
        type: Boolean,
        default: false,
      },
      requiresApproval: {
        type: Boolean,
        default: false,
      },
      approvalCount: {
        type: Number,
        default: 1,
        min: 1,
      },
      requiresAudit: {
        type: Boolean,
        default: true,
      },
      requiresBlockchainLog: {
        type: Boolean,
        default: false,
      },
    },

    // Time-Based Restrictions
    timeRestrictions: {
      enabled: {
        type: Boolean,
        default: false,
      },
      allowedDays: [
        {
          type: String,
          enum: [
            'monday',
            'tuesday',
            'wednesday',
            'thursday',
            'friday',
            'saturday',
            'sunday',
          ],
        },
      ],
      allowedHours: {
        start: String, // HH:MM format
        end: String, // HH:MM format
      },
      timezone: {
        type: String,
        default: 'America/New_York',
      },
    },

    // Context-Based Restrictions
    contextRestrictions: {
      enabled: {
        type: Boolean,
        default: false,
      },
      allowedIpRanges: [String],
      allowedCountries: [String],
      requiresVPN: {
        type: Boolean,
        default: false,
      },
      requiresSecureNetwork: {
        type: Boolean,
        default: false,
      },
      allowedDeviceTypes: [
        {
          type: String,
          enum: ['desktop', 'mobile', 'tablet', 'server'],
        },
      ],
      trustedDevicesOnly: {
        type: Boolean,
        default: false,
      },
    },

    // Dependencies
    dependencies: {
      requiredPermissions: [
        {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'Permission',
        },
      ],
      conflictingPermissions: [
        {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'Permission',
        },
      ],
    },

    // Usage Limits
    usageLimits: {
      enabled: {
        type: Boolean,
        default: false,
      },
      maxUsesPerDay: Number,
      maxUsesPerWeek: Number,
      maxUsesPerMonth: Number,
      cooldownPeriod: Number, // in seconds
    },

    // Metadata
    isActive: {
      type: Boolean,
      default: true,
    },
    isSystemPermission: {
      type: Boolean,
      default: false,
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    modifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
  },
  {
    timestamps: true,
  }
);

// Indexes
permissionSchema.index({ tenantId: 1, code: 1 }, { unique: true });
permissionSchema.index({ category: 1, riskLevel: 1 });
permissionSchema.index({ isActive: 1 });

// Instance Methods
permissionSchema.methods = {
  // Check if permission can be used at current time
  isAllowedAtTime: function (date = new Date()) {
    if (!this.timeRestrictions.enabled) {
      return true;
    }

    const dayName = date
      .toLocaleDateString('en-US', { weekday: 'long' })
      .toLowerCase();
    if (
      this.timeRestrictions.allowedDays.length > 0 &&
      !this.timeRestrictions.allowedDays.includes(dayName)
    ) {
      return false;
    }

    if (
      this.timeRestrictions.allowedHours.start &&
      this.timeRestrictions.allowedHours.end
    ) {
      const currentTime = date.toLocaleTimeString('en-US', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
      });

      if (
        currentTime < this.timeRestrictions.allowedHours.start ||
        currentTime > this.timeRestrictions.allowedHours.end
      ) {
        return false;
      }
    }

    return true;
  },

  // Check if permission can be used from context
  isAllowedFromContext: function (context) {
    if (!this.contextRestrictions.enabled) {
      return { allowed: true };
    }

    const reasons = [];

    // Check IP range
    if (this.contextRestrictions.allowedIpRanges.length > 0) {
      const ipAllowed = this.contextRestrictions.allowedIpRanges.some(
        (range) => {
          // Simple check - in production, use proper IP range checking
          return context.ipAddress && context.ipAddress.startsWith(range);
        }
      );

      if (!ipAllowed) {
        reasons.push('IP address not in allowed range');
      }
    }

    // Check VPN requirement
    if (this.contextRestrictions.requiresVPN && !context.isVPN) {
      reasons.push('VPN connection required');
    }

    // Check secure network
    if (
      this.contextRestrictions.requiresSecureNetwork &&
      !context.isSecureNetwork
    ) {
      reasons.push('Secure network required');
    }

    // Check device type
    if (
      this.contextRestrictions.allowedDeviceTypes.length > 0 &&
      !this.contextRestrictions.allowedDeviceTypes.includes(context.deviceType)
    ) {
      reasons.push('Device type not allowed');
    }

    // Check trusted device
    if (
      this.contextRestrictions.trustedDevicesOnly &&
      !context.isTrustedDevice
    ) {
      reasons.push('Trusted device required');
    }

    return {
      allowed: reasons.length === 0,
      reasons,
    };
  },

  // Get required biometric types
  getRequiredBiometrics: function () {
    if (!this.security.requiresBiometric) {
      return [];
    }

    return this.security.biometricTypes.slice(
      0,
      this.security.minimumBiometrics
    );
  },
};

// Static Methods
permissionSchema.statics = {
  // Find by code
  findByCode: function (code, tenantId) {
    return this.findOne({ code: code.toUpperCase(), tenantId, isActive: true });
  },

  // Find by category
  findByCategory: function (category, tenantId) {
    return this.find({ category, tenantId, isActive: true });
  },

  // Find by risk level
  findByRiskLevel: function (riskLevel, tenantId) {
    return this.find({ riskLevel, tenantId, isActive: true });
  },

  // Get all system permissions
  getSystemPermissions: function (tenantId) {
    return this.find({ tenantId, isSystemPermission: true, isActive: true });
  },

  // Create default permissions
  createDefaultPermissions: async function (tenantId, createdBy) {
    const defaultPermissions = [
      // System Permissions
      {
        name: 'System Administrator',
        code: 'SYSTEM_ADMIN',
        description: 'Full system control and administration',
        category: 'system',
        riskLevel: 'critical',
        security: {
          requiresBiometric: true,
          biometricTypes: ['fingerprint', 'facial', 'voice'],
          minimumBiometrics: 3,
          requiresMFA: true,
          requiresAudit: true,
          requiresBlockchainLog: true,
        },
        isSystemPermission: true,
      },
      {
        name: 'Security Administrator',
        code: 'SECURITY_ADMIN',
        description: 'Manage security settings and policies',
        category: 'security',
        riskLevel: 'critical',
        security: {
          requiresBiometric: true,
          biometricTypes: ['fingerprint', 'facial'],
          minimumBiometrics: 2,
          requiresMFA: true,
          requiresAudit: true,
          requiresBlockchainLog: true,
        },
        isSystemPermission: true,
      },
      {
        name: 'User Management',
        code: 'USER_MANAGEMENT',
        description: 'Create, modify, and delete users',
        category: 'user_management',
        riskLevel: 'high',
        security: {
          requiresBiometric: true,
          biometricTypes: ['fingerprint'],
          minimumBiometrics: 1,
          requiresMFA: true,
          requiresAudit: true,
        },
        isSystemPermission: true,
      },

      // Financial Permissions
      {
        name: 'View Accounts',
        code: 'VIEW_ACCOUNTS',
        description: 'View account balances and information',
        category: 'financial',
        riskLevel: 'medium',
        security: {
          requiresBiometric: true,
          biometricTypes: ['fingerprint'],
          minimumBiometrics: 1,
          requiresAudit: true,
        },
        isSystemPermission: true,
      },
      {
        name: 'Initiate Transfers',
        code: 'INITIATE_TRANSFERS',
        description: 'Start money transfers',
        category: 'financial',
        riskLevel: 'high',
        security: {
          requiresBiometric: true,
          biometricTypes: ['fingerprint', 'facial'],
          minimumBiometrics: 2,
          requiresMFA: true,
          requiresApproval: true,
          requiresAudit: true,
          requiresBlockchainLog: true,
        },
        isSystemPermission: true,
      },
      {
        name: 'Approve Transfers',
        code: 'APPROVE_TRANSFERS',
        description: 'Approve pending transactions',
        category: 'financial',
        riskLevel: 'critical',
        security: {
          requiresBiometric: true,
          biometricTypes: ['fingerprint', 'facial', 'voice'],
          minimumBiometrics: 2,
          requiresMFA: true,
          requiresAudit: true,
          requiresBlockchainLog: true,
        },
        isSystemPermission: true,
      },

      // Data Permissions
      {
        name: 'Read Sensitive Data',
        code: 'READ_SENSITIVE',
        description: 'View sensitive information',
        category: 'data',
        riskLevel: 'high',
        security: {
          requiresBiometric: true,
          biometricTypes: ['fingerprint'],
          minimumBiometrics: 1,
          requiresAudit: true,
        },
        isSystemPermission: true,
      },
      {
        name: 'Write Sensitive Data',
        code: 'WRITE_SENSITIVE',
        description: 'Modify sensitive information',
        category: 'data',
        riskLevel: 'high',
        security: {
          requiresBiometric: true,
          biometricTypes: ['fingerprint', 'facial'],
          minimumBiometrics: 2,
          requiresMFA: true,
          requiresAudit: true,
          requiresBlockchainLog: true,
        },
        isSystemPermission: true,
      },
      {
        name: 'Delete Records',
        code: 'DELETE_RECORDS',
        description: 'Delete data and records',
        category: 'data',
        riskLevel: 'critical',
        security: {
          requiresBiometric: true,
          biometricTypes: ['fingerprint', 'facial'],
          minimumBiometrics: 2,
          requiresMFA: true,
          requiresApproval: true,
          approvalCount: 2,
          requiresAudit: true,
          requiresBlockchainLog: true,
        },
        isSystemPermission: true,
      },

      // Operational Permissions
      {
        name: 'Deploy Code',
        code: 'DEPLOY_CODE',
        description: 'Deploy applications and code',
        category: 'operational',
        riskLevel: 'high',
        security: {
          requiresBiometric: true,
          biometricTypes: ['fingerprint'],
          minimumBiometrics: 1,
          requiresMFA: true,
          requiresAudit: true,
        },
        isSystemPermission: true,
      },
      {
        name: 'Access Production',
        code: 'ACCESS_PRODUCTION',
        description: 'Access production systems',
        category: 'operational',
        riskLevel: 'high',
        security: {
          requiresBiometric: true,
          biometricTypes: ['fingerprint', 'facial'],
          minimumBiometrics: 2,
          requiresMFA: true,
          requiresAudit: true,
        },
        isSystemPermission: true,
      },
      {
        name: 'Emergency Override',
        code: 'EMERGENCY_OVERRIDE',
        description: 'Emergency system override',
        category: 'emergency',
        riskLevel: 'critical',
        security: {
          requiresBiometric: true,
          biometricTypes: ['fingerprint', 'facial', 'voice'],
          minimumBiometrics: 3,
          requiresMFA: true,
          requiresApproval: true,
          approvalCount: 2,
          requiresAudit: true,
          requiresBlockchainLog: true,
        },
        isSystemPermission: true,
      },
    ];

    const created = [];
    for (const perm of defaultPermissions) {
      try {
        const existing = await this.findOne({ code: perm.code, tenantId });
        if (!existing) {
          const permission = await this.create({
            ...perm,
            tenantId,
            createdBy,
          });
          created.push(permission);
        }
      } catch (error) {
        logger.error(
          `Failed to create permission ${perm.code}:`,
          error.message
        );
      }
    }

    return created;
  },
};

export default mongoose.model('Permission', permissionSchema);
