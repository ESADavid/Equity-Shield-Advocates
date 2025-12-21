import Permission from '../models/Permission.js';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'permission-service' },
  transports: [
    new winston.transports.File({ filename: 'logs/permission-service.log' }),
    new winston.transports.File({
      filename: 'logs/permission-service-error.log',
      level: 'error',
    }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
    })
  );
}

class PermissionService {
  /**
   * Check if user has permission
   */
  async checkPermission(userId, permissionCode, tenantId, context = {}) {
    try {
      const permission = await Permission.findByCode(permissionCode, tenantId);
      
      if (!permission) {
        logger.warn('Permission not found', { permissionCode, tenantId });
        return {
          allowed: false,
          reason: 'Permission not found',
        };
      }

      if (!permission.isActive) {
        return {
          allowed: false,
          reason: 'Permission is inactive',
        };
      }

      // Check time restrictions
      if (!permission.isAllowedAtTime()) {
        return {
          allowed: false,
          reason: 'Permission not allowed at this time',
          restrictions: permission.restrictions.timeRestrictions,
        };
      }

      // Check context restrictions
      const contextCheck = permission.isAllowedFromContext(context);
      if (!contextCheck.allowed) {
        return {
          allowed: false,
          reason: 'Context restrictions not met',
          violations: contextCheck.reasons,
        };
      }

      // Check usage limits
      const usageLimitCheck = await this.checkUsageLimits(permission, userId);
      if (!usageLimitCheck.allowed) {
        return {
          allowed: false,
          reason: 'Usage limit exceeded',
          limits: usageLimitCheck.limits,
        };
      }

      logger.info('Permission check passed', {
        userId,
        permissionCode,
        tenantId,
      });

      return {
        allowed: true,
        permission,
        requiresBiometric: permission.security.requiresBiometric,
        biometricTypes: permission.security.biometricTypes,
        minimumBiometrics: permission.security.minimumBiometrics,
        requiresMFA: permission.security.requiresMFA,
        requiresApproval: permission.security.requiresApproval,
        approvalCount: permission.security.approvalCount,
      };
    } catch (error) {
      logger.error('Permission check failed', {
        userId,
        permissionCode,
        tenantId,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Check usage limits
   */
  async checkUsageLimits(permission, userId) {
    try {
      if (!permission.restrictions.usageLimits) {
        return { allowed: true };
      }

      const limits = permission.restrictions.usageLimits;
      const now = new Date();

      // Check daily limit
      if (limits.daily) {
        const todayStart = new Date(now.setHours(0, 0, 0, 0));
        const todayUsage = await this.getUsageCount(
          permission._id,
          userId,
          todayStart
        );
        
        if (todayUsage >= limits.daily) {
          return {
            allowed: false,
            limits: { daily: limits.daily, current: todayUsage },
          };
        }
      }

      // Check weekly limit
      if (limits.weekly) {
        const weekStart = new Date(now);
        weekStart.setDate(now.getDate() - now.getDay());
        weekStart.setHours(0, 0, 0, 0);
        
        const weeklyUsage = await this.getUsageCount(
          permission._id,
          userId,
          weekStart
        );
        
        if (weeklyUsage >= limits.weekly) {
          return {
            allowed: false,
            limits: { weekly: limits.weekly, current: weeklyUsage },
          };
        }
      }

      // Check monthly limit
      if (limits.monthly) {
        const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
        const monthlyUsage = await this.getUsageCount(
          permission._id,
          userId,
          monthStart
        );
        
        if (monthlyUsage >= limits.monthly) {
          return {
            allowed: false,
            limits: { monthly: limits.monthly, current: monthlyUsage },
          };
        }
      }

      return { allowed: true };
    } catch (error) {
      logger.error('Usage limit check failed', {
        permissionId: permission._id,
        userId,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Get usage count for a permission
   */
  async getUsageCount(permissionId, userId, since) {
    // This would query an audit log or usage tracking collection
    // For now, return 0 as placeholder
    // In production, implement actual usage tracking
    return 0;
  }

  /**
   * Log permission usage
   */
  async logPermissionUsage(userId, permissionCode, tenantId, context = {}) {
    try {
      // This would log to an audit trail or usage tracking collection
      logger.info('Permission used', {
        userId,
        permissionCode,
        tenantId,
        timestamp: new Date(),
        context,
      });

      // In production, save to database for usage tracking
      return true;
    } catch (error) {
      logger.error('Failed to log permission usage', {
        userId,
        permissionCode,
        error: error.message,
      });
      return false;
    }
  }

  /**
   * Get required biometrics for permission
   */
  async getRequiredBiometrics(permissionCode, tenantId) {
    try {
      const permission = await Permission.findByCode(permissionCode, tenantId);
      
      if (!permission) {
        return [];
      }

      return permission.getRequiredBiometrics();
    } catch (error) {
      logger.error('Failed to get required biometrics', {
        permissionCode,
        tenantId,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Validate context for permission
   */
  validateContext(permission, context) {
    return permission.isAllowedFromContext(context);
  }

  /**
   * Grant permission to user
   */
  async grantPermission(userId, permissionCode, tenantId, grantedBy) {
    try {
      const permission = await Permission.findByCode(permissionCode, tenantId);
      
      if (!permission) {
        throw new Error('Permission not found');
      }

      // In production, this would create a user-permission relationship
      // For now, just log the action
      logger.info('Permission granted', {
        userId,
        permissionCode,
        tenantId,
        grantedBy,
        timestamp: new Date(),
      });

      return {
        success: true,
        message: 'Permission granted successfully',
      };
    } catch (error) {
      logger.error('Failed to grant permission', {
        userId,
        permissionCode,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Revoke permission from user
   */
  async revokePermission(userId, permissionCode, tenantId, revokedBy) {
    try {
      const permission = await Permission.findByCode(permissionCode, tenantId);
      
      if (!permission) {
        throw new Error('Permission not found');
      }

      // In production, this would remove user-permission relationship
      // For now, just log the action
      logger.info('Permission revoked', {
        userId,
        permissionCode,
        tenantId,
        revokedBy,
        timestamp: new Date(),
      });

      return {
        success: true,
        message: 'Permission revoked successfully',
      };
    } catch (error) {
      logger.error('Failed to revoke permission', {
        userId,
        permissionCode,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Get all permissions for tenant
   */
  async getAllPermissions(tenantId) {
    try {
      const permissions = await Permission.find({ tenantId, isActive: true });
      return permissions;
    } catch (error) {
      logger.error('Failed to get permissions', {
        tenantId,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Initialize default permissions for tenant
   */
  async initializeDefaultPermissions(tenantId, createdBy) {
    try {
      await Permission.createDefaultPermissions(tenantId, createdBy);
      logger.info('Default permissions initialized', { tenantId, createdBy });
      return {
        success: true,
        message: 'Default permissions created successfully',
      };
    } catch (error) {
      logger.error('Failed to initialize default permissions', {
        tenantId,
        error: error.message,
      });
      throw error;
    }
  }
}

export default new PermissionService();
