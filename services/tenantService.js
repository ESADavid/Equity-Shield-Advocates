import Tenant from '../models/Tenant.js';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'tenant-service' },
  transports: [
    new winston.transports.File({ filename: 'logs/tenant-service.log' }),
    new winston.transports.File({ filename: 'logs/tenant-service-error.log', level: 'error' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

class TenantService {
  constructor() {
    this.cache = new Map();
    this.cacheExpiry = 5 * 60 * 1000; // 5 minutes
  }

  // Get tenant by ID with caching
  async getTenantById(tenantId) {
    try {
      // Check cache first
      const cacheKey = `tenant_${tenantId}`;
      const cached = this.cache.get(cacheKey);

      if (cached && (Date.now() - cached.timestamp) < this.cacheExpiry) {
        return cached.data;
      }

      const tenant = await Tenant.findOne({ tenantId, status: 'active' });

      if (tenant) {
        // Cache the result
        this.cache.set(cacheKey, {
          data: tenant,
          timestamp: Date.now()
        });
      }

      return tenant;
    } catch (error) {
      logger.error('Error getting tenant by ID', { tenantId, error: error.message });
      throw error;
    }
  }

  // Get tenant by domain
  async getTenantByDomain(domain) {
    try {
      const cacheKey = `domain_${domain}`;
      const cached = this.cache.get(cacheKey);

      if (cached && (Date.now() - cached.timestamp) < this.cacheExpiry) {
        return cached.data;
      }

      const tenant = await Tenant.findByDomain(domain);

      if (tenant) {
        this.cache.set(cacheKey, {
          data: tenant,
          timestamp: Date.now()
        });
      }

      return tenant;
    } catch (error) {
      logger.error('Error getting tenant by domain', { domain, error: error.message });
      throw error;
    }
  }

  // Create new tenant
  async createTenant(tenantData) {
    try {
      const tenant = new Tenant({
        ...tenantData,
        audit: {
          ...tenantData.audit,
          createdBy: tenantData.audit?.createdBy || 'system'
        }
      });

      await tenant.save();

      logger.info('Tenant created successfully', {
        tenantId: tenant.tenantId,
        name: tenant.name,
        domain: tenant.domain
      });

      // Clear cache
      this.clearCache();

      return tenant;
    } catch (error) {
      logger.error('Error creating tenant', { error: error.message, tenantData });
      throw error;
    }
  }

  // Update tenant
  async updateTenant(tenantId, updateData, updatedBy = 'system') {
    try {
      const tenant = await Tenant.findOneAndUpdate(
        { tenantId },
        {
          ...updateData,
          'audit.updatedBy': updatedBy,
          'audit.updatedAt': new Date()
        },
        { new: true, runValidators: true }
      );

      if (!tenant) {
        throw new Error('Tenant not found');
      }

      logger.info('Tenant updated successfully', {
        tenantId,
        updatedBy,
        changes: Object.keys(updateData)
      });

      // Clear cache
      this.clearCache();

      return tenant;
    } catch (error) {
      logger.error('Error updating tenant', { tenantId, error: error.message });
      throw error;
    }
  }

  // Delete tenant (soft delete by setting status to inactive)
  async deleteTenant(tenantId, deletedBy = 'system') {
    try {
      const tenant = await this.updateTenant(tenantId, {
        status: 'inactive',
        'audit.updatedBy': deletedBy
      });

      logger.info('Tenant deleted (soft)', { tenantId, deletedBy });

      return tenant;
    } catch (error) {
      logger.error('Error deleting tenant', { tenantId, error: error.message });
      throw error;
    }
  }

  // Check tenant limits
  async checkTenantLimits(tenantId, type) {
    try {
      const tenant = await this.getTenantById(tenantId);
      if (!tenant) {
        throw new Error('Tenant not found');
      }

      return await tenant.checkLimits(type);
    } catch (error) {
      logger.error('Error checking tenant limits', { tenantId, type, error: error.message });
      throw error;
    }
  }

  // Get tenant usage statistics
  async getTenantUsage(tenantId) {
    try {
      const tenant = await this.getTenantById(tenantId);
      if (!tenant) {
        throw new Error('Tenant not found');
      }

      return await tenant.getUsageStats();
    } catch (error) {
      logger.error('Error getting tenant usage', { tenantId, error: error.message });
      throw error;
    }
  }

  // Verify API key for tenant
  async verifyApiKey(tenantId, apiKey) {
    try {
      const tenant = await this.getTenantById(tenantId);
      if (!tenant) {
        return { valid: false, reason: 'Tenant not found' };
      }

      const result = await tenant.verifyApiKey(apiKey);
      return result;
    } catch (error) {
      logger.error('Error verifying API key', { tenantId, error: error.message });
      return { valid: false, reason: 'Verification failed' };
    }
  }

  // Check if tenant has feature access
  async hasFeatureAccess(tenantId, feature) {
    try {
      const tenant = await this.getTenantById(tenantId);
      if (!tenant) {
        return false;
      }

      return tenant.hasFeature(feature);
    } catch (error) {
      logger.error('Error checking feature access', { tenantId, feature, error: error.message });
      return false;
    }
  }

  // Get all active tenants
  async getActiveTenants() {
    try {
      return await Tenant.find({ status: 'active' }).select('tenantId name domain subscription.plan');
    } catch (error) {
      logger.error('Error getting active tenants', { error: error.message });
      throw error;
    }
  }

  // Process expired subscriptions
  async processExpiredSubscriptions() {
    try {
      const expiredTenants = await Tenant.findExpiredSubscriptions();

      for (const tenant of expiredTenants) {
        logger.info('Processing expired subscription', {
          tenantId: tenant.tenantId,
          plan: tenant.subscription.plan,
          endDate: tenant.subscription.endDate
        });

        // Suspend tenant if auto-renew is disabled
        if (!tenant.subscription.autoRenew) {
          await tenant.suspend('Subscription expired');
          logger.info('Tenant suspended due to expired subscription', { tenantId: tenant.tenantId });
        } else {
          // Implement auto-renewal logic
          try {
            const renewalResult = await this.processAutoRenewal(tenant);
            if (renewalResult.success) {
              logger.info('Auto-renewal processed successfully', {
                tenantId: tenant.tenantId,
                newEndDate: renewalResult.newEndDate
              });
            } else {
              logger.warn('Auto-renewal failed, suspending tenant', {
                tenantId: tenant.tenantId,
                reason: renewalResult.reason
              });
              await tenant.suspend('Auto-renewal failed');
            }
          } catch (renewalError) {
            logger.error('Error during auto-renewal', {
              tenantId: tenant.tenantId,
              error: renewalError.message
            });
            await tenant.suspend('Auto-renewal error');
          }
        }
      }

      return expiredTenants.length;
    } catch (error) {
      logger.error('Error processing expired subscriptions', { error: error.message });
      throw error;
    }
  }

  // Process auto-renewal for a tenant
  async processAutoRenewal(tenant) {
    try {
      // Get current subscription details
      const currentPlan = tenant.subscription.plan;
      const currentEndDate = tenant.subscription.endDate;

      // Calculate new end date (extend by subscription period)
      const planDurations = {
        starter: 30, // 30 days
        professional: 365, // 1 year
        enterprise: 365 // 1 year
      };

      const extensionDays = planDurations[currentPlan] || 365;
      const newEndDate = new Date(currentEndDate);
      newEndDate.setDate(newEndDate.getDate() + extensionDays);

      // Update tenant subscription
      tenant.subscription.endDate = newEndDate;
      tenant.subscription.status = 'active';
      tenant.audit.updatedAt = new Date();
      tenant.audit.updatedBy = 'auto-renewal-system';

      await tenant.save();

      logger.info('Auto-renewal completed', {
        tenantId: tenant.tenantId,
        plan: currentPlan,
        oldEndDate: currentEndDate,
        newEndDate: newEndDate
      });

      return {
        success: true,
        newEndDate: newEndDate,
        plan: currentPlan
      };
    } catch (error) {
      logger.error('Auto-renewal processing failed', {
        tenantId: tenant.tenantId,
        error: error.message
      });

      return {
        success: false,
        reason: error.message
      };
    }
  }

  // Create tenant-specific database connection (for future multi-database support)
  async getTenantDatabase(tenantId) {
    // For now, return default connection
    // In the future, this could return tenant-specific database connections
    const mongoose = (await import('mongoose')).default;
    return mongoose.connection;
  }

  // Clear cache
  clearCache() {
    this.cache.clear();
    logger.debug('Tenant cache cleared');
  }

  // Get cache statistics
  getCacheStats() {
    return {
      size: this.cache.size,
      keys: Array.from(this.cache.keys())
    };
  }

  // Health check for tenant service
  async healthCheck() {
    try {
      const tenantCount = await Tenant.countDocuments({ status: 'active' });
      return {
        status: 'healthy',
        activeTenants: tenantCount,
        cacheSize: this.cache.size
      };
    } catch (error) {
      logger.error('Tenant service health check failed', { error: error.message });
      return {
        status: 'unhealthy',
        error: error.message
      };
    }
  }
}

// Create singleton instance
const tenantService = new TenantService();

export default tenantService;
