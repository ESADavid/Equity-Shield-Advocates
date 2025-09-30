import tenantService from '../services/tenantService.js';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'tenant-middleware' },
  transports: [
    new winston.transports.File({ filename: 'logs/tenant-middleware.log' }),
    new winston.transports.File({ filename: 'logs/tenant-middleware-error.log', level: 'error' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Resolve tenant from request
export const resolveTenant = async (req, res, next) => {
  try {
    let tenantId = null;
    let tenant = null;

    // Method 1: Check JWT token (already set by auth middleware)
    if (req.tenantId) {
      tenantId = req.tenantId;
      tenant = await tenantService.getTenantById(tenantId);
    }

    // Method 2: Check subdomain (e.g., tenant1.oscarbroome.com)
    if (!tenant && req.subdomains && req.subdomains.length > 0) {
      const subdomain = req.subdomains[0];
      tenant = await tenantService.getTenantByDomain(`${subdomain}.${req.hostname}`);
      if (tenant) {
        tenantId = tenant.tenantId;
      }
    }

    // Method 3: Check custom header
    if (!tenant) {
      const tenantHeader = req.headers['x-tenant-id'] || req.headers['tenant-id'];
      if (tenantHeader) {
        tenant = await tenantService.getTenantById(tenantHeader);
        if (tenant) {
          tenantId = tenant.tenantId;
        }
      }
    }

    // Method 4: Check API key
    if (!tenant) {
      const apiKey = req.headers['x-api-key'] || req.headers['api-key'];
      if (apiKey) {
        // Try to find tenant by API key (this would need to be implemented more efficiently)
        // For now, skip this method
        logger.debug('API key authentication not implemented for tenant resolution');
      }
    }

    // Method 5: Default to system tenant if no tenant found
    if (!tenant) {
      tenant = await tenantService.getTenantById('default');
      if (tenant) {
        tenantId = tenant.tenantId;
        logger.debug('Using default tenant', { path: req.path, ip: req.ip });
      }
    }

    if (!tenant) {
      logger.warn('No tenant found for request', {
        path: req.path,
        hostname: req.hostname,
        subdomains: req.subdomains,
        ip: req.ip
      });

      return res.status(400).json({
        success: false,
        message: 'Unable to determine tenant for this request'
      });
    }

    // Check if tenant is active
    if (tenant.status !== 'active') {
      logger.warn('Inactive tenant access attempt', {
        tenantId: tenant.tenantId,
        status: tenant.status,
        path: req.path
      });

      return res.status(403).json({
        success: false,
        message: 'Tenant is not active'
      });
    }

    // Check subscription status
    if (!tenant.isSubscriptionActive) {
      logger.warn('Expired subscription access attempt', {
        tenantId: tenant.tenantId,
        subscriptionStatus: tenant.subscription.status,
        path: req.path
      });

      return res.status(403).json({
        success: false,
        message: 'Tenant subscription has expired'
      });
    }

    // Attach tenant to request
    req.tenant = tenant;
    req.tenantId = tenantId;

    logger.debug('Tenant resolved successfully', {
      tenantId,
      tenantName: tenant.name,
      path: req.path
    });

    next();
  } catch (error) {
    logger.error('Tenant resolution failed', {
      error: error.message,
      path: req.path,
      ip: req.ip
    });

    return res.status(500).json({
      success: false,
      message: 'Tenant resolution failed'
    });
  }
};

// Check tenant feature access
export const requireFeature = (feature) => {
  return async (req, res, next) => {
    try {
      if (!req.tenant) {
        return res.status(500).json({
          success: false,
          message: 'Tenant not resolved'
        });
      }

      const hasFeature = await tenantService.hasFeatureAccess(req.tenant.tenantId, feature);

      if (!hasFeature) {
        logger.warn('Feature access denied', {
          tenantId: req.tenant.tenantId,
          feature,
          path: req.path
        });

        return res.status(403).json({
          success: false,
          message: `Feature '${feature}' is not available for this tenant`
        });
      }

      logger.debug('Feature access granted', {
        tenantId: req.tenant.tenantId,
        feature,
        path: req.path
      });

      next();
    } catch (error) {
      logger.error('Feature check failed', {
        error: error.message,
        tenantId: req.tenant?.tenantId,
        feature,
        path: req.path
      });

      return res.status(500).json({
        success: false,
        message: 'Feature check failed'
      });
    }
  };
};

// Check tenant limits
export const checkLimits = (type) => {
  return async (req, res, next) => {
    try {
      if (!req.tenant) {
        return res.status(500).json({
          success: false,
          message: 'Tenant not resolved'
        });
      }

      const limitCheck = await tenantService.checkTenantLimits(req.tenant.tenantId, type);

      if (limitCheck.exceeded) {
        logger.warn('Tenant limit exceeded', {
          tenantId: req.tenant.tenantId,
          type,
          current: limitCheck.current,
          limit: limitCheck.limit,
          path: req.path
        });

        return res.status(429).json({
          success: false,
          message: `Tenant ${type} limit exceeded (${limitCheck.current}/${limitCheck.limit})`
        });
      }

      // Attach limit info to request for monitoring
      req.limitInfo = limitCheck;

      logger.debug('Limit check passed', {
        tenantId: req.tenant.tenantId,
        type,
        current: limitCheck.current,
        remaining: limitCheck.remaining,
        path: req.path
      });

      next();
    } catch (error) {
      logger.error('Limit check failed', {
        error: error.message,
        tenantId: req.tenant?.tenantId,
        type,
        path: req.path
      });

      return res.status(500).json({
        success: false,
        message: 'Limit check failed'
      });
    }
  };
};

// Tenant-specific rate limiting
export const tenantRateLimit = (options = {}) => {
  const windowMs = options.windowMs || 15 * 60 * 1000; // 15 minutes
  const maxRequests = options.maxRequests || 100; // requests per window
  const skipSuccessfulRequests = options.skipSuccessfulRequests || false;

  const requests = new Map();

  return (req, res, next) => {
    if (!req.tenant) {
      return next(); // Skip if no tenant resolved
    }

    const tenantId = req.tenant.tenantId;
    const now = Date.now();
    const windowStart = now - windowMs;

    if (!requests.has(tenantId)) {
      requests.set(tenantId, []);
    }

    const tenantRequests = requests.get(tenantId);

    // Remove old requests outside the window
    const recentRequests = tenantRequests.filter(time => time > windowStart);

    if (recentRequests.length >= maxRequests) {
      logger.warn('Tenant rate limit exceeded', {
        tenantId,
        requestCount: recentRequests.length,
        maxRequests,
        path: req.path
      });

      return res.status(429).json({
        success: false,
        message: 'Rate limit exceeded for this tenant'
      });
    }

    // Add current request
    recentRequests.push(now);
    requests.set(tenantId, recentRequests);

    // Track successful requests
    if (!skipSuccessfulRequests) {
      res.on('finish', () => {
        if (res.statusCode >= 200 && res.statusCode < 400) {
          // Keep the request in the list
        } else {
          // Remove failed requests from count
          const index = recentRequests.indexOf(now);
          if (index > -1) {
            recentRequests.splice(index, 1);
          }
        }
      });
    }

    next();
  };
};

// Tenant isolation middleware (adds tenant context to database queries)
export const tenantIsolation = (req, res, next) => {
  if (!req.tenant) {
    return next();
  }

  // Add tenant context to request for use in services/models
  req.tenantContext = {
    tenantId: req.tenant.tenantId,
    tenant: req.tenant,
    database: null // For future multi-database support
  };

  // Set tenant context in async local storage for the request
  // This ensures all database operations within this request are tenant-scoped
  const asyncLocalStorage = (global.asyncLocalStorage = global.asyncLocalStorage || new Map());

  asyncLocalStorage.set(Symbol.for('tenant-context'), req.tenantContext);

  logger.debug('Tenant isolation context set', {
    tenantId: req.tenant.tenantId,
    path: req.path
  });

  next();
};

// Log tenant activity
export const logTenantActivity = (activityType) => {
  return (req, res, next) => {
    const startTime = Date.now();

    res.on('finish', () => {
      const duration = Date.now() - startTime;

      logger.info('Tenant activity', {
        activityType,
        tenantId: req.tenant?.tenantId,
        tenantName: req.tenant?.name,
        userId: req.user?._id,
        path: req.path,
        method: req.method,
        statusCode: res.statusCode,
        duration,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
    });

    next();
  };
};

// Validate tenant access to resources
export const validateTenantResource = (resourceType) => {
  return async (req, res, next) => {
    try {
      if (!req.tenant) {
        return res.status(500).json({
          success: false,
          message: 'Tenant context not available'
        });
      }

      const resourceId = req.params.id || req.params.resourceId || req.body.id;

      if (!resourceId) {
        return next(); // No specific resource to validate
      }

      // This would need to be implemented based on your resource models
      // For example, check if a Transaction belongs to the tenant
      const isValid = await validateResourceOwnership(resourceType, resourceId, req.tenant.tenantId);

      if (!isValid) {
        logger.warn('Tenant resource access denied', {
          tenantId: req.tenant.tenantId,
          resourceType,
          resourceId,
          path: req.path
        });

        return res.status(403).json({
          success: false,
          message: 'Access denied to this resource'
        });
      }

      logger.debug('Tenant resource access granted', {
        tenantId: req.tenant.tenantId,
        resourceType,
        resourceId,
        path: req.path
      });

      next();
    } catch (error) {
      logger.error('Tenant resource validation failed', {
        error: error.message,
        tenantId: req.tenant?.tenantId,
        resourceType,
        path: req.path
      });

      return res.status(500).json({
        success: false,
        message: 'Resource validation failed'
      });
    }
  };
};

// Helper function to validate resource ownership
async function validateResourceOwnership(resourceType, resourceId, tenantId) {
  try {
    // This is a placeholder - implement based on your models
    switch (resourceType) {
      case 'transaction':
        const Transaction = (await import('../models/Transaction.js')).default;
        const transaction = await Transaction.findOne({ _id: resourceId, tenantId });
        return !!transaction;

      case 'user':
        const User = (await import('../models/User.js')).default;
        const user = await User.findOne({ _id: resourceId, tenantId });
        return !!user;

      case 'analytics':
        const Analytics = (await import('../models/Analytics.js')).default;
        const analytics = await Analytics.findOne({ _id: resourceId, tenantId });
        return !!analytics;

      default:
        return true; // Allow by default for unknown resource types
    }
  } catch (error) {
    logger.error('Resource ownership validation error', {
      resourceType,
      resourceId,
      tenantId,
      error: error.message
    });
    return false;
  }
}

export default {
  resolveTenant,
  requireFeature,
  checkLimits,
  tenantRateLimit,
  tenantIsolation,
  logTenantActivity,
  validateTenantResource
};
