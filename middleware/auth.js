import authService from '../services/authService.js';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'auth-middleware' },
  transports: [
    new winston.transports.File({ filename: 'logs/auth-middleware.log' }),
    new winston.transports.File({ filename: 'logs/auth-middleware-error.log', level: 'error' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Authenticate JWT token
export const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access token required'
      });
    }

    const { user, tokenData } = await authService.verifyToken(token);

    // Attach user to request
    req.user = user;
    req.tokenData = tokenData;

    logger.debug('Authentication successful', { userId: user._id, path: req.path });
    next();
  } catch (error) {
    logger.error('Authentication failed', {
      error: error.message,
      path: req.path,
      ip: req.ip
    });

    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token'
    });
  }
};

// Optional authentication (doesn't fail if no token)
export const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
      const { user, tokenData } = await authService.verifyToken(token);
      req.user = user;
      req.tokenData = tokenData;
    }

    next();
  } catch (error) {
    // Don't fail, just continue without user
    logger.debug('Optional authentication failed, continuing without user', {
      error: error.message,
      path: req.path
    });
    next();
  }
};

// Check if user has required permission
export const requirePermission = (permission) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required'
        });
      }

      const hasPermission = await authService.checkPermission(req.user._id, permission);

      if (!hasPermission) {
        logger.warn('Permission denied', {
          userId: req.user._id,
          permission,
          path: req.path
        });

        return res.status(403).json({
          success: false,
          message: 'Insufficient permissions'
        });
      }

      logger.debug('Permission granted', {
        userId: req.user._id,
        permission,
        path: req.path
      });

      next();
    } catch (error) {
      logger.error('Permission check failed', {
        error: error.message,
        userId: req.user?._id,
        permission,
        path: req.path
      });

      return res.status(500).json({
        success: false,
        message: 'Permission check failed'
      });
    }
  };
};

// Check if user has any of the required permissions
export const requireAnyPermission = (...permissions) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required'
        });
      }

      let hasPermission = false;
      for (const permission of permissions) {
        if (await authService.checkPermission(req.user._id, permission)) {
          hasPermission = true;
          break;
        }
      }

      if (!hasPermission) {
        logger.warn('Permission denied (any)', {
          userId: req.user._id,
          permissions,
          path: req.path
        });

        return res.status(403).json({
          success: false,
          message: 'Insufficient permissions'
        });
      }

      logger.debug('Permission granted (any)', {
        userId: req.user._id,
        permissions,
        path: req.path
      });

      next();
    } catch (error) {
      logger.error('Permission check failed (any)', {
        error: error.message,
        userId: req.user?._id,
        permissions,
        path: req.path
      });

      return res.status(500).json({
        success: false,
        message: 'Permission check failed'
      });
    }
  };
};

// Check if user has required role
export const requireRole = (role) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    if (req.user.role !== role && req.user.role !== 'admin') {
      logger.warn('Role check failed', {
        userId: req.user._id,
        userRole: req.user.role,
        requiredRole: role,
        path: req.path
      });

      return res.status(403).json({
        success: false,
        message: `Role '${role}' required`
      });
    }

    logger.debug('Role check passed', {
      userId: req.user._id,
      role: req.user.role,
      path: req.path
    });

    next();
  };
};

// Check if user has any of the required roles
export const requireAnyRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    if (!roles.includes(req.user.role) && req.user.role !== 'admin') {
      logger.warn('Role check failed (any)', {
        userId: req.user._id,
        userRole: req.user.role,
        requiredRoles: roles,
        path: req.path
      });

      return res.status(403).json({
        success: false,
        message: `One of roles [${roles.join(', ')}] required`
      });
    }

    logger.debug('Role check passed (any)', {
      userId: req.user._id,
      role: req.user.role,
      path: req.path
    });

    next();
  };
};

// Rate limiting for auth endpoints
export const authRateLimit = (req, res, next) => {
  // Simple in-memory rate limiting (in production, use Redis or similar)
  const clientId = req.ip;
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const maxRequests = 5; // 5 requests per window

  if (!global.authRateLimit) {
    global.authRateLimit = new Map();
  }

  const now = Date.now();
  const windowStart = now - windowMs;

  if (!global.authRateLimit.has(clientId)) {
    global.authRateLimit.set(clientId, []);
  }

  const requests = global.authRateLimit.get(clientId);
  const recentRequests = requests.filter(time => time > windowStart);

  if (recentRequests.length >= maxRequests) {
    logger.warn('Rate limit exceeded', { clientId, path: req.path });
    return res.status(429).json({
      success: false,
      message: 'Too many authentication attempts. Please try again later.'
    });
  }

  recentRequests.push(now);
  global.authRateLimit.set(clientId, recentRequests);

  next();
};

// Log authentication events
export const logAuthEvent = (eventType) => {
  return (req, res, next) => {
    const startTime = Date.now();

    res.on('finish', () => {
      const duration = Date.now() - startTime;
      logger.info('Auth event', {
        eventType,
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

// Validate request body for auth endpoints
export const validateAuthRequest = (schema) => {
  return (req, res, next) => {
    // Basic validation - in production, use a proper validation library like Joi
    const errors = [];

    if (schema.username && (!req.body.username || req.body.username.length < 3)) {
      errors.push('Username must be at least 3 characters long');
    }

    if (schema.email && (!req.body.email || !req.body.email.includes('@'))) {
      errors.push('Valid email is required');
    }

    if (schema.password && (!req.body.password || req.body.password.length < 6)) {
      errors.push('Password must be at least 6 characters long');
    }

    if (errors.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors
      });
    }

    next();
  };
};
