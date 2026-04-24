/**
 * Transaction Override Authentication Middleware
 * Handles authorization for transaction override operations
 */

import logger from '../config/logger.js';

/**
 * @typedef {import('express').Request} ExpressRequest
 * @typedef {import('express').Response} ExpressResponse
 * @typedef {import('express').NextFunction} ExpressNextFunction
 */

// Enhanced auth configuration for override operations
const overrideAuthConfig = {
  users: {
    admin: 'securepassword',
    override_manager: 'override123',
    super_admin: 'supersecure123',
  },
  challenge: true,
  realm: 'Transaction Override System',
};

// Role-based authorization
const authorizeOverride = (roles = ['admin', 'override_manager']) => {
  /**
   * @param {import('express').Request} req
   * @param {import('express').Response} res 
   * @param {import('express').NextFunction} next 
   */
  /**
   * @param {ExpressRequest} req
   * @param {ExpressResponse} res 
   * @param {ExpressNextFunction} next 
   */
  return (req, res, next) => {
    const user = req.user;

    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // Check if user has required role
    if (user.role && !roles.includes(user.role)) {
      return res.status(403).json({
        error: 'Insufficient permissions for transaction override',
      });
    }

    // Add user info to request
    req.overrideUser = {
      username: String(user._id),
      role: user.role || 'user',
      timestamp: new Date().toISOString(),
    };

    next();
  };

};

/**
 * @param {ExpressRequest} req 
 * @param {ExpressResponse} res 
 * @param {ExpressNextFunction} next 
 */
const auditOverride = (req, res, next) => {
  const originalSend = res.send;

  res.send = function (/** @type {any} body */ body) {
    // Log override attempt
    if (req.path.includes('/api/transactions/override')) {
      const auditEntry = {
        action: req.method,
        endpoint: req.path,
        user: req.overrideUser?.username || 'unknown',
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        body: req.method !== 'GET' ? req.body : null,
      };

      // In production, save to audit log
      logger.info('AUDIT:', auditEntry);
    }

    return originalSend.call(this, body);
  };


  next();
};

export { overrideAuthConfig, authorizeOverride, auditOverride };

