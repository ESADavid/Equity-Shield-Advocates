/**
 * Transaction Override Authentication Middleware (JSDoc Typed)
 * Handles authorization for transaction override operations
 * VSCode Compliance: JSDoc-only typing for .js file
 */

import logger from '../config/logger.js';

/**
 * @typedef {import('express').Request & {
 *   user?: {
 *     _id: string;
 *     role?: string;
 *   };
 *   overrideUser?: {
 *     username: string;
 *     role: string;
 *     timestamp: string;
 *   };
 * }} OverrideRequest
 *
 * @typedef {import('express').Response} Response
 * @typedef {import('express').NextFunction} NextFunction
 */

const overrideAuthConfig = {
  users: {
    admin: 'securepassword',
    override_manager: 'override123',
    super_admin: 'supersecure123',
  },
  challenge: true,
  realm: 'Transaction Override System',
};

/**
 * Role-based authorization middleware factory
 * @param {string[]} [roles=['admin','override_manager']] - Allowed roles
 * @returns {import('express').RequestHandler}
 */
const authorizeOverride = (roles = ['admin', 'override_manager']) => {
  /**
   * @param {OverrideRequest} req - Extended request
   * @param {Response} res - Express response
   * @param {NextFunction} next - Next middleware
   */
  return (req, res, next) => {
    /** @type {any} */
    const user = req.user;

    if (!user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    if (user.role && !roles.includes(user.role)) {
      res.status(403).json({
        error: 'Insufficient permissions for transaction override',
      });
      return;
    }

    req.overrideUser = {
      username: String(user._id),
      role: user.role || 'user',
      timestamp: new Date().toISOString(),
    };

    next();
  };
};

/**
 * Audit logging middleware for override endpoints
 * @param {OverrideRequest} req
 * @param {Response} res
 * @param {NextFunction} next
 */
const auditOverride = (req, res, next) => {
  const originalSend = res.send.bind(res);

  res.send = function (/** @type {any} */ body) {
    if (req.path.includes('/api/transactions/override')) {
      const auditEntry = {
        action: req.method,
        endpoint: req.path,
        user: req.overrideUser?.username || 'unknown',
        ip: req.ip,
        userAgent: req.get('User-Agent') || 'unknown',
        timestamp: new Date().toISOString(),
        body: req.method !== 'GET' ? req.body : null,
      };

      logger.info('Transaction Override AUDIT', auditEntry);
    }

    return originalSend(body);
  };

  next();
};

export { overrideAuthConfig, authorizeOverride, auditOverride };



