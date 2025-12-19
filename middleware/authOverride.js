/**
 * Transaction Override Authentication Middleware
 * Handles authorization for transaction override operations
 */

import express from 'express';
import basicAuth from 'express-basic-auth';

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
  return (req, res, next) => {
    const user = req.auth?.user;

    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // Check if user has required role
    if (!roles.includes(user)) {
      return res.status(403).json({
        error: 'Insufficient permissions for transaction override',
      });
    }

    // Add user info to request
    req.overrideUser = {
      username: user,
      role: user,
      timestamp: new Date().toISOString(),
    };

    next();
  };
};

// Audit logging middleware
const auditOverride = (req, res, next) => {
  const originalSend = res.send;

  res.send = function (body) {
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

    originalSend.call(this, body);
  };

  next();
};

export { overrideAuthConfig, authorizeOverride, auditOverride };
