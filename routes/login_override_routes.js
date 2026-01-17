/**
 * Login Override API Routes
 * Emergency access and administrative override endpoints
 */

const express = require('express');
const {
  loginOverrideManager,
  OVERRIDE_TYPES,
  OVERRIDE_REASONS,
} = require('../auth/login_override');
const winston = require('winston');

// Override API logger
const apiLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'login-override-api' },
  transports: [
    new winston.transports.File({ filename: 'logs/login_override_api.log' }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
  ],
});

const router = express.Router();

// Middleware to validate override requests
const validateOverrideRequest = (req, res, next) => {
  const { userId, reason, type } = req.body;

  if (!userId || !reason) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: userId and reason',
      code: 'VALIDATION_ERROR',
    });
  }

  // Validate reason
  const validReasons = Object.values(OVERRIDE_REASONS);
  if (!validReasons.includes(reason)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid override reason',
      code: 'INVALID_REASON',
      validReasons: validReasons,
    });
  }

  // Validate type if provided
  if (type) {
    const validTypes = Object.values(OVERRIDE_TYPES);
    if (!validTypes.includes(type)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid override type',
        code: 'INVALID_TYPE',
        validTypes: validTypes,
      });
    }
  }

  next();
};

// Middleware to check admin permissions
const requireAdmin = (req, res, next) => {
  // In a real implementation, this would check JWT token or session
  // For now, we'll use a simple header check
  const adminToken = req.headers['x-admin-token'];

  if (!adminToken || adminToken !== process.env.ADMIN_OVERRIDE_TOKEN) {
    return res.status(403).json({
      success: false,
      error: 'Admin authentication required',
      code: 'ADMIN_REQUIRED',
    });
  }

  next();
};

// Emergency override endpoint
router.post('/emergency', validateOverrideRequest, async (req, res) => {
  try {
    const { userId, reason, additionalAuth, emergencyCode } = req.body;

    // Validate emergency code
    const expectedCode =
      process.env.EMERGENCY_OVERRIDE_CODE || 'OSCAR_BROOME_EMERGENCY_2024';
    if (emergencyCode !== expectedCode) {
      loginOverrideManager.recordOverrideAttempt(userId, false);

      apiLogger.warn('Invalid emergency override code attempted', {
        userId,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
      });

      return res.status(403).json({
        success: false,
        error: 'Invalid emergency override code',
        code: 'INVALID_EMERGENCY_CODE',
      });
    }

    // Check override attempts
    const attempts = loginOverrideManager.checkOverrideAttempts(userId);
    if (attempts.count >= 3) {
      return res.status(429).json({
        success: false,
        error:
          'Too many override attempts. Please contact system administrator.',
        code: 'MAX_ATTEMPTS_EXCEEDED',
      });
    }

    const result = await loginOverrideManager.emergencyOverride(
      userId,
      reason,
      additionalAuth
    );

    loginOverrideManager.recordOverrideAttempt(userId, true);

    apiLogger.info('Emergency override successful', {
      userId,
      overrideId: result.overrideId,
      ip: req.ip,
    });

    res.json({
      success: true,
      message: result.message,
      data: {
        overrideId: result.overrideId,
        expiresAt: result.expiresAt,
        accessGranted: result.accessGranted,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    apiLogger.error('Emergency override failed', {
      userId: req.body.userId,
      error: error.message,
      ip: req.ip,
    });

    res.status(500).json({
      success: false,
      error: error.message,
      code: 'EMERGENCY_OVERRIDE_FAILED',
      timestamp: new Date().toISOString(),
    });
  }
});

// Administrative override endpoint
router.post(
  '/admin',
  requireAdmin,
  validateOverrideRequest,
  async (req, res) => {
    try {
      const { adminUserId, targetUserId, reason, justification } = req.body;

      if (!justification || justification.length < 10) {
        return res.status(400).json({
          success: false,
          error: 'Detailed justification required (minimum 10 characters)',
          code: 'JUSTIFICATION_REQUIRED',
        });
      }

      const result = await loginOverrideManager.adminOverride(
        adminUserId,
        targetUserId,
        reason,
        justification
      );

      apiLogger.info('Admin override successful', {
        adminUserId,
        targetUserId,
        overrideId: result.overrideId,
        ip: req.ip,
      });

      res.json({
        success: true,
        message: result.message,
        data: {
          overrideId: result.overrideId,
          expiresAt: result.expiresAt,
          accessGranted: result.accessGranted,
        },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      apiLogger.error('Admin override failed', {
        adminUserId: req.body.adminUserId,
        targetUserId: req.body.targetUserId,
        error: error.message,
        ip: req.ip,
      });

      res.status(500).json({
        success: false,
        error: error.message,
        code: 'ADMIN_OVERRIDE_FAILED',
        timestamp: new Date().toISOString(),
      });
    }
  }
);

// Technical support override endpoint
router.post('/technical', validateOverrideRequest, async (req, res) => {
  try {
    const { supportUserId, targetUserId, reason, ticketNumber } = req.body;

    if (!ticketNumber || !/^[A-Z]{2,4}-\d{4,6}$/.test(ticketNumber)) {
      return res.status(400).json({
        success: false,
        error: 'Valid support ticket number required (format: ABCD-1234)',
        code: 'INVALID_TICKET_NUMBER',
      });
    }

    const result = await loginOverrideManager.technicalOverride(
      supportUserId,
      targetUserId,
      reason,
      ticketNumber
    );

    apiLogger.info('Technical override successful', {
      supportUserId,
      targetUserId,
      ticketNumber,
      overrideId: result.overrideId,
      ip: req.ip,
    });

    res.json({
      success: true,
      message: result.message,
      data: {
        overrideId: result.overrideId,
        expiresAt: result.expiresAt,
        accessGranted: result.accessGranted,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    apiLogger.error('Technical override failed', {
      supportUserId: req.body.supportUserId,
      targetUserId: req.body.targetUserId,
      ticketNumber: req.body.ticketNumber,
      error: error.message,
      ip: req.ip,
    });

    res.status(500).json({
      success: false,
      error: error.message,
      code: 'TECHNICAL_OVERRIDE_FAILED',
      timestamp: new Date().toISOString(),
    });
  }
});

// Validate override session endpoint
router.post('/validate/:overrideId', async (req, res) => {
  try {
    const { overrideId } = req.params;
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({
        success: false,
        error: 'userId is required',
        code: 'USER_ID_REQUIRED',
      });
    }

    const validation = loginOverrideManager.validateOverrideSession(
      overrideId,
      userId
    );

    if (!validation.valid) {
      return res.status(403).json({
        success: false,
        error: validation.reason,
        code: 'OVERRIDE_INVALID',
        timestamp: new Date().toISOString(),
      });
    }

    res.json({
      success: true,
      message: 'Override session is valid',
      data: {
        type: validation.type,
        expiresAt: validation.expiresAt,
        valid: true,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    apiLogger.error('Override validation failed', {
      overrideId: req.params.overrideId,
      userId: req.body.userId,
      error: error.message,
      ip: req.ip,
    });

    res.status(500).json({
      success: false,
      error: error.message,
      code: 'VALIDATION_FAILED',
      timestamp: new Date().toISOString(),
    });
  }
});

// Revoke override session endpoint
router.post('/revoke/:overrideId', requireAdmin, async (req, res) => {
  try {
    const { overrideId } = req.params;
    const { revokedBy, reason } = req.body;

    if (!revokedBy || !reason) {
      return res.status(400).json({
        success: false,
        error: 'revokedBy and reason are required',
        code: 'MISSING_REVOCATION_DATA',
      });
    }

    const result = loginOverrideManager.revokeOverride(
      overrideId,
      revokedBy,
      reason
    );

    apiLogger.info('Override session revoked', {
      overrideId,
      revokedBy,
      reason,
      ip: req.ip,
    });

    res.json({
      success: true,
      message: result.message,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    apiLogger.error('Override revocation failed', {
      overrideId: req.params.overrideId,
      revokedBy: req.body.revokedBy,
      error: error.message,
      ip: req.ip,
    });

    res.status(500).json({
      success: false,
      error: error.message,
      code: 'REVOCATION_FAILED',
      timestamp: new Date().toISOString(),
    });
  }
});

// Get active overrides for user endpoint
router.get('/active/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const activeOverrides = loginOverrideManager.getActiveOverrides(userId);

    res.json({
      success: true,
      data: {
        userId,
        activeOverrides,
        count: activeOverrides.length,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    apiLogger.error('Failed to get active overrides', {
      userId: req.params.userId,
      error: error.message,
      ip: req.ip,
    });

    res.status(500).json({
      success: false,
      error: error.message,
      code: 'GET_ACTIVE_OVERRIDES_FAILED',
      timestamp: new Date().toISOString(),
    });
  }
});

// Get override statistics endpoint
router.get('/stats', requireAdmin, async (req, res) => {
  try {
    const stats = loginOverrideManager.getOverrideStatistics();

    res.json({
      success: true,
      data: stats,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    apiLogger.error('Failed to get override statistics', {
      error: error.message,
      ip: req.ip,
    });

    res.status(500).json({
      success: false,
      error: error.message,
      code: 'GET_STATS_FAILED',
      timestamp: new Date().toISOString(),
    });
  }
});

// Get override configuration endpoint
router.get('/config', requireAdmin, async (req, res) => {
  try {
    const config = {
      maxAttempts: process.env.MAX_OVERRIDE_ATTEMPTS || 3,
      windowMinutes: process.env.OVERRIDE_WINDOW_MINUTES || 15,
      requireAdditionalAuth: process.env.REQUIRE_ADDITIONAL_AUTH === 'true',
      notificationEmails: (process.env.NOTIFICATION_EMAILS || '')
        .split(',')
        .filter((email) => email.trim()),
      emergencyCodeRequired: true,
      adminOverrideCodeRequired: true,
    };

    res.json({
      success: true,
      data: config,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    apiLogger.error('Failed to get override configuration', {
      error: error.message,
      ip: req.ip,
    });

    res.status(500).json({
      success: false,
      error: error.message,
      code: 'GET_CONFIG_FAILED',
      timestamp: new Date().toISOString(),
    });
  }
});

// Health check for override system
router.get('/health', async (req, res) => {
  try {
    const stats = loginOverrideManager.getOverrideStatistics();

    res.json({
      success: true,
      message: 'Login override system is operational',
      data: {
        status: 'healthy',
        activeOverrides: stats.totalActive,
        systemTime: new Date().toISOString(),
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    apiLogger.error('Override system health check failed', {
      error: error.message,
      ip: req.ip,
    });

    res.status(500).json({
      success: false,
      error: 'Override system health check failed',
      code: 'HEALTH_CHECK_FAILED',
      timestamp: new Date().toISOString(),
    });
  }
});

module.exports = router;
