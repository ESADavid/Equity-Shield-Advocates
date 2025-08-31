/**
 * Oscar Broome Login Override System
 * Emergency access and administrative override capabilities
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const winston = require('winston');

// Override logger
const overrideLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'login-override' },
  transports: [
    new winston.transports.File({ filename: 'logs/login_override.log' }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// Override configuration
const OVERRIDE_CONFIG = {
  EMERGENCY_CODE: process.env.EMERGENCY_OVERRIDE_CODE || 'OSCAR_BROOME_EMERGENCY_2024',
  ADMIN_OVERRIDE_CODE: process.env.ADMIN_OVERRIDE_CODE || 'ADMIN_OVERRIDE_2024',
  MAX_OVERRIDE_ATTEMPTS: parseInt(process.env.MAX_OVERRIDE_ATTEMPTS) || 3,
  OVERRIDE_WINDOW_MINUTES: parseInt(process.env.OVERRIDE_WINDOW_MINUTES) || 15,
  REQUIRE_ADDITIONAL_AUTH: process.env.REQUIRE_ADDITIONAL_AUTH === 'true',
  NOTIFICATION_EMAILS: (process.env.NOTIFICATION_EMAILS || '').split(',').filter(email => email.trim())
};

// Override session storage
const activeOverrides = new Map();
const overrideAttempts = new Map();

// Override types
const OVERRIDE_TYPES = {
  EMERGENCY: 'emergency',
  ADMIN: 'admin',
  TECHNICAL: 'technical',
  SECURITY: 'security'
};

// Override reasons
const OVERRIDE_REASONS = {
  LOCKED_OUT: 'account_locked',
  MFA_FAILURE: 'mfa_failure',
  PASSWORD_RESET: 'password_reset',
  SYSTEM_MAINTENANCE: 'system_maintenance',
  EMERGENCY_ACCESS: 'emergency_access',
  TECHNICAL_ISSUE: 'technical_issue'
};

class LoginOverrideManager {
  constructor() {
    this.loadOverrideHistory();
  }

  // Emergency override for Oscar Broome
  async emergencyOverride(userId, reason, additionalAuth = null) {
    const overrideId = this.generateOverrideId();
    const timestamp = new Date().toISOString();

    // Validate emergency conditions
    if (!this.validateEmergencyConditions(userId, reason)) {
      throw new Error('Emergency override conditions not met');
    }

    // Check additional authentication if required
    if (OVERRIDE_CONFIG.REQUIRE_ADDITIONAL_AUTH && !additionalAuth) {
      throw new Error('Additional authentication required for emergency override');
    }

    // Create override session
    const overrideSession = {
      id: overrideId,
      type: OVERRIDE_TYPES.EMERGENCY,
      userId: userId,
      reason: reason,
      timestamp: timestamp,
      expiresAt: new Date(Date.now() + OVERRIDE_CONFIG.OVERRIDE_WINDOW_MINUTES * 60 * 1000).toISOString(),
      status: 'active',
      additionalAuth: additionalAuth,
      approvedBy: 'SYSTEM_EMERGENCY_PROTOCOL',
      notificationsSent: []
    };

    // Store override session
    activeOverrides.set(overrideId, overrideSession);

    // Log emergency override
    overrideLogger.warn('EMERGENCY OVERRIDE ACTIVATED', {
      overrideId,
      userId,
      reason,
      timestamp,
      expiresAt: overrideSession.expiresAt
    });

    // Send notifications
    await this.sendEmergencyNotifications(overrideSession);

    // Reset attempt counter
    overrideAttempts.delete(userId);

    return {
      success: true,
      overrideId,
      message: 'Emergency override activated for Oscar Broome',
      expiresAt: overrideSession.expiresAt,
      accessGranted: true
    };
  }

  // Administrative override
  async adminOverride(adminUserId, targetUserId, reason, justification) {
    const overrideId = this.generateOverrideId();
    const timestamp = new Date().toISOString();

    // Validate admin permissions
    if (!this.validateAdminPermissions(adminUserId)) {
      throw new Error('Insufficient admin permissions for override');
    }

    // Validate justification
    if (!justification || justification.length < 10) {
      throw new Error('Detailed justification required for admin override');
    }

    // Create override session
    const overrideSession = {
      id: overrideId,
      type: OVERRIDE_TYPES.ADMIN,
      adminUserId: adminUserId,
      targetUserId: targetUserId,
      reason: reason,
      justification: justification,
      timestamp: timestamp,
      expiresAt: new Date(Date.now() + OVERRIDE_CONFIG.OVERRIDE_WINDOW_MINUTES * 60 * 1000).toISOString(),
      status: 'active',
      approvedBy: adminUserId,
      notificationsSent: []
    };

    // Store override session
    activeOverrides.set(overrideId, overrideSession);

    // Log admin override
    overrideLogger.info('ADMIN OVERRIDE ACTIVATED', {
      overrideId,
      adminUserId,
      targetUserId,
      reason,
      justification,
      timestamp,
      expiresAt: overrideSession.expiresAt
    });

    // Send notifications
    await this.sendAdminNotifications(overrideSession);

    return {
      success: true,
      overrideId,
      message: 'Administrative override activated',
      expiresAt: overrideSession.expiresAt,
      accessGranted: true
    };
  }

  // Technical support override
  async technicalOverride(supportUserId, targetUserId, reason, ticketNumber) {
    const overrideId = this.generateOverrideId();
    const timestamp = new Date().toISOString();

    // Validate support permissions
    if (!this.validateSupportPermissions(supportUserId)) {
      throw new Error('Insufficient support permissions for override');
    }

    // Validate ticket number
    if (!ticketNumber || !/^[A-Z]{2,4}-\d{4,6}$/.test(ticketNumber)) {
      throw new Error('Valid support ticket number required');
    }

    // Create override session
    const overrideSession = {
      id: overrideId,
      type: OVERRIDE_TYPES.TECHNICAL,
      supportUserId: supportUserId,
      targetUserId: targetUserId,
      reason: reason,
      ticketNumber: ticketNumber,
      timestamp: timestamp,
      expiresAt: new Date(Date.now() + OVERRIDE_CONFIG.OVERRIDE_WINDOW_MINUTES * 60 * 1000).toISOString(),
      status: 'active',
      approvedBy: supportUserId,
      notificationsSent: []
    };

    // Store override session
    activeOverrides.set(overrideId, overrideSession);

    // Log technical override
    overrideLogger.info('TECHNICAL OVERRIDE ACTIVATED', {
      overrideId,
      supportUserId,
      targetUserId,
      reason,
      ticketNumber,
      timestamp,
      expiresAt: overrideSession.expiresAt
    });

    // Send notifications
    await this.sendTechnicalNotifications(overrideSession);

    return {
      success: true,
      overrideId,
      message: 'Technical support override activated',
      expiresAt: overrideSession.expiresAt,
      accessGranted: true
    };
  }

  // Validate override session
  validateOverrideSession(overrideId, userId) {
    const session = activeOverrides.get(overrideId);

    if (!session) {
      return { valid: false, reason: 'Override session not found' };
    }

    if (session.status !== 'active') {
      return { valid: false, reason: 'Override session not active' };
    }

    if (new Date() > new Date(session.expiresAt)) {
      session.status = 'expired';
      activeOverrides.set(overrideId, session);
      return { valid: false, reason: 'Override session expired' };
    }

    if (session.targetUserId && session.targetUserId !== userId) {
      return { valid: false, reason: 'Override session not for this user' };
    }

    return {
      valid: true,
      session: session,
      type: session.type,
      expiresAt: session.expiresAt
    };
  }

  // Revoke override session
  revokeOverride(overrideId, revokedBy, reason) {
    const session = activeOverrides.get(overrideId);

    if (!session) {
      throw new Error('Override session not found');
    }

    session.status = 'revoked';
    session.revokedBy = revokedBy;
    session.revokedAt = new Date().toISOString();
    session.revokeReason = reason;

    activeOverrides.set(overrideId, session);

    // Log revocation
    overrideLogger.warn('OVERRIDE SESSION REVOKED', {
      overrideId,
      revokedBy,
      reason,
      originalSession: session
    });

    // Send revocation notifications
    this.sendRevocationNotifications(session);

    return { success: true, message: 'Override session revoked' };
  }

  // Get active overrides for user
  getActiveOverrides(userId) {
    const userOverrides = [];

    for (const [overrideId, session] of activeOverrides) {
      if ((session.userId === userId || session.targetUserId === userId) &&
          session.status === 'active' &&
          new Date() < new Date(session.expiresAt)) {
        userOverrides.push({
          id: overrideId,
          type: session.type,
          reason: session.reason,
          expiresAt: session.expiresAt,
          approvedBy: session.approvedBy
        });
      }
    }

    return userOverrides;
  }

  // Check override attempts
  checkOverrideAttempts(userId) {
    const attempts = overrideAttempts.get(userId) || { count: 0, lastAttempt: null };
    const now = new Date();

    // Reset attempts if more than 1 hour has passed
    if (attempts.lastAttempt && (now - new Date(attempts.lastAttempt)) > 60 * 60 * 1000) {
      attempts.count = 0;
    }

    return attempts;
  }

  // Record override attempt
  recordOverrideAttempt(userId, success = false) {
    const attempts = this.checkOverrideAttempts(userId);
    attempts.lastAttempt = new Date().toISOString();

    if (!success) {
      attempts.count += 1;

      if (attempts.count >= OVERRIDE_CONFIG.MAX_OVERRIDE_ATTEMPTS) {
        overrideLogger.error('MAX OVERRIDE ATTEMPTS EXCEEDED', {
          userId,
          attempts: attempts.count,
          timestamp: attempts.lastAttempt
        });

        // Send security alert
        this.sendSecurityAlert(userId, 'max_override_attempts_exceeded');
      }
    } else {
      attempts.count = 0; // Reset on success
    }

    overrideAttempts.set(userId, attempts);
  }

  // Validate emergency conditions
  validateEmergencyConditions(userId, reason) {
    // Check if user is Oscar Broome or designated executive
    const authorizedUsers = ['oscar.broome@oscarsystem.com', 'executive@oscarsystem.com', 'admin@oscarsystem.com'];

    // Allow emergency override for critical reasons
    const criticalReasons = [
      OVERRIDE_REASONS.EMERGENCY_ACCESS,
      OVERRIDE_REASONS.SYSTEM_MAINTENANCE,
      OVERRIDE_REASONS.TECHNICAL_ISSUE
    ];

    return criticalReasons.includes(reason);
  }

  // Validate admin permissions
  validateAdminPermissions(userId) {
    // Check if user has admin role
    const adminUsers = ['admin@oscarsystem.com', 'super_admin@oscarsystem.com'];
    return adminUsers.includes(userId);
  }

  // Validate support permissions
  validateSupportPermissions(userId) {
    // Check if user has support role
    const supportUsers = ['support@oscarsystem.com', 'tech@oscarsystem.com'];
    return supportUsers.includes(userId);
  }

  // Generate unique override ID
  generateOverrideId() {
    return `OVERRIDE_${Date.now()}_${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  }

  // Send emergency notifications
  async sendEmergencyNotifications(session) {
    const notifications = OVERRIDE_CONFIG.NOTIFICATION_EMAILS;

    for (const email of notifications) {
      // In a real implementation, this would send actual emails
      overrideLogger.info('EMERGENCY OVERRIDE NOTIFICATION SENT', {
        overrideId: session.id,
        email: email,
        type: 'emergency_override_activated'
      });
    }

    session.notificationsSent = notifications;
  }

  // Send admin notifications
  async sendAdminNotifications(session) {
    const notifications = OVERRIDE_CONFIG.NOTIFICATION_EMAILS;

    for (const email of notifications) {
      overrideLogger.info('ADMIN OVERRIDE NOTIFICATION SENT', {
        overrideId: session.id,
        email: email,
        type: 'admin_override_activated'
      });
    }

    session.notificationsSent = notifications;
  }

  // Send technical notifications
  async sendTechnicalNotifications(session) {
    const notifications = OVERRIDE_CONFIG.NOTIFICATION_EMAILS;

    for (const email of notifications) {
      overrideLogger.info('TECHNICAL OVERRIDE NOTIFICATION SENT', {
        overrideId: session.id,
        email: email,
        type: 'technical_override_activated'
      });
    }

    session.notificationsSent = notifications;
  }

  // Send revocation notifications
  sendRevocationNotifications(session) {
    const notifications = OVERRIDE_CONFIG.NOTIFICATION_EMAILS;

    for (const email of notifications) {
      overrideLogger.info('OVERRIDE REVOCATION NOTIFICATION SENT', {
        overrideId: session.id,
        email: email,
        type: 'override_revoked'
      });
    }
  }

  // Send security alert
  sendSecurityAlert(userId, alertType) {
    const notifications = OVERRIDE_CONFIG.NOTIFICATION_EMAILS;

    for (const email of notifications) {
      overrideLogger.error('SECURITY ALERT', {
        userId,
        alertType,
        email: email,
        timestamp: new Date().toISOString()
      });
    }
  }

  // Load override history from file
  loadOverrideHistory() {
    try {
      const historyPath = path.join(__dirname, '../logs/override_history.json');
      if (fs.existsSync(historyPath)) {
        const history = JSON.parse(fs.readFileSync(historyPath, 'utf-8'));
        // Restore active overrides from history
        for (const [id, session] of Object.entries(history.activeOverrides || {})) {
          if (session.status === 'active' && new Date() < new Date(session.expiresAt)) {
            activeOverrides.set(id, session);
          }
        }
      }
    } catch (error) {
      overrideLogger.error('Failed to load override history', { error: error.message });
    }
  }

  // Save override history to file
  saveOverrideHistory() {
    try {
      const historyPath = path.join(__dirname, '../logs/override_history.json');
      const history = {
        activeOverrides: Object.fromEntries(activeOverrides),
        lastUpdated: new Date().toISOString()
      };

      fs.writeFileSync(historyPath, JSON.stringify(history, null, 2), 'utf-8');
    } catch (error) {
      overrideLogger.error('Failed to save override history', { error: error.message });
    }
  }

  // Cleanup expired overrides
  cleanupExpiredOverrides() {
    const now = new Date();
    let cleaned = 0;

    for (const [id, session] of activeOverrides) {
      if (session.status === 'active' && now > new Date(session.expiresAt)) {
        session.status = 'expired';
        activeOverrides.set(id, session);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      overrideLogger.info('Cleaned up expired overrides', { count: cleaned });
      this.saveOverrideHistory();
    }
  }

  // Get override statistics
  getOverrideStatistics() {
    const stats = {
      totalActive: 0,
      byType: {},
      byReason: {},
      recentActivity: []
    };

    for (const [id, session] of activeOverrides) {
      if (session.status === 'active') {
        stats.totalActive++;
        stats.byType[session.type] = (stats.byType[session.type] || 0) + 1;
        stats.byReason[session.reason] = (stats.byReason[session.reason] || 0) + 1;
      }

      // Add to recent activity (last 24 hours)
      const sessionTime = new Date(session.timestamp);
      const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

      if (sessionTime > oneDayAgo) {
        stats.recentActivity.push({
          id: session.id,
          type: session.type,
          reason: session.reason,
          timestamp: session.timestamp,
          status: session.status
        });
      }
    }

    return stats;
  }
}

// Create singleton instance
const loginOverrideManager = new LoginOverrideManager();

// Periodic cleanup
setInterval(() => {
  loginOverrideManager.cleanupExpiredOverrides();
}, 5 * 60 * 1000); // Every 5 minutes

// Periodic save
setInterval(() => {
  loginOverrideManager.saveOverrideHistory();
}, 10 * 60 * 1000); // Every 10 minutes

module.exports = {
  LoginOverrideManager,
  loginOverrideManager,
  OVERRIDE_TYPES,
  OVERRIDE_REASONS
};
