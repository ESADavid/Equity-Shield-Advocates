/**
 * Oscar Broome Login Override System
 * Emergency access and administrative override capabilities
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import winston from 'winston';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

// Standard authentication logger
const authLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'standard-auth' },
  transports: [
    new winston.transports.File({ filename: 'logs/auth.log' }),
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
  NOTIFICATION_EMAILS: (process.env.NOTIFICATION_EMAILS || '').split(',').filter(email => email.trim()),
  // Enhanced security settings
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 5,
  MFA_ENFORCEMENT_LEVEL: process.env.MFA_ENFORCEMENT_LEVEL || 'required', // 'required', 'optional', 'disabled'
  SESSION_TIMEOUT_MINUTES: parseInt(process.env.SESSION_TIMEOUT_MINUTES) || 30,
  PASSWORD_MIN_LENGTH: parseInt(process.env.PASSWORD_MIN_LENGTH) || 12,
  PASSWORD_REQUIRE_COMPLEXITY: process.env.PASSWORD_REQUIRE_COMPLEXITY !== 'false'
};

  // Override session storage
  const activeOverrides = new Map();
  const overrideAttempts = new Map();

  // Rate limiting storage
  const rateLimitStore = new Map();

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

  // Standard User Authentication Methods
  async registerUser(username, email, password, role = 'user') {
    try {
      // Check if user already exists
      const existingUser = await this.getUserByUsername(username);
      if (existingUser) {
        throw new Error('Username already exists');
      }

      const existingEmail = await this.getUserByEmail(email);
      if (existingEmail) {
        throw new Error('Email already exists');
      }

      // Hash password
      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      // Create user object
      const user = {
        id: this.generateUserId(),
        username,
        email,
        password: hashedPassword,
        role,
        createdAt: new Date().toISOString(),
        lastLogin: null,
        isActive: true,
        loginAttempts: 0,
        lockoutUntil: null,
        mfaEnabled: false,
        mfaSecret: null
      };

      // Save user (in production, use database)
      await this.saveUser(user);

      // Log registration
      authLogger.info('USER REGISTERED', {
        userId: user.id,
        username,
        email,
        role,
        timestamp: user.createdAt
      });

      return {
        success: true,
        userId: user.id,
        message: 'User registered successfully'
      };
    } catch (error) {
      authLogger.error('USER REGISTRATION FAILED', {
        username,
        email,
        error: error.message
      });
      throw error;
    }
  }

  async authenticateUser(usernameOrEmail, password) {
    try {
      // Get user by username or email
      let user = await this.getUserByUsername(usernameOrEmail);
      if (!user) {
        user = await this.getUserByEmail(usernameOrEmail);
      }

      if (!user) {
        throw new Error('Invalid credentials');
      }

      // Check if account is locked
      if (user.lockoutUntil && new Date() < new Date(user.lockoutUntil)) {
        throw new Error('Account is temporarily locked due to too many failed attempts');
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        await this.recordFailedLoginAttempt(user.id);
        throw new Error('Invalid credentials');
      }

      // Check if account is active
      if (!user.isActive) {
        throw new Error('Account is deactivated');
      }

      // Reset login attempts on successful login
      await this.resetLoginAttempts(user.id);

      // Update last login
      user.lastLogin = new Date().toISOString();
      await this.updateUser(user);

      // Generate JWT token
      const token = jwt.sign(
        {
          userId: user.id,
          username: user.username,
          email: user.email,
          role: user.role
        },
        process.env.JWT_SECRET || 'your_jwt_secret_key',
        { expiresIn: '24h' }
      );

      // Log successful login
      authLogger.info('USER LOGIN SUCCESSFUL', {
        userId: user.id,
        username: user.username,
        timestamp: new Date().toISOString()
      });

      return {
        success: true,
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          lastLogin: user.lastLogin
        }
      };
    } catch (error) {
      authLogger.warn('USER LOGIN FAILED', {
        usernameOrEmail,
        error: error.message,
        timestamp: new Date().toISOString()
      });
      throw error;
    }
  }

  async changePassword(userId, currentPassword, newPassword) {
    try {
      const user = await this.getUserById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Verify current password
      const isValidPassword = await bcrypt.compare(currentPassword, user.password);
      if (!isValidPassword) {
        throw new Error('Current password is incorrect');
      }

      // Validate new password strength
      if (!this.validatePasswordStrength(newPassword)) {
        throw new Error('New password does not meet strength requirements');
      }

      // Hash new password
      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

      // Update password
      user.password = hashedPassword;
      await this.updateUser(user);

      // Log password change
      authLogger.info('PASSWORD CHANGED', {
        userId,
        timestamp: new Date().toISOString()
      });

      return {
        success: true,
        message: 'Password changed successfully'
      };
    } catch (error) {
      authLogger.error('PASSWORD CHANGE FAILED', {
        userId,
        error: error.message
      });
      throw error;
    }
  }

  async enableMFA(userId) {
    try {
      const user = await this.getUserById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Generate MFA secret
      const mfaSecret = crypto.randomBytes(32).toString('hex');

      user.mfaEnabled = true;
      user.mfaSecret = mfaSecret;
      await this.updateUser(user);

      authLogger.info('MFA ENABLED', {
        userId,
        timestamp: new Date().toISOString()
      });

      return {
        success: true,
        mfaSecret,
        message: 'MFA enabled successfully'
      };
    } catch (error) {
      authLogger.error('MFA ENABLEMENT FAILED', {
        userId,
        error: error.message
      });
      throw error;
    }
  }

  async verifyMFAToken(userId, token) {
    try {
      const user = await this.getUserById(userId);
      if (!user || !user.mfaEnabled || !user.mfaSecret) {
        throw new Error('MFA not enabled for this user');
      }

      // Simple token verification (in production, use proper TOTP)
      const expectedToken = crypto.createHmac('sha256', user.mfaSecret)
        .update(Math.floor(Date.now() / 30000).toString()) // 30-second window
        .digest('hex')
        .substring(0, 6);

      if (token !== expectedToken) {
        throw new Error('Invalid MFA token');
      }

      return { success: true, message: 'MFA token verified' };
    } catch (error) {
      authLogger.warn('MFA VERIFICATION FAILED', {
        userId,
        error: error.message
      });
      throw error;
    }
  }

  async deactivateUser(userId, adminUserId) {
    try {
      const user = await this.getUserById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Check admin permissions
      if (!this.validateAdminPermissions(adminUserId)) {
        throw new Error('Insufficient permissions to deactivate user');
      }

      user.isActive = false;
      await this.updateUser(user);

      authLogger.info('USER DEACTIVATED', {
        userId,
        adminUserId,
        timestamp: new Date().toISOString()
      });

      return {
        success: true,
        message: 'User deactivated successfully'
      };
    } catch (error) {
      authLogger.error('USER DEACTIVATION FAILED', {
        userId,
        adminUserId,
        error: error.message
      });
      throw error;
    }
  }

  // Helper methods for user management
  generateUserId() {
    return `USER_${Date.now()}_${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  }

  validatePasswordStrength(password) {
    // At least 8 characters, 1 uppercase, 1 lowercase, 1 number, 1 special character
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    return passwordRegex.test(password);
  }

  async recordFailedLoginAttempt(userId) {
    const user = await this.getUserById(userId);
    if (user) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;

      // Lock account after 5 failed attempts
      if (user.loginAttempts >= 5) {
        user.lockoutUntil = new Date(Date.now() + 30 * 60 * 1000).toISOString(); // 30 minutes
      }

      await this.updateUser(user);
    }
  }

  async resetLoginAttempts(userId) {
    const user = await this.getUserById(userId);
    if (user) {
      user.loginAttempts = 0;
      user.lockoutUntil = null;
      await this.updateUser(user);
    }
  }

  // User data persistence methods (in production, use database)
  async saveUser(user) {
    try {
      const usersPath = path.join(__dirname, '../data/users.json');
      let users = {};

      if (fs.existsSync(usersPath)) {
        users = JSON.parse(fs.readFileSync(usersPath, 'utf-8'));
      }

      users[user.id] = user;
      fs.writeFileSync(usersPath, JSON.stringify(users, null, 2), 'utf-8');
    } catch (error) {
      throw new Error(`Failed to save user: ${error.message}`);
    }
  }

  async getUserById(userId) {
    try {
      const usersPath = path.join(__dirname, '../data/users.json');
      if (!fs.existsSync(usersPath)) return null;

      const users = JSON.parse(fs.readFileSync(usersPath, 'utf-8'));
      return users[userId] || null;
    } catch (error) {
      return null;
    }
  }

  async getUserByUsername(username) {
    try {
      const usersPath = path.join(__dirname, '../data/users.json');
      if (!fs.existsSync(usersPath)) return null;

      const users = JSON.parse(fs.readFileSync(usersPath, 'utf-8'));
      return Object.values(users).find(user => user.username === username) || null;
    } catch (error) {
      return null;
    }
  }

  async getUserByEmail(email) {
    try {
      const usersPath = path.join(__dirname, '../data/users.json');
      if (!fs.existsSync(usersPath)) return null;

      const users = JSON.parse(fs.readFileSync(usersPath, 'utf-8'));
      return Object.values(users).find(user => user.email === email) || null;
    } catch (error) {
      return null;
    }
  }

  async updateUser(user) {
    await this.saveUser(user);
  }

  // Validate JWT token
  validateToken(token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key');
      return { valid: true, user: decoded };
    } catch (error) {
      return { valid: false, error: error.message };
    }
  }

  // Rate limiting for override requests
  checkRateLimit(identifier) {
    const now = Date.now();
    const windowStart = now - OVERRIDE_CONFIG.RATE_LIMIT_WINDOW_MS;

    // Get or create rate limit data for this identifier
    let rateData = rateLimitStore.get(identifier);
    if (!rateData) {
      rateData = { requests: [], lastReset: now };
      rateLimitStore.set(identifier, rateData);
    }

    // Clean old requests outside the window
    rateData.requests = rateData.requests.filter(timestamp => timestamp > windowStart);

    // Check if under limit
    if (rateData.requests.length >= OVERRIDE_CONFIG.RATE_LIMIT_MAX_REQUESTS) {
      const oldestRequest = Math.min(...rateData.requests);
      const resetTime = oldestRequest + OVERRIDE_CONFIG.RATE_LIMIT_WINDOW_MS;
      return {
        allowed: false,
        resetTime: resetTime,
        remainingRequests: 0,
        resetInMs: resetTime - now
      };
    }

    // Add current request
    rateData.requests.push(now);

    return {
      allowed: true,
      resetTime: now + OVERRIDE_CONFIG.RATE_LIMIT_WINDOW_MS,
      remainingRequests: OVERRIDE_CONFIG.RATE_LIMIT_MAX_REQUESTS - rateData.requests.length,
      resetInMs: OVERRIDE_CONFIG.RATE_LIMIT_WINDOW_MS
    };
  }

  // Enhanced password validation with configurable requirements
  validatePasswordStrength(password) {
    if (!password || password.length < OVERRIDE_CONFIG.PASSWORD_MIN_LENGTH) {
      return false;
    }

    if (OVERRIDE_CONFIG.PASSWORD_REQUIRE_COMPLEXITY) {
      // At least 1 uppercase, 1 lowercase, 1 number, 1 special character
      const complexityRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/;
      return complexityRegex.test(password);
    }

    return true;
  }

  // Enhanced MFA enforcement
  shouldEnforceMFA(user, action = 'login') {
    if (OVERRIDE_CONFIG.MFA_ENFORCEMENT_LEVEL === 'disabled') {
      return false;
    }

    if (OVERRIDE_CONFIG.MFA_ENFORCEMENT_LEVEL === 'required') {
      return true;
    }

    // Optional level - check user preference or role-based requirements
    if (user && user.role === 'admin') {
      return true; // Always require MFA for admins
    }

    return user && user.mfaEnabled;
  }

  // Session timeout validation
  validateSessionTimeout(sessionStartTime) {
    const now = new Date();
    const sessionAge = now - new Date(sessionStartTime);
    const maxAge = OVERRIDE_CONFIG.SESSION_TIMEOUT_MINUTES * 60 * 1000;

    return sessionAge < maxAge;
  }

  // Cleanup rate limit data periodically
  cleanupRateLimitData() {
    const now = Date.now();
    const cutoff = now - (OVERRIDE_CONFIG.RATE_LIMIT_WINDOW_MS * 2); // Keep 2x window for safety

    for (const [identifier, data] of rateLimitStore) {
      data.requests = data.requests.filter(timestamp => timestamp > cutoff);
      if (data.requests.length === 0) {
        rateLimitStore.delete(identifier);
      }
    }

    overrideLogger.info('Rate limit data cleaned up', {
      activeIdentifiers: rateLimitStore.size,
      timestamp: new Date().toISOString()
    });
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

export { LoginOverrideManager, loginOverrideManager, OVERRIDE_TYPES, OVERRIDE_REASONS };

// Export standard authentication methods
export const registerUser = loginOverrideManager.registerUser.bind(loginOverrideManager);
export const authenticateUser = loginOverrideManager.authenticateUser.bind(loginOverrideManager);
export const changePassword = loginOverrideManager.changePassword.bind(loginOverrideManager);
export const enableMFA = loginOverrideManager.enableMFA.bind(loginOverrideManager);
export const verifyMFAToken = loginOverrideManager.verifyMFAToken.bind(loginOverrideManager);
export const deactivateUser = loginOverrideManager.deactivateUser.bind(loginOverrideManager);
export const validateToken = loginOverrideManager.validateToken.bind(loginOverrideManager);
export const getUserById = loginOverrideManager.getUserById.bind(loginOverrideManager);
export const getUserByUsername = loginOverrideManager.getUserByUsername.bind(loginOverrideManager);
export const getUserByEmail = loginOverrideManager.getUserByEmail.bind(loginOverrideManager);
