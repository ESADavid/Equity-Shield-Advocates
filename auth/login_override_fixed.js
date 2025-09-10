/**
 * Oscar Broome Login Override System
 * Emergency access and administrative override capabilities
 */

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const winston = require('winston');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

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
  defaultMeta: { service: 'auth-system' },
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

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || crypto.randomBytes(64).toString('hex');
const MFA_SECRET = process.env.MFA_SECRET || crypto.randomBytes(32).toString('hex');
const ADMIN_OVERRIDE_CODE = process.env.ADMIN_OVERRIDE_CODE || 'OSCAR_BROOME_EMERGENCY_2024';

// In-memory user store (in production, use database)
const users = new Map();
const sessions = new Map();
const overrideCodes = new Map();

// Rate limiting
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

class AuthenticationManager {
  constructor() {
    this.initializeDefaultUsers();
  }

  async initializeDefaultUsers() {
    // Create default admin user
    const adminPassword = await bcrypt.hash('OscarBroome2024!', 12);
    users.set('admin@oscarbroomerevenue.com', {
      id: 'admin-001',
      email: 'admin@oscarbroomerevenue.com',
      password: adminPassword,
      role: 'admin',
      mfaEnabled: true,
      mfaSecret: MFA_SECRET,
      lastLogin: null,
      loginAttempts: 0,
      locked: false,
      permissions: ['read', 'write', 'delete', 'admin']
    });

    // Create executive user
    const execPassword = await bcrypt.hash('Executive2024!', 12);
    users.set('executive@oscarbroomerevenue.com', {
      id: 'exec-001',
      email: 'executive@oscarbroomerevenue.com',
      password: execPassword,
      role: 'executive',
      mfaEnabled: true,
      mfaSecret: crypto.randomBytes(32).toString('hex'),
      lastLogin: null,
      loginAttempts: 0,
      locked: false,
      permissions: ['read', 'write']
    });

    authLogger.info('Default users initialized');
  }

  async authenticateUser(email, password, mfaCode = null) {
    try {
      // Check rate limiting
      if (this.isAccountLocked(email)) {
        authLogger.warn(`Login attempt for locked account: ${email}`);
        return { success: false, message: 'Account is temporarily locked due to too many failed attempts' };
      }

      const user = users.get(email);
      if (!user) {
        authLogger.warn(`Login attempt for non-existent user: ${email}`);
        this.recordFailedAttempt(email);
        return { success: false, message: 'Invalid credentials' };
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        authLogger.warn(`Invalid password for user: ${email}`);
        this.recordFailedAttempt(email);
        return { success: false, message: 'Invalid credentials' };
      }

      // Check MFA if enabled
      if (user.mfaEnabled) {
        if (!mfaCode) {
          return { success: false, message: 'MFA code required', requiresMfa: true };
        }

        const isValidMfa = this.verifyMfaCode(user.mfaSecret, mfaCode);
        if (!isValidMfa) {
          authLogger.warn(`Invalid MFA code for user: ${email}`);
          this.recordFailedAttempt(email);
          return { success: false, message: 'Invalid MFA code' };
        }
      }

      // Reset login attempts on successful login
      user.loginAttempts = 0;
      user.lastLogin = new Date();
      users.set(email, user);

      // Generate tokens
      const tokens = this.generateTokens(user);

      // Store session
      sessions.set(tokens.accessToken, {
        userId: user.id,
        email: user.email,
        role: user.role,
        permissions: user.permissions,
        expiresAt: Date.now() + (15 * 60 * 1000) // 15 minutes
      });

      authLogger.info(`Successful login for user: ${email}`);
      return {
        success: true,
        message: 'Login successful',
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          permissions: user.permissions
        },
        tokens
      };

    } catch (error) {
      authLogger.error(`Authentication error for ${email}: ${error.message}`);
      return { success: false, message: 'Authentication failed' };
    }
  }

  async adminOverride(overrideCode, targetEmail) {
    try {
      if (overrideCode !== ADMIN_OVERRIDE_CODE) {
        overrideLogger.warn(`Invalid admin override code attempt`);
        return { success: false, message: 'Invalid override code' };
      }

      const user = users.get(targetEmail);
      if (!user) {
        overrideLogger.warn(`Admin override for non-existent user: ${targetEmail}`);
        return { success: false, message: 'User not found' };
      }

      // Reset user account
      user.loginAttempts = 0;
      user.locked = false;
      users.set(targetEmail, user);

      // Generate emergency access token
      const emergencyToken = jwt.sign(
        {
          userId: user.id,
          email: user.email,
          role: user.role,
          permissions: user.permissions,
          override: true,
          emergency: true
        },
        JWT_SECRET,
        { expiresIn: '1h' }
      );

      overrideLogger.info(`Admin override successful for user: ${targetEmail}`);
      return {
        success: true,
        message: 'Admin override successful',
        emergencyToken,
        user: {
          id: user.id,
          email: user.email,
          role: user.role
        }
      };

    } catch (error) {
      overrideLogger.error(`Admin override error: ${error.message}`);
      return { success: false, message: 'Override failed' };
    }
  }

  generateTokens(user) {
    const accessToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role,
        permissions: user.permissions
      },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        type: 'refresh'
      },
      JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    return { accessToken, refreshToken };
  }

  verifyToken(token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const session = sessions.get(token);

      if (!session || session.expiresAt < Date.now()) {
        return null;
      }

      return decoded;
    } catch (error) {
      return null;
    }
  }

  verifyMfaCode(secret, code) {
    // Simple TOTP implementation (in production, use a proper TOTP library)
    const timeWindow = Math.floor(Date.now() / 30000); // 30-second windows
    const expectedCode = crypto.createHmac('sha1', secret)
      .update(timeWindow.toString())
      .digest('hex')
      .substring(0, 6);

    return expectedCode === code;
  }

  recordFailedAttempt(email) {
    const attempts = loginAttempts.get(email) || { count: 0, lastAttempt: Date.now() };
    attempts.count += 1;
    attempts.lastAttempt = Date.now();

    if (attempts.count >= MAX_LOGIN_ATTEMPTS) {
      const user = users.get(email);
      if (user) {
        user.locked = true;
        user.lockedUntil = Date.now() + LOCKOUT_TIME;
        users.set(email, user);
        authLogger.warn(`Account locked for user: ${email}`);
      }
    }

    loginAttempts.set(email, attempts);
  }

  isAccountLocked(email) {
    const user = users.get(email);
    if (!user || !user.locked) return false;

    if (Date.now() > user.lockedUntil) {
      user.locked = false;
      users.set(email, user);
      return false;
    }

    return true;
  }

  async refreshToken(refreshToken) {
    try {
      const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
      const user = users.get(decoded.email);

      if (!user) {
        return { success: false, message: 'User not found' };
      }

      const tokens = this.generateTokens(user);
      return { success: true, tokens };
    } catch (error) {
      return { success: false, message: 'Invalid refresh token' };
    }
  }

  logout(token) {
    sessions.delete(token);
    authLogger.info('User logged out');
    return { success: true, message: 'Logged out successfully' };
  }

  getUserProfile(email) {
    const user = users.get(email);
    if (!user) return null;

    return {
      id: user.id,
      email: user.email,
      role: user.role,
      permissions: user.permissions,
      lastLogin: user.lastLogin,
      mfaEnabled: user.mfaEnabled
    };
  }
}

// Export singleton instance
const authManager = new AuthenticationManager();

module.exports = {
  AuthenticationManager,
  authManager,
  authenticateUser: (email, password, mfaCode) => authManager.authenticateUser(email, password, mfaCode),
  adminOverride: (code, email) => authManager.adminOverride(code, email),
  verifyToken: (token) => authManager.verifyToken(token),
  refreshToken: (token) => authManager.refreshToken(token),
  logout: (token) => authManager.logout(token),
  getUserProfile: (email) => authManager.getUserProfile(email)
};
