/**
 * JPMorgan Authentication Integration
 * Integrates Oscar Broome Login Override System with JPMorgan Payment System
 */

const jwt = require('jsonwebtoken');
const crypto = require('node:crypto');
const bcrypt = require('bcrypt');
const winston = require('winston');

// Configuration
const config = {
  jwt: {
    secret: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
    refreshSecret:
      process.env.JWT_REFRESH_SECRET || crypto.randomBytes(64).toString('hex'),
    expiresIn: '15m',
    refreshExpiresIn: '7d',
  },
  mfa: {
    secret: process.env.MFA_SECRET || crypto.randomBytes(32).toString('hex'),
  },
  security: {
    maxLoginAttempts: 5,
    lockoutTime: 15 * 60 * 1000, // 15 minutes
    adminOverrideCode:
      process.env.ADMIN_OVERRIDE_CODE || 'OSCAR_BROOME_EMERGENCY_2024',
  },
};

// In-memory stores (use database in production)
const users = new Map();
const sessions = new Map();
const loginAttempts = new Map();
const overrideCodes = new Map();

// Logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'auth.log' }),
  ],
});

class JPMorganAuthManager {
  constructor() {
    this.initializeDefaultUsers();
  }

  // Password hashing using bcrypt (replacing hashlib)
  async hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
  }

  // Password verification
  async verifyPassword(password, hashedPassword) {
    try {
      return await bcrypt.compare(password, hashedPassword);
    } catch (error) {
      logger.error('Password verification error:', error);
      return false;
    }
  }

  // Password validation
  validatePassword(password) {
    if (!password || password.length < 8 || password.length > 128) {
      return {
        valid: false,
        message: 'Password must be 8-128 characters long',
      };
    }

    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasDigit = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*()_+\-={}|;:,.<>?`~]/.test(password);

    if (!(hasUpper && hasLower && hasDigit && hasSpecial)) {
      return {
        valid: false,
        message:
          'Password must contain uppercase, lowercase, digit, and special character',
      };
    }

    return { valid: true, message: 'Password is valid' };
  }

  // Initialize default users
  async initializeDefaultUsers() {
    try {
      // Admin user
      const adminPassword = await this.hashPassword('OscarBroome2024!');
      users.set('admin@jpmorgan.oscarbroomerevenue.com', {
        id: 'admin-jpm-001',
        email: 'admin@jpmorgan.oscarbroomerevenue.com',
        password: adminPassword,
        role: 'admin',
        mfaEnabled: true,
        mfaSecret: config.mfa.secret,
        lastLogin: null,
        loginAttempts: 0,
        locked: false,
        lockedUntil: null,
        permissions: ['read', 'write', 'delete', 'admin', 'jpmorgan_payments'],
        department: 'JPMorgan Integration',
      });

      // Executive user
      const execPassword = await this.hashPassword('Executive2024!');
      users.set('executive@jpmorgan.oscarbroomerevenue.com', {
        id: 'exec-jpm-001',
        email: 'executive@jpmorgan.oscarbroomerevenue.com',
        password: execPassword,
        role: 'executive',
        mfaEnabled: true,
        mfaSecret: crypto.randomBytes(32).toString('hex'),
        lastLogin: null,
        loginAttempts: 0,
        locked: false,
        lockedUntil: null,
        permissions: ['read', 'write', 'jpmorgan_payments'],
        department: 'JPMorgan Integration',
      });

      logger.info('JPMorgan authentication users initialized');
    } catch (error) {
      logger.error('Error initializing users:', error);
    }
  }

  // User authentication
  async authenticateUser(email, password, mfaCode = null) {
    // Check rate limiting
    if (this.isAccountLocked(email)) {
      logger.warning(`Login attempt for locked account: ${email}`);
      return {
        success: false,
        message:
          'Account is temporarily locked due to too many failed attempts',
      };
    }

    const user = users.get(email);
    if (!user) {
      logger.warning(`Login attempt for non-existent user: ${email}`);
      this.recordFailedAttempt(email);
      return { success: false, message: 'Invalid credentials' };
    }

    // Verify password
    const isValidPassword = await this.verifyPassword(password, user.password);
    if (!isValidPassword) {
      logger.warning(`Invalid password for user: ${email}`);
      this.recordFailedAttempt(email);
      return { success: false, message: 'Invalid credentials' };
    }

    // Check MFA if enabled
    if (user.mfaEnabled) {
      if (!mfaCode) {
        return {
          success: false,
          message: 'MFA code required',
          requiresMfa: true,
        };
      }

      if (!this.verifyMfaCode(user.mfaSecret, mfaCode)) {
        logger.warning(`Invalid MFA code for user: ${email}`);
        this.recordFailedAttempt(email);
        return { success: false, message: 'Invalid MFA code' };
      }
    }

    // Reset login attempts on successful login
    user.loginAttempts = 0;
    user.lastLogin = new Date().toISOString();
    users.set(email, user);

    // Generate tokens
    const tokens = this.generateTokens(user);

    // Store session
    sessions.set(tokens.accessToken, {
      userId: user.id,
      email: user.email,
      role: user.role,
      permissions: user.permissions,
      department: user.department,
      expiresAt: Date.now() + 15 * 60 * 1000, // 15 minutes
    });

    logger.info(`Successful login for JPMorgan user: ${email}`);
    return {
      success: true,
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        permissions: user.permissions,
        department: user.department,
      },
      tokens,
    };
  }

  // Admin override
  async adminOverride(overrideCode, targetEmail) {
    if (overrideCode !== config.security.adminOverrideCode) {
      logger.warning('Invalid admin override code attempt');
      return { success: false, message: 'Invalid override code' };
    }

    const user = users.get(targetEmail);
    if (!user) {
      logger.warning(`Admin override for non-existent user: ${targetEmail}`);
      return { success: false, message: 'User not found' };
    }

    // Reset user account
    user.loginAttempts = 0;
    user.locked = false;
    user.lockedUntil = null;
    users.set(targetEmail, user);

    // Generate emergency access token
    const emergencyToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role,
        permissions: user.permissions,
        department: user.department,
        override: true,
        emergency: true,
        exp: Math.floor(Date.now() / 1000) + 60 * 60, // 1 hour
      },
      config.jwt.secret
    );

    logger.info(`Admin override successful for JPMorgan user: ${targetEmail}`);
    return {
      success: true,
      message: 'Admin override successful',
      emergencyToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        department: user.department,
      },
    };
  }

  // Token generation
  generateTokens(user) {
    const accessToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role,
        permissions: user.permissions,
        department: user.department,
        exp: Math.floor(Date.now() / 1000) + 15 * 60, // 15 minutes
      },
      config.jwt.secret
    );

    const refreshToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        type: 'refresh',
        exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60, // 7 days
      },
      config.jwt.refreshSecret
    );

    return { accessToken, refreshToken };
  }

  // Token verification
  verifyToken(token) {
    try {
      const decoded = jwt.verify(token, config.jwt.secret);
      const session = sessions.get(token);

      if (!session || session.expiresAt < Date.now()) {
        return null;
      }

      return decoded;
    } catch (error) {
      return null;
    }
  }

  // MFA verification (simplified TOTP)
  verifyMfaCode(secret, code) {
    const timeWindow = Math.floor(Date.now() / 30000); // 30-second windows
    const expectedCode = (timeWindow % 1000000).toString().padStart(6, '0');
    return expectedCode === code;
  }

  // Rate limiting
  recordFailedAttempt(email) {
    const attempts = loginAttempts.get(email) || {
      count: 0,
      lastAttempt: Date.now(),
    };
    attempts.count += 1;
    attempts.lastAttempt = Date.now();

    if (attempts.count >= config.security.maxLoginAttempts) {
      const user = users.get(email);
      if (user) {
        user.locked = true;
        user.lockedUntil = Date.now() + config.security.lockoutTime;
        users.set(email, user);
        logger.warning(`Account locked for JPMorgan user: ${email}`);
      }
    }

    loginAttempts.set(email, attempts);
  }

  // Account lock check
  isAccountLocked(email) {
    const user = users.get(email);
    if (!user || !user.locked) {
      return false;
    }

    if (Date.now() > user.lockedUntil) {
      user.locked = false;
      users.set(email, user);
      return false;
    }

    return true;
  }

  // Token refresh
  async refreshToken(refreshToken) {
    try {
      const decoded = jwt.verify(refreshToken, config.jwt.refreshSecret);
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

  // Logout
  logout(token) {
    sessions.delete(token);
    logger.info('JPMorgan user logged out');
    return { success: true, message: 'Logged out successfully' };
  }

  // Get user profile
  getUserProfile(email) {
    const user = users.get(email);
    if (!user) {
      return null;
    }

    return {
      id: user.id,
      email: user.email,
      role: user.role,
      permissions: user.permissions,
      department: user.department,
      lastLogin: user.lastLogin,
      mfaEnabled: user.mfaEnabled,
    };
  }

  // Session cleanup
  cleanupExpiredSessions() {
    const now = Date.now();
    const expiredTokens = [];

    for (const [token, session] of sessions) {
      if (session.expiresAt < now) {
        expiredTokens.push(token);
      }
    }

    for (const token of expiredTokens) {
      sessions.delete(token);
    }
    return { success: true, cleaned: expiredTokens.length };
  }

  // Force logout all sessions for user
  forceLogoutAll(userId) {
    const expiredTokens = [];

    for (const [token, session] of sessions) {
      if (session.userId === userId) {
        expiredTokens.push(token);
      }
    }

    expiredTokens.forEach((token) => sessions.delete(token));
    return { success: true, loggedOut: expiredTokens.length };
  }
}

// Create singleton instance
const jpmorganAuthManager = new JPMorganAuthManager();

// Express middleware for JPMorgan authentication
const jpmorganAuthMiddleware = (requiredPermissions = []) => {
  return (req, res, next) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authorization token required' });
      }

      const token = authHeader.substring(7);
      const decoded = jpmorganAuthManager.verifyToken(token);

      if (!decoded) {
        return res.status(401).json({ error: 'Invalid or expired token' });
      }

      // Check permissions
      if (requiredPermissions.length > 0) {
        const userPermissions = decoded.permissions || [];
        const hasPermission = requiredPermissions.every((perm) =>
          userPermissions.includes(perm)
        );

        if (!hasPermission) {
          return res.status(403).json({ error: 'Insufficient permissions' });
        }
      }

      req.user = decoded;
      next();
    } catch (error) {
      logger.error('Auth middleware error:', error);
      res.status(500).json({ error: 'Authentication error' });
    }
  };
};

// Admin override middleware
const jpmorganAdminMiddleware = (req, res, next) => {
  const user = req.user;
  if (!user || user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

module.exports = {
  JPMorganAuthManager,
  jpmorganAuthManager,
  jpmorganAuthMiddleware,
  jpmorganAdminMiddleware,
  authenticateUser: (email, password, mfaCode) =>
    jpmorganAuthManager.authenticateUser(email, password, mfaCode),
  adminOverride: (code, email) =>
    jpmorganAuthManager.adminOverride(code, email),
  verifyToken: (token) => jpmorganAuthManager.verifyToken(token),
  refreshToken: (token) => jpmorganAuthManager.refreshToken(token),
  logout: (token) => jpmorganAuthManager.logout(token),
  getUserProfile: (email) => jpmorganAuthManager.getUserProfile(email),
};
