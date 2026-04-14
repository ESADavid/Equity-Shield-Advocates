import { info, error } from '../utils/loggerWrapper.js';
import User from '../models/User.js';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';

/**
 * JPMorgan Auth Integration Stub - Mock implementation for development/testing
 * Replace with real JPMorgan Connect/BaaS API calls when live.
 */

const JWT_SECRET = process.env.JWT_SECRET || 'jpmorgan-dev-secret-2024';
const TOKEN_EXPIRY = '24h';
const REFRESH_EXPIRY = '7d';

export async function authenticateUser(email, password, mfaCode = null) {
  info(`Auth attempt for email: ${email}`);

  try {
    // Mock DB lookup (use real User model in prod)
    const user = await User.findForAuth(email, 'default-tenant'); // Assume tenant

    if (!user) {
      return { success: false, message: 'User not found', requiresMfa: false };
    }

    // Mock password check
    const passwordMatch = await user.comparePassword(password);
    if (!passwordMatch) {
      await user.incLoginAttempts();
      return {
        success: false,
        message: 'Invalid credentials',
        requiresMfa: false,
      };
    }

    // Mock MFA (skip or simple check)
    if (user.security.twoFactorEnabled && !mfaCode) {
      return { success: false, message: 'MFA required', requiresMfa: true };
    }
    if (user.security.twoFactorEnabled && mfaCode !== '123456') {
      return {
        success: false,
        message: 'Invalid MFA code',
        requiresMfa: false,
      };
    }

    await user.resetLoginAttempts();

    // Generate tokens
    const accessToken = user.generateAuthToken();
    const refreshToken = jwt.sign(
      { userId: user._id, type: 'refresh' },
      JWT_SECRET,
      { expiresIn: REFRESH_EXPIRY }
    );

    info(`User ${email} authenticated successfully`);

    return {
      success: true,
      accessToken,
      refreshToken,
      user: user.toPublicJSON(),
      requiresMfa: false,
    };
  } catch (err) {
    error('Auth error:', err);
    return { success: false, message: 'Authentication failed' };
  }
}

export async function adminOverride(overrideCode, targetEmail) {
  info(`Admin override requested for ${targetEmail}, code: ${overrideCode}`);

  // Mock admin check (hardcoded for dev)
  if (overrideCode !== 'ADMIN-OVERRIDE-2024-SECURE') {
    return { success: false, message: 'Invalid override code' };
  }

  return {
    success: true,
    message: 'Admin override granted',
    temporaryToken: jwt.sign(
      { email: targetEmail, override: true },
      JWT_SECRET,
      { expiresIn: '1h' }
    ),
  };
}

export function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

export async function refreshToken(token) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.type !== 'refresh') {
      return { success: false, message: 'Invalid refresh token' };
    }

    const user = await User.findById(decoded.userId);
    if (!user) {
      return { success: false, message: 'User not found' };
    }

    const newAccessToken = user.generateAuthToken();
    const newRefreshToken = jwt.sign(
      { userId: user._id, type: 'refresh' },
      JWT_SECRET,
      { expiresIn: REFRESH_EXPIRY }
    );

    return {
      success: true,
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  } catch (err) {
    error('Refresh token error:', err);
    return { success: false, message: 'Invalid refresh token' };
  }
}

export async function logout(token) {
  // Mock blacklist (use Redis in prod)
  info('User logged out');
  return { success: true, message: 'Logged out successfully' };
}

export async function getUserProfile(email) {
  const user = await User.findForAuth(email, 'default-tenant');
  return user ? user.toPublicJSON() : null;
}

// Middleware factories
export function jpmorganAuthMiddleware() {
  return async (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ success: false, message: 'Invalid token' });
    }

    req.user = decoded;
    next();
  };
}

export function jpmorganAdminMiddleware(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin required' });
  }
  next();
}

info('JPMorgan Auth Integration loaded (Mock mode)');
