/**
 * JPMorgan Authentication Routes - Real JWT Implementation
 */

import express from 'express';
import { z } from 'zod';
import bcrypt from 'bcrypt';
import { generateAccessToken, generateRefreshToken } from '../utils/jwt.js';
import { authenticateToken, authenticateRefreshToken, requireAdmin } from '../utils/authMiddleware.js';
import { info, error } from '../utils/loggerWrapper.js';


const router = express.Router();

// Mock user DB (replace with real User model later)
const usersDB = {
  'admin@jpm.com': {
    id: '1',
    email: 'admin@jpm.com',
    password: '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
    role: 'admin',
    permissions: ['full'],
    department: 'treasury',
  },
  'user@jpm.com': {
    id: '2',
    email: 'user@jpm.com',
    password: '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
    role: 'user',
    permissions: ['read'],
    department: 'finance',
  }
};

// Zod schemas
const loginSchema = z.object({
  email: z.string().email('Invalid email'),
  password: z.string().min(8, 'Password too short'),
  mfaCode: z.string().optional(),
});

const adminOverrideSchema = z.object({
  overrideCode: z.string().min(6),
  targetEmail: z.string().email(),
});

const refreshSchema = z.object({
  refreshToken: z.string(),
});

// Auth functions
const authenticateUser = async (email, password) => {
  const user = usersDB[email];
  if (!user) {
    return { success: false, message: 'Invalid credentials' };
  }

  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    return { success: false, message: 'Invalid credentials' };
  }

  return {
    success: true,
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
      permissions: user.permissions,
      department: user.department,
    }
  };
};

const adminOverride = async (overrideCode, targetEmail) => {
  // Mock override logic
  if (overrideCode === 'ADMIN123') {
    return { success: true, message: `Override approved for ${targetEmail}` };
  }
  return { success: false, message: 'Invalid override code' };
};

const refreshAuthToken = (user) => {
  return {
    success: true,
    token: generateAccessToken({ 
      userId: user.id, 
      email: user.email, 
      role: user.role,
      permissions: user.permissions,
      department: user.department 
    }),
  };
};

// Rate limiter (middleware)
const loginLimiter = (req, res, next) => next();

// Login endpoint
router.post('/login', loginLimiter, async (req, res) => {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        errors: parsed.error.flatten(),
      });
    }

    const { email, password } = parsed.data;

    const authResult = await authenticateUser(email, password);
    if (!authResult.success) {
      return res.status(401).json(authResult);
    }

    const user = authResult.user;
    const token = generateAccessToken({ 
      userId: user.id, 
      email: user.email, 
      role: user.role,
      permissions: user.permissions,
      department: user.department 
    });
    const refreshTokenStr = generateRefreshToken({ userId: user.id });

    info(`JPMorgan login successful for ${email}`);

    res.json({
      success: true,
      token,
      refreshToken: refreshTokenStr,
      user,
    });
  } catch (err) {
    error('JPMorgan login error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Admin override endpoint
router.post('/admin-override', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const parsed = adminOverrideSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        errors: parsed.error.flatten(),
      });
    }

    const { overrideCode, targetEmail } = parsed.data;
    const result = await adminOverride(overrideCode, targetEmail);

    res.json(result);
  } catch (err) {
    error('Admin override error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Token refresh endpoint
router.post('/refresh-token', authenticateRefreshToken, async (req, res) => {
  try {
    const refreshResult = refreshAuthToken(req.user);
    res.json(refreshResult);
  } catch (err) {
    error('Token refresh error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Logout endpoint (client-side token discard)
router.post('/logout', authenticateToken, async (req, res) => {
  res.json({ success: true, message: 'Logged out successfully' });
});

// Get user profile endpoint
router.get('/profile', authenticateToken, async (req, res) => {
  res.json({
    success: true,
    profile: req.user,
  });
});

// Verify token endpoint
router.get('/verify', authenticateToken, async (req, res) => {
  res.json({
    success: true,
    message: 'Token valid',
    user: req.user,
  });
});

// Status check endpoint
router.get('/status', authenticateToken, async (req, res) => {
  res.json({
    authenticated: true,
    user: req.user,
  });
});

// Health check
router.get('/health', (req, res) => {
  res.json({
    success: true,
    service: 'JPMorgan Auth (JWT/Zod)',
    timestamp: new Date().toISOString(),
  });
});

export default router;

