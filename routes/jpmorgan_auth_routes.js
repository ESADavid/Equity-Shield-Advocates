/**
 * JPMorgan Authentication Routes
 * Provides authentication endpoints for the JPMorgan payment system
 */

const express = require('express');
const router = express.Router();
const Joi = require('joi');

// Import JPMorgan Authentication Integration
const {
  jpmorganAuthMiddleware,
  jpmorganAdminMiddleware,
  authenticateUser,
  adminOverride,
  verifyToken,
  refreshToken,
  logout,
  getUserProfile
} = require('../auth/jpmorgan_auth_integration');

// Validation schemas
const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).max(128).required(),
  mfaCode: Joi.string().length(6).optional()
});

const adminOverrideSchema = Joi.object({
  overrideCode: Joi.string().required(),
  targetEmail: Joi.string().email().required()
});

const refreshTokenSchema = Joi.object({
  refreshToken: Joi.string().required()
});

// Login endpoint
router.post('/login', async (req, res) => {
  try {
    // Validate request body
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Invalid request data',
        error: error.details[0].message
      });
    }

    const { email, password, mfaCode } = value;

    // Attempt authentication
    const result = await authenticateUser(email, password, mfaCode);

    if (!result.success) {
      return res.status(result.requiresMfa ? 200 : 401).json(result);
    }

    res.json(result);
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during login'
    });
  }
});

// Admin override endpoint
router.post('/admin-override',
  jpmorganAdminMiddleware,
  async (req, res) => {
    try {
      // Validate request body
      const { error, value } = adminOverrideSchema.validate(req.body);
      if (error) {
        return res.status(400).json({
          success: false,
          message: 'Invalid request data',
          error: error.details[0].message
        });
      }

      const { overrideCode, targetEmail } = value;

      // Attempt admin override
      const result = await adminOverride(overrideCode, targetEmail);

      if (!result.success) {
        return res.status(400).json(result);
      }

      res.json(result);
    } catch (error) {
      console.error('Admin override error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error during admin override'
      });
    }
  }
);

// Token refresh endpoint
router.post('/refresh-token', async (req, res) => {
  try {
    // Validate request body
    const { error, value } = refreshTokenSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Invalid request data',
        error: error.details[0].message
      });
    }

    const { refreshToken: token } = value;

    // Attempt token refresh
    const result = await refreshToken(token);

    if (!result.success) {
      return res.status(401).json(result);
    }

    res.json(result);
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during token refresh'
    });
  }
});

// Logout endpoint
router.post('/logout',
  jpmorganAuthMiddleware(),
  async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      const token = authHeader && authHeader.startsWith('Bearer ')
        ? authHeader.substring(7)
        : null;

      if (token) {
        const result = await logout(token);
        res.json(result);
      } else {
        res.json({ success: true, message: 'Logged out successfully' });
      }
    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error during logout'
      });
    }
  }
);

// Get user profile endpoint
router.get('/profile',
  jpmorganAuthMiddleware(),
  async (req, res) => {
    try {
      const user = req.user;
      const profile = getUserProfile(user.email);

      if (!profile) {
        return res.status(404).json({
          success: false,
          message: 'User profile not found'
        });
      }

      res.json({
        success: true,
        profile
      });
    } catch (error) {
      console.error('Profile retrieval error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error retrieving profile'
      });
    }
  }
);

// Verify token endpoint
router.get('/verify',
  jpmorganAuthMiddleware(),
  async (req, res) => {
    try {
      const user = req.user;
      res.json({
        success: true,
        message: 'Token is valid',
        user: {
          id: user.userId,
          email: user.email,
          role: user.role,
          permissions: user.permissions,
          department: user.department
        }
      });
    } catch (error) {
      console.error('Token verification error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error during token verification'
      });
    }
  }
);

// Get authentication status endpoint
router.get('/status', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.startsWith('Bearer ')
      ? authHeader.substring(7)
      : null;

    if (!token) {
      return res.json({
        authenticated: false,
        message: 'No authentication token provided'
      });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.json({
        authenticated: false,
        message: 'Invalid or expired token'
      });
    }

    res.json({
      authenticated: true,
      user: {
        id: decoded.userId,
        email: decoded.email,
        role: decoded.role,
        permissions: decoded.permissions,
        department: decoded.department
      }
    });
  } catch (error) {
    console.error('Status check error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during status check'
    });
  }
});

// Health check endpoint
router.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'JPMorgan Authentication Service is healthy',
    timestamp: new Date().toISOString(),
    service: 'JPMorgan Auth Integration'
  });
});

module.exports = router;
