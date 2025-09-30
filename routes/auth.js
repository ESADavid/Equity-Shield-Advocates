import express from 'express';
import authService from '../services/authService.js';
import {
  authenticate,
  authRateLimit,
  logAuthEvent,
  validateAuthRequest
} from '../middleware/auth.js';

const router = express.Router();

// Register new user
router.post('/register', authRateLimit, logAuthEvent('register'), async (req, res) => {
  try {
    const { username, email, password, firstName, lastName, role, tenantId } = req.body;

    // Basic validation
    if (!username || !email || !password || !firstName || !lastName || !tenantId) {
      return res.status(400).json({
        success: false,
        message: 'All fields including tenantId are required'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters long'
      });
    }

    const result = await authService.register({
      username,
      email,
      password,
      firstName,
      lastName,
      role: role || 'user',
      tenantId
    });

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: result
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(400).json({
      success: false,
      message: error.message
    });
  }
});

// Login user
router.post('/login', authRateLimit, logAuthEvent('login'), async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username and password are required'
      });
    }

    const result = await authService.login({ username, password });

    res.json({
      success: true,
      message: 'Login successful',
      data: result
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(401).json({
      success: false,
      message: error.message
    });
  }
});

// Refresh access token
router.post('/refresh', logAuthEvent('refresh'), async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token is required'
      });
    }

    const tokens = await authService.refreshToken(refreshToken);

    res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: tokens
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(401).json({
      success: false,
      message: 'Invalid refresh token'
    });
  }
});

// Logout user
router.post('/logout', authenticate, logAuthEvent('logout'), async (req, res) => {
  try {
    await authService.logout(req.user._id);

    res.json({
      success: true,
      message: 'Logout successful'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Logout failed'
    });
  }
});

// Get current user profile
router.get('/profile', authenticate, logAuthEvent('get_profile'), async (req, res) => {
  try {
    const profile = await authService.getProfile(req.user._id);

    res.json({
      success: true,
      data: profile
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get profile'
    });
  }
});

// Update user profile
router.put('/profile', authenticate, logAuthEvent('update_profile'), async (req, res) => {
  try {
    const profile = await authService.updateProfile(req.user._id, req.body);

    res.json({
      success: true,
      message: 'Profile updated successfully',
      data: profile
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(400).json({
      success: false,
      message: error.message
    });
  }
});

// Change password
router.put('/change-password', authenticate, logAuthEvent('change_password'), async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Current password and new password are required'
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'New password must be at least 6 characters long'
      });
    }

    await authService.changePassword(req.user._id, currentPassword, newPassword);

    res.json({
      success: true,
      message: 'Password changed successfully'
    });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(400).json({
      success: false,
      message: error.message
    });
  }
});

// Request password reset
router.post('/forgot-password', authRateLimit, logAuthEvent('forgot_password'), async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    const result = await authService.requestPasswordReset(email);

    res.json({
      success: true,
      message: result.message
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process password reset request'
    });
  }
});

// Reset password with token
router.post('/reset-password', logAuthEvent('reset_password'), async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Token and new password are required'
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'New password must be at least 6 characters long'
      });
    }

    await authService.resetPassword(token, newPassword);

    res.json({
      success: true,
      message: 'Password reset successfully'
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(400).json({
      success: false,
      message: error.message
    });
  }
});

// Verify token (for frontend to check if token is valid)
router.get('/verify', authenticate, logAuthEvent('verify_token'), (req, res) => {
  res.json({
    success: true,
    message: 'Token is valid',
    data: {
      user: req.user.toPublicJSON(),
      tokenData: req.tokenData
    }
  });
});

export default router;
