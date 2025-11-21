import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import emailService from './emailService.js';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'auth' },
  transports: [
    new winston.transports.File({ filename: 'logs/auth.log' }),
    new winston.transports.File({ filename: 'logs/auth-error.log', level: 'error' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

class AuthService {
  constructor() {
    this.jwtSecret = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
    this.jwtExpiresIn = process.env.JWT_EXPIRES_IN || '24h';
    this.refreshTokenExpiresIn = process.env.REFRESH_TOKEN_EXPIRES_IN || '7d';
  }

  // Register new user
  async register(userData) {
    try {
      const { username, email, password, firstName, lastName, role = 'user', tenantId } = userData;

      // Validate tenantId is provided
      if (!tenantId) {
        throw new Error('Tenant ID is required for registration');
      }

      // Check if user already exists within the tenant
      const existingUser = await User.findOne({
        tenantId,
        $or: [{ email }, { username }]
      });

      if (existingUser) {
        throw new Error('User already exists with this email or username in this tenant');
      }

      // Create new user
      const user = new User({
        tenantId,
        username,
        email,
        password,
        firstName,
        lastName,
        role
      });

      await user.save();

      logger.info('User registered successfully', { userId: user._id, username, tenantId });

      // Generate tokens
      const tokens = this.generateTokens(user);

      return {
        user: user.toPublicJSON(),
        tokens
      };
    } catch (error) {
      logger.error('User registration failed', { error: error.message, 'email': userData?.email, 'username': userData?.username });
      throw error;
    }
  }

  // Login user
  async login(credentials) {
    try {
      const { username, password } = credentials;

      // Find user
      const user = await User.findForAuth(username);
      if (!user) {
        throw new Error('Invalid credentials');
      }

      // Check if account is locked
      if (user.isLocked) {
        throw new Error('Account is temporarily locked due to too many failed login attempts');
      }

      // Verify password
      const isValidPassword = await user.comparePassword(password);
      if (!isValidPassword) {
        await user.incLoginAttempts();
        throw new Error('Invalid credentials');
      }

      // Reset login attempts and update last login
      await user.resetLoginAttempts();

      logger.info('User logged in successfully', { userId: user._id, username: user.username });

      // Generate tokens
      const tokens = this.generateTokens(user);

      return {
        user: user.toPublicJSON(),
        tokens
      };
    } catch (error) {
      logger.error('User login failed', { error: error.message, username: credentials?.username });
      throw error;
    }
  }

  // Refresh access token
  async refreshToken(refreshToken) {
    try {
      const decoded = jwt.verify(refreshToken, this.jwtSecret);

      const user = await User.findById(decoded._id);
      if (!user || !user.isActive) {
        throw new Error('User not found or inactive');
      }

      logger.info('Token refreshed successfully', { userId: user._id });

      const tokens = this.generateTokens(user);
      return tokens;
    } catch (error) {
      logger.error('Token refresh failed', { error: error.message });
      throw new Error('Invalid refresh token');
    }
  }

  // Logout user (invalidate refresh token)
  async logout(userId) {
    try {
      // In a more sophisticated system, you might want to maintain a blacklist
      // For now, we'll just log the logout
      logger.info('User logged out', { userId });
      return { success: true };
    } catch (error) {
      logger.error('Logout failed', { error: error.message, userId });
      throw error;
    }
  }

  // Verify JWT token
  async verifyToken(token) {
    try {
      const decoded = jwt.verify(token, this.jwtSecret);

      const user = await User.findById(decoded._id);
      if (!user || !user.isActive) {
        throw new Error('User not found or inactive');
      }

      return {
        user,
        tokenData: decoded
      };
    } catch (error) {
      logger.error('Token verification failed', { error: error.message });
      throw new Error('Invalid token');
    }
  }

  // Generate access and refresh tokens
  generateTokens(user) {
    const accessToken = jwt.sign(
      {
        _id: user._id,
        username: user.username,
        role: user.role,
        permissions: user.permissions,
        tenantId: user.tenantId
      },
      this.jwtSecret,
      { expiresIn: this.jwtExpiresIn }
    );

    const refreshToken = jwt.sign(
      {
        _id: user._id,
        type: 'refresh',
        tenantId: user.tenantId
      },
      this.jwtSecret,
      { expiresIn: this.refreshTokenExpiresIn }
    );

    return {
      accessToken,
      refreshToken,
      expiresIn: this.jwtExpiresIn
    };
  }

  // Change password
  async changePassword(userId, currentPassword, newPassword) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Verify current password
      const isValidPassword = await user.comparePassword(currentPassword);
      if (!isValidPassword) {
        throw new Error('Current password is incorrect');
      }

      // Update password
      user.password = newPassword;
      await user.save();

      logger.info('Password changed successfully', { userId });

      return { success: true };
    } catch (error) {
      logger.error('Password change failed', { error: error.message, userId });
      throw error;
    }
  }

  // Request password reset
  async requestPasswordReset(email) {
    try {
      const user = await User.findOne({ email, isActive: true });
      if (!user) {
        // Don't reveal if email exists or not for security
        return { success: true, message: 'If the email exists, a reset link has been sent' };
      }

      // Generate reset token
      const resetToken = jwt.sign(
        { _id: user._id, type: 'passwordReset' },
        this.jwtSecret,
        { expiresIn: '1h' }
      );

      // Save reset token to user
      user.security.passwordResetToken = resetToken;
      user.security.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
      await user.save();

      // Send password reset email
      try {
        await emailService.sendPasswordResetEmail(user.email, user.firstName, resetToken);
        logger.info('Password reset email sent successfully', { userId: user._id, email });
      } catch (emailError) {
        logger.error('Failed to send password reset email', {
          userId: user._id,
          email,
          error: emailError.message
        });
        // Don't fail the request if email fails, but log it
      }

      return { success: true, message: 'Password reset link sent to your email' };
    } catch (error) {
      logger.error('Password reset request failed', { error: error.message, email });
      throw error;
    }
  }

  // Reset password with token
  async resetPassword(token, newPassword) {
    try {
      const decoded = jwt.verify(token, this.jwtSecret);

      if (decoded.type !== 'passwordReset') {
        throw new Error('Invalid reset token');
      }

      const user = await User.findById(decoded._id);
      if (!user || !user.security.passwordResetToken || user.security.passwordResetToken !== token) {
        throw new Error('Invalid or expired reset token');
      }

      if (user.security.passwordResetExpires < new Date()) {
        throw new Error('Reset token has expired');
      }

      // Update password and clear reset token
      user.password = newPassword;
      user.security.passwordResetToken = undefined;
      user.security.passwordResetExpires = undefined;
      await user.save();

      logger.info('Password reset successfully', { userId: user._id });

      return { success: true };
    } catch (error) {
      logger.error('Password reset failed', { error: error.message });
      throw error;
    }
  }

  // Check if user has permission
  async checkPermission(userId, permission) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        return false;
      }

      return user.hasPermission(permission);
    } catch (error) {
      logger.error('Permission check failed', { error: error.message, userId, permission });
      return false;
    }
  }

  // Get user profile
  async getProfile(userId) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      return user.toPublicJSON();
    } catch (error) {
      logger.error('Get profile failed', { error: error.message, userId });
      throw error;
    }
  }

  // Update user profile
  async updateProfile(userId, profileData) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      const allowedFields = ['firstName', 'lastName', 'department', 'profile'];
      allowedFields.forEach(field => {
        if (profileData[field] !== undefined) {
          if (field === 'profile') {
            user.profile = { ...user.profile, ...profileData.profile };
          } else {
            user[field] = profileData[field];
          }
        }
      });

      await user.save();

      logger.info('Profile updated successfully', { userId });

      return user.toPublicJSON();
    } catch (error) {
      logger.error('Profile update failed', { error: error.message, userId });
      throw error;
    }
  }
}

// Create singleton instance
const authService = new AuthService();

export default authService;
