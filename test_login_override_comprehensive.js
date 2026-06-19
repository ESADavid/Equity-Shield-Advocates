/**
 * Comprehensive Test Suite for Login Override System
 * Tests all enhanced security features including rate limiting, MFA, session management
 */

const {
  LoginOverrideManager,
  loginOverrideManager,
  OVERRIDE_TYPES,
  OVERRIDE_REASONS,
} = require('./auth/login_override');

// Mock environment variables for testing
process.env.JWT_SECRET = 'test_jwt_secret_key';
process.env.RATE_LIMIT_WINDOW_MS = '900000'; // 15 minutes
