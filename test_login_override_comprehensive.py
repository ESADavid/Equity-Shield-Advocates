"""
Comprehensive test suite for Oscar Broome Login Override System
Tests all authentication flows, security features, and edge cases
"""

import os
import sys
import unittest
import json
import time
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

# Add the auth directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'auth'))

try:
    from login_override_fixed import (
        auth_manager, authenticate_user, admin_override,
        verify_token, refresh_token, logout, get_user_profile,
        AuthenticationManager
    )
except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure login_override_fixed.py is in the auth directory")
    sys.exit(1)

class TestLoginOverrideComprehensive(unittest.TestCase):
    """Comprehensive test suite for login override system"""

    def setUp(self):
        """Set up test environment"""
        # Reset the auth manager for each test
        global auth_manager
        auth_manager = AuthenticationManager()

        # Set test environment
        os.environ['TESTING'] = 'true'
        os.environ['NODE_ENV'] = 'test'

        # Clear any existing sessions
        from login_override_fixed import sessions, login_attempts
        sessions.clear()
        login_attempts.clear()

    def tearDown(self):
        """Clean up after each test"""
        # Clear sessions and attempts
        from login_override_fixed import sessions, login_attempts
        sessions.clear()
        login_attempts.clear()

    def test_password_validation(self):
        """Test password validation function"""
        # Valid password
        result = auth_manager.validatePassword("ValidPass123!")
        self.assertTrue(result['valid'])
        self.assertEqual(result['message'], "Password is valid")

        # Too short
        result = auth_manager.validatePassword("Short1!")
        self.assertFalse(result['valid'])
        self.assertIn("at least 8 characters", result['message'])

        # Too long
        long_password = "A" * 129
        result = auth_manager.validatePassword(long_password)
        self.assertFalse(result['valid'])
        self.assertIn("cannot exceed 128 characters", result['message'])

        # Missing uppercase
        result = auth_manager.validatePassword("validpass123!")
        self.assertFalse(result['valid'])
        self.assertIn("uppercase", result['message'])

        # Missing lowercase
        result = auth_manager.validatePassword("VALIDPASS123!")
        self.assertFalse(result['valid'])
        self.assertIn("lowercase", result['message'])

        # Missing digit
        result = auth_manager.validatePassword("ValidPass!")
        self.assertFalse(result['valid'])
        self.assertIn("digit", result['message'])

        # Missing special character
        result = auth_manager.validatePassword("ValidPass123")
        self.assertFalse(result['valid'])
        self.assertIn("special character", result['message'])

        # Empty password
        result = auth_manager.validatePassword("")
        self.assertFalse(result['valid'])
        self.assertIn("cannot be empty", result['message'])

    def test_successful_admin_login(self):
        """Test successful admin login"""
        result = authenticate_user('admin@oscarbroomerevenue.com', 'OscarBroome2024!')

        self.assertTrue(result['success'])
        self.assertEqual(result['message'], 'Login successful')
        self.assertEqual(result['user']['email'], 'admin@oscarbroomerevenue.com')
        self.assertEqual(result['user']['role'], 'admin')
        self.assertIn('access_token', result['tokens'])
        self.assertIn('refresh_token', result['tokens'])

    def test_successful_executive_login(self):
        """Test successful executive login"""
        result = authenticate_user('executive@oscarbroomerevenue.com', 'Executive2024!')

        self.assertTrue(result['success'])
        self.assertEqual(result['user']['role'], 'executive')
        self.assertIn('read', result['user']['permissions'])
        self.assertIn('write', result['user']['permissions'])

    def test_invalid_credentials(self):
        """Test login with invalid credentials"""
        result = authenticate_user('admin@oscarbroomerevenue.com', 'WrongPassword!')

        self.assertFalse(result['success'])
        self.assertEqual(result['message'], 'Invalid credentials')

    def test_nonexistent_user(self):
        """Test login with nonexistent user"""
        result = authenticate_user('nonexistent@example.com', 'Password123!')

        self.assertFalse(result['success'])
        self.assertEqual(result['message'], 'Invalid credentials')

    def test_mfa_required_login(self):
        """Test login requiring MFA"""
        result = authenticate_user('admin@oscarbroomerevenue.com', 'OscarBroome2024!')

        self.assertTrue(result['success'])
        self.assertTrue(result.get('requires_mfa', False))

    def test_mfa_login_success(self):
        """Test successful login with MFA"""
        # First attempt without MFA
        result1 = authenticate_user('admin@oscarbroomerevenue.com', 'OscarBroome2024!')
        self.assertTrue(result1.get('requires_mfa', False))

        # Second attempt with MFA code
        result2 = authenticate_user('admin@oscarbroomerevenue.com', 'OscarBroome2024!', '123456')

        self.assertTrue(result2['success'])
        self.assertEqual(result2['message'], 'Login successful')

    def test_mfa_login_failure(self):
        """Test login failure with invalid MFA"""
        result = authenticate_user('admin@oscarbroomerevenue.com', 'OscarBroome2024!', '000000')

        self.assertFalse(result['success'])
        self.assertEqual(result['message'], 'Invalid MFA code')

    def test_rate_limiting(self):
        """Test rate limiting and account lockout"""
        # Make multiple failed attempts
        for i in range(6):
            result = authenticate_user('admin@oscarbroomerevenue.com', 'WrongPassword!')
            if i < 5:
                self.assertEqual(result['message'], 'Invalid credentials')
            else:
                self.assertEqual(result['message'], 'Account is temporarily locked due to too many failed attempts')

    def test_account_lockout_recovery(self):
        """Test account recovery after lockout period"""
        # Lock the account
        for i in range(6):
            authenticate_user('admin@oscarbroomerevenue.com', 'WrongPassword!')

        # Verify account is locked
        result = authenticate_user('admin@oscarbroomerevenue.com', 'OscarBroome2024!')
        self.assertFalse(result['success'])
        self.assertIn('locked', result['message'])

        # Simulate time passing (would need to mock time in real implementation)
        # For now, we'll test the lockout detection logic
        self.assertTrue(auth_manager.is_account_locked('admin@oscarbroomerevenue.com'))

    def test_admin_override_success(self):
        """Test successful admin override"""
        # First lock an account
        for i in range(6):
            authenticate_user('executive@oscarbroomerevenue.com', 'WrongPassword!')

        # Perform admin override
        result = admin_override('OSCAR_BROOME_EMERGENCY_2024', 'executive@oscarbroomerevenue.com')

        self.assertTrue(result['success'])
        self.assertEqual(result['message'], 'Admin override successful')
        self.assertIn('emergency_token', result)

    def test_admin_override_invalid_code(self):
        """Test admin override with invalid code"""
        result = admin_override('INVALID_CODE', 'executive@oscarbroomerevenue.com')

        self.assertFalse(result['success'])
        self.assertEqual(result['message'], 'Invalid override code')

    def test_admin_override_nonexistent_user(self):
        """Test admin override for nonexistent user"""
        result = admin_override('OSCAR_BROOME_EMERGENCY_2024', 'nonexistent@example.com')

        self.assertFalse(result['success'])
        self.assertEqual(result['message'], 'User not found')

    def test_token_verification(self):
        """Test JWT token verification"""
        # Login to get a token
        result = authenticate_user('admin@oscarbroomerevenue.com', 'OscarBroome2024!', '123456')
        token = result['tokens']['access_token']

        # Verify the token
        payload = verify_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload['email'], 'admin@oscarbroomerevenue.com')
        self.assertEqual(payload['role'], 'admin')

    def test_invalid_token_verification(self):
        """Test verification of invalid token"""
        payload = verify_token('invalid_token')
        self.assertIsNone(payload)

    def test_expired_token_verification(self):
        """Test verification of expired token"""
        # Create an expired token (this would need proper time mocking in production)
        expired_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4tMDAxIiwiZW1haWwiOiJhZG1pbkBvc2NhcmJyb29tZXJldmVudWUuY29tIiwicm9sZSI6ImFkbWluIiwicGVybWlzc2lvbnMiOlsicmVhZCIsIndyaXRlIiwiZGVsZXRlIiwiYWRtaW4iXSwiZXhwIjoxNjg0NzY4MDAwfQ.invalid"

        payload = verify_token(expired_token)
        self.assertIsNone(payload)

    def test_token_refresh(self):
        """Test token refresh functionality"""
        # Login to get tokens
        result = authenticate_user('admin@oscarbroomerevenue.com', 'OscarBroome2024!', '123456')
        refresh_token_value = result['tokens']['refresh_token']

        # Refresh the token
        refresh_result = refresh_token(refresh_token_value)

        self.assertTrue(refresh_result['success'])
        self.assertIn('access_token', refresh_result['tokens'])
        self.assertIn('refresh_token', refresh_result['tokens'])

    def test_invalid_refresh_token(self):
        """Test refresh with invalid token"""
        result = refresh_token('invalid_refresh_token')

        self.assertFalse(result['success'])
        self.assertEqual(result['message'], 'Invalid refresh token')

    def test_logout(self):
        """Test user logout"""
        # Login first
        result = authenticate_user('admin@oscarbroomerevenue.com', 'OscarBroome2024!', '123456')
        token = result['tokens']['access_token']

        # Verify token exists
        self.assertIsNotNone(verify_token(token))

        # Logout
        logout_result = logout(token)
        self.assertTrue(logout_result['success'])

        # Verify token is invalidated
        self.assertIsNone(verify_token(token))

    def test_get_user_profile(self):
        """Test getting user profile"""
        profile = get_user_profile('admin@oscarbroomerevenue.com')

        self.assertIsNotNone(profile)
        self.assertEqual(profile['email'], 'admin@oscarbroomerevenue.com')
        self.assertEqual(profile['role'], 'admin')
        self.assertTrue(profile['mfa_enabled'])

    def test_get_nonexistent_user_profile(self):
        """Test getting profile for nonexistent user"""
        profile = get_user_profile('nonexistent@example.com')
        self.assertIsNone(profile)

    def test_session_management(self):
        """Test session creation and cleanup"""
        # Login to create a session
        result = authenticate_user('admin@oscarbroomerevenue.com', 'OscarBroome2024!', '123456')
        token = result['tokens']['access_token']

        # Verify session exists
        from login_override_fixed import sessions
        self.assertIn(token, sessions)

        # Clean up expired sessions
        auth_manager.cleanupExpiredSessions()

        # Session should still exist (not expired)
        self.assertIn(token, sessions)

    def test_force_logout_all(self):
        """Test force logout of all user sessions"""
        # Login multiple times (simulate multiple sessions)
        result1 = authenticate_user('admin@oscarbroomerevenue.com', 'OscarBroome2024!', '123456')
        result2 = authenticate_user('admin@oscarbroomerevenue.com', 'OscarBroome2024!', '123456')

        token1 = result1['tokens']['access_token']
        token2 = result2['tokens']['access_token']

        # Verify both sessions exist
        from login_override_fixed import sessions
        self.assertIn(token1, sessions)
        self.assertIn(token2, sessions)

        # Force logout all sessions for admin user
        auth_manager.forceLogoutAll('admin-001')

        # Verify sessions are removed
        self.assertNotIn(token1, sessions)
        self.assertNotIn(token2, sessions)

    def test_password_hashing_security(self):
        """Test password hashing security"""
        password = "TestPassword123!"

        # Hash the same password multiple times
        hash1 = auth_manager.hash_password(password)
        hash2 = auth_manager.hash_password(password)

        # Hashes should be different due to different salts
        self.assertNotEqual(hash1, hash2)

        # But both should verify correctly
        self.assertTrue(auth_manager.verify_password(password, hash1))
        self.assertTrue(auth_manager.verify_password(password, hash2))

        # Wrong password should fail
        self.assertFalse(auth_manager.verify_password("WrongPassword!", hash1))

    def test_concurrent_login_attempts(self):
        """Test handling of concurrent login attempts"""
        import threading
        import queue

        results = queue.Queue()

        def login_worker(email, password, mfa_code=None):
            result = authenticate_user(email, password, mfa_code)
            results.put(result)

        # Start multiple concurrent login attempts
        threads = []
        for i in range(5):
            thread = threading.Thread(
                target=login_worker,
                args=('admin@oscarbroomerevenue.com', 'OscarBroome2024!', '123456')
            )
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Collect results
        successful_logins = 0
        for i in range(5):
            result = results.get()
            if result['success']:
                successful_logins += 1

        # Should have at least one successful login
        self.assertGreaterEqual(successful_logins, 1)

    def test_emergency_override_token(self):
        """Test emergency override token functionality"""
        # Lock an account
        for i in range(6):
            authenticate_user('executive@oscarbroomerevenue.com', 'WrongPassword!')

        # Get emergency token via admin override
        result = admin_override('OSCAR_BROOME_EMERGENCY_2024', 'executive@oscarbroomerevenue.com')
        emergency_token = result['emergency_token']

        # Verify emergency token works
        payload = verify_token(emergency_token)
        self.assertIsNotNone(payload)
        self.assertTrue(payload.get('emergency', False))
        self.assertEqual(payload['email'], 'executive@oscarbroomerevenue.com')

    def test_permission_based_access(self):
        """Test role-based permissions"""
        # Admin login
        admin_result = authenticate_user('admin@oscarbroomerevenue.com', 'OscarBroome2024!', '123456')
        admin_permissions = admin_result['user']['permissions']

        # Executive login
        exec_result = authenticate_user('executive@oscarbroomerevenue.com', 'Executive2024!', '123456')
        exec_permissions = exec_result['user']['permissions']

        # Admin should have all permissions
        self.assertIn('admin', admin_permissions)
        self.assertIn('delete', admin_permissions)

        # Executive should not have admin or delete permissions
        self.assertNotIn('admin', exec_permissions)
        self.assertNotIn('delete', exec_permissions)

        # Both should have read and write
        self.assertIn('read', admin_permissions)
        self.assertIn('write', admin_permissions)
        self.assertIn('read', exec_permissions)
        self.assertIn('write', exec_permissions)

if __name__ == '__main__':
    # Set up test environment
    os.environ['TESTING'] = 'true'
    os.environ['NODE_ENV'] = 'test'

    # Run the tests
    unittest.main(verbosity=2)
