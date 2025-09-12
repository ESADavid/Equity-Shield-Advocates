"""
Oscar Broome Login Override System - Python Implementation
Emergency access and administrative override capabilities
"""

import os
import json
import hashlib
import hmac
import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import jwt
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
JWT_SECRET = os.getenv('JWT_SECRET', secrets.token_hex(64))
JWT_REFRESH_SECRET = os.getenv('JWT_REFRESH_SECRET', secrets.token_hex(64))
MFA_SECRET = os.getenv('MFA_SECRET', secrets.token_hex(32))
ADMIN_OVERRIDE_CODE = os.getenv('ADMIN_OVERRIDE_CODE', 'OSCAR_BROOME_EMERGENCY_2024')

# In-memory user store (in production, use database)
users = {}
sessions = {}
override_codes = {}

# Rate limiting
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 15 * 60 * 1000  # 15 minutes

class AuthenticationManager:
    """Authentication manager with login override capabilities"""

    def __init__(self):
        self.initialize_default_users()

    def hash_password(self, password: str) -> str:
        """Hash password using SHA-256 with salt"""
        salt = secrets.token_hex(16)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}:{hashed.hex()}"

    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        try:
            salt, hash_value = hashed.split(':')
            test_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return hmac.compare_digest(test_hash.hex(), hash_value)
        except:
            return False

    def initialize_default_users(self):
        """Create default admin and executive users"""
        # Create default admin user
        admin_password = self.hash_password('OscarBroome2024!')
        users['admin@oscarbroomerevenue.com'] = {
            'id': 'admin-001',
            'email': 'admin@oscarbroomerevenue.com',
            'password': admin_password,
            'role': 'admin',
            'mfa_enabled': True,
            'mfa_secret': MFA_SECRET,
            'last_login': None,
            'login_attempts': 0,
            'locked': False,
            'permissions': ['read', 'write', 'delete', 'admin']
        }

        # Create executive user
        exec_password = self.hash_password('Executive2024!')
        users['executive@oscarbroomerevenue.com'] = {
            'id': 'exec-001',
            'email': 'executive@oscarbroomerevenue.com',
            'password': exec_password,
            'role': 'executive',
            'mfa_enabled': True,
            'mfa_secret': secrets.token_hex(32),
            'last_login': None,
            'login_attempts': 0,
            'locked': False,
            'permissions': ['read', 'write']
        }

        logger.info('Default users initialized')

    def validatePassword(self, password: str) -> Dict[str, Any]:
        """Validate password strength and requirements"""
        if not password:
            return {'valid': False, 'message': 'Password cannot be empty'}

        if len(password) < 8:
            return {'valid': False, 'message': 'Password must be at least 8 characters long'}

        if len(password) > 128:
            return {'valid': False, 'message': 'Password cannot exceed 128 characters'}

        # Check for required character types
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?`~' for c in password)

        if not (has_upper and has_lower and has_digit and has_special):
            return {'valid': False, 'message': 'Password must contain uppercase, lowercase, digit, and special character'}

        return {'valid': True, 'message': 'Password is valid'}

    def authenticate_user(self, email: str, password: str, mfa_code: str = None) -> Dict[str, Any]:
        """Authenticate a user with email, password, and optional MFA"""
        try:
            # Check rate limiting
            if self.is_account_locked(email):
                logger.warning(f'Login attempt for locked account: {email}')
                return {
                    'success': False,
                    'message': 'Account is temporarily locked due to too many failed attempts'
                }

            user = users.get(email)
            if not user:
                logger.warning(f'Login attempt for non-existent user: {email}')
                self.record_failed_attempt(email)
                return {'success': False, 'message': 'Invalid credentials'}

            # Verify password
            if not self.verify_password(password, user['password']):
                logger.warning(f'Invalid password for user: {email}')
                self.record_failed_attempt(email)
                return {'success': False, 'message': 'Invalid credentials'}

            # Check MFA if enabled
            if user['mfa_enabled']:
                if not mfa_code:
                    return {
                        'success': False,
                        'message': 'MFA code required',
                        'requires_mfa': True
                    }

                if not self.verify_mfa_code(user['mfa_secret'], mfa_code):
                    logger.warning(f'Invalid MFA code for user: {email}')
                    self.record_failed_attempt(email)
                    return {'success': False, 'message': 'Invalid MFA code'}

            # Reset login attempts on successful login
            user['login_attempts'] = 0
            user['last_login'] = datetime.utcnow().isoformat()
            users[email] = user

            # Generate tokens
            tokens = self.generate_tokens(user)

            # Store session
            sessions[tokens['access_token']] = {
                'user_id': user['id'],
                'email': user['email'],
                'role': user['role'],
                'permissions': user['permissions'],
                'expires_at': datetime.utcnow().timestamp() + (15 * 60)  # 15 minutes
            }

            logger.info(f'Successful login for user: {email}')
            return {
                'success': True,
                'message': 'Login successful',
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'role': user['role'],
                    'permissions': user['permissions']
                },
                'tokens': tokens
            }

        except Exception as e:
            logger.error(f'Authentication error for {email}: {e}')
            return {'success': False, 'message': 'Authentication failed'}

    def admin_override(self, override_code: str, target_email: str) -> Dict[str, Any]:
        """Perform admin override for locked account"""
        try:
            if override_code != ADMIN_OVERRIDE_CODE:
                logger.warning('Invalid admin override code attempt')
                return {'success': False, 'message': 'Invalid override code'}

            user = users.get(target_email)
            if not user:
                logger.warning(f'Admin override for non-existent user: {target_email}')
                return {'success': False, 'message': 'User not found'}

            # Reset user account
            user['login_attempts'] = 0
            user['locked'] = False
            users[target_email] = user

            # Generate emergency access token
            emergency_token = jwt.encode(
                {
                    'user_id': user['id'],
                    'email': user['email'],
                    'role': user['role'],
                    'permissions': user['permissions'],
                    'override': True,
                    'emergency': True,
                    'exp': datetime.utcnow() + timedelta(hours=1)
                },
                JWT_SECRET,
                algorithm='HS256'
            )

            logger.info(f'Admin override successful for user: {target_email}')
            return {
                'success': True,
                'message': 'Admin override successful',
                'emergency_token': emergency_token,
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'role': user['role']
                }
            }

        except Exception as e:
            logger.error(f'Admin override error: {e}')
            return {'success': False, 'message': 'Override failed'}

    def generate_tokens(self, user: Dict[str, Any]) -> Dict[str, str]:
        """Generate access and refresh tokens"""
        access_token = jwt.encode(
            {
                'user_id': user['id'],
                'email': user['email'],
                'role': user['role'],
                'permissions': user['permissions'],
                'exp': datetime.utcnow() + timedelta(minutes=15)
            },
            JWT_SECRET,
            algorithm='HS256'
        )

        refresh_token = jwt.encode(
            {
                'user_id': user['id'],
                'email': user['email'],
                'type': 'refresh',
                'exp': datetime.utcnow() + timedelta(days=7)
            },
            JWT_REFRESH_SECRET,
            algorithm='HS256'
        )

        return {'access_token': access_token, 'refresh_token': refresh_token}

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            session = sessions.get(token)

            if not session or session['expires_at'] < datetime.utcnow().timestamp():
                return None

            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def verify_mfa_code(self, secret: str, code: str) -> bool:
        """Verify MFA code (simplified TOTP implementation)"""
        time_window = int(datetime.utcnow().timestamp() // 30)
        expected_code = str(time_window % 1000000).zfill(6)
        return expected_code == code

    def record_failed_attempt(self, email: str):
        """Record failed login attempt"""
        attempts = login_attempts.get(email, {'count': 0, 'last_attempt': datetime.utcnow().timestamp()})
        attempts['count'] += 1
        attempts['last_attempt'] = datetime.utcnow().timestamp()

        if attempts['count'] >= MAX_LOGIN_ATTEMPTS:
            user = users.get(email)
            if user:
                user['locked'] = True
                user['locked_until'] = datetime.utcnow().timestamp() + LOCKOUT_TIME
                users[email] = user
                logger.warning(f'Account locked for user: {email}')

        login_attempts[email] = attempts

    def is_account_locked(self, email: str) -> bool:
        """Check if account is locked"""
        user = users.get(email)
        if not user or not user.get('locked'):
            return False

        if datetime.utcnow().timestamp() > user.get('locked_until', 0):
            user['locked'] = False
            users[email] = user
            return False

        return True

    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh access token"""
        try:
            payload = jwt.decode(refresh_token, JWT_REFRESH_SECRET, algorithms=['HS256'])
            user = users.get(payload['email'])

            if not user:
                return {'success': False, 'message': 'User not found'}

            tokens = self.generate_tokens(user)
            return {'success': True, 'tokens': tokens}
        except Exception:
            return {'success': False, 'message': 'Invalid refresh token'}

    def logout(self, token: str) -> Dict[str, Any]:
        """Logout user by removing session"""
        sessions.pop(token, None)
        logger.info('User logged out')
        return {'success': True, 'message': 'Logged out successfully'}

    def get_user_profile(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user profile"""
        user = users.get(email)
        if not user:
            return None

        return {
            'id': user['id'],
            'email': user['email'],
            'role': user['role'],
            'permissions': user['permissions'],
            'last_login': user['last_login'],
            'mfa_enabled': user['mfa_enabled']
        }

    def cleanupExpiredSessions(self) -> Dict[str, Any]:
        """Clean up expired sessions"""
        current_time = datetime.utcnow().timestamp()
        expired_sessions = []

        for token, session in sessions.items():
            if session.get('expires_at', 0) < current_time:
                expired_sessions.append(token)

        for token in expired_sessions:
            sessions.pop(token, None)

        return {'success': True, 'cleaned': len(expired_sessions)}

    def forceLogoutAll(self, user_id: str) -> Dict[str, Any]:
        """Force logout all sessions for a user"""
        expired_sessions = []

        for token, session in sessions.items():
            if session.get('user_id') == user_id:
                expired_sessions.append(token)

        for token in expired_sessions:
            sessions.pop(token, None)

        return {'success': True, 'logged_out': len(expired_sessions)}

# Create singleton instance
auth_manager = AuthenticationManager()

# Export functions for compatibility
def authenticate_user(email: str, password: str, mfa_code: str = None):
    return auth_manager.authenticate_user(email, password, mfa_code)

def admin_override(code: str, email: str):
    return auth_manager.admin_override(code, email)

def verify_token(token: str):
    return auth_manager.verify_token(token)

def refresh_token(token: str):
    return auth_manager.refresh_token(token)

def logout(token: str):
    return auth_manager.logout(token)

def get_user_profile(email: str):
    return auth_manager.get_user_profile(email)
