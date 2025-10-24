import jwt
import logging
import os
import time
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Any, Optional, Tuple
from flask import request, jsonify, g
from cryptography.fernet import Fernet
import json

logger = logging.getLogger(__name__)

class AuthMiddleware:
    """
    Enhanced authentication middleware with JWT validation, refresh tokens,
    and encrypted token caching.
    """

    def __init__(self):
        self.jwt_secret = os.getenv('JWT_SECRET_KEY', 'equity-shield-jwt-secret-2024')
        self.jwt_algorithm = 'HS256'
        self.token_expiry = int(os.getenv('JWT_TOKEN_EXPIRY_MINUTES', '60'))
        self.refresh_token_expiry = int(os.getenv('JWT_REFRESH_TOKEN_EXPIRY_DAYS', '30'))

        # Encryption key for token caching
        self.encryption_key = os.getenv('TOKEN_ENCRYPTION_KEY')
        if not self.encryption_key:
            self.encryption_key = Fernet.generate_key().decode()
            logger.warning("Generated new encryption key - set TOKEN_ENCRYPTION_KEY env var")

        self.fernet = Fernet(self.encryption_key.encode())

        # Token cache file
        self.cache_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'token_cache.enc')

    def _encrypt_data(self, data: Dict[str, Any]) -> str:
        """Encrypt data for secure storage"""
        json_data = json.dumps(data)
        return self.fernet.encrypt(json_data.encode()).decode()

    def _decrypt_data(self, encrypted_data: str) -> Dict[str, Any]:
        """Decrypt stored data"""
        try:
            decrypted = self.fernet.decrypt(encrypted_data.encode())
            return json.loads(decrypted.decode())
        except Exception as e:
            logger.error(f"Failed to decrypt token data: {str(e)}")
            return {}

    def _load_token_cache(self) -> Dict[str, Any]:
        """Load encrypted token cache"""
        if not os.path.exists(self.cache_file):
            return {}

        try:
            with open(self.cache_file, 'r') as f:
                encrypted_data = f.read().strip()
                return self._decrypt_data(encrypted_data)
        except Exception as e:
            logger.error(f"Failed to load token cache: {str(e)}")
            return {}

    def _save_token_cache(self, cache_data: Dict[str, Any]) -> None:
        """Save encrypted token cache"""
        try:
            encrypted_data = self._encrypt_data(cache_data)
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            with open(self.cache_file, 'w') as f:
                f.write(encrypted_data)
        except Exception as e:
            logger.error(f"Failed to save token cache: {str(e)}")

    def generate_tokens(self, user_id: str, user_data: Dict[str, Any] = None) -> Tuple[str, str]:
        """
        Generate access and refresh tokens
        """
        if user_data is None:
            user_data = {}

        now = datetime.utcnow()

        # Access token payload
        access_payload = {
            'user_id': user_id,
            'exp': now + timedelta(minutes=self.token_expiry),
            'iat': now,
            'type': 'access',
            **user_data
        }

        # Refresh token payload
        refresh_payload = {
            'user_id': user_id,
            'exp': now + timedelta(days=self.refresh_token_expiry),
            'iat': now,
            'type': 'refresh'
        }

        access_token = jwt.encode(access_payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        refresh_token = jwt.encode(refresh_payload, self.jwt_secret, algorithm=self.jwt_algorithm)

        # Cache refresh token
        cache_data = self._load_token_cache()
        cache_data[user_id] = {
            'refresh_token': refresh_token,
            'created_at': now.isoformat(),
            'user_data': user_data
        }
        self._save_token_cache(cache_data)

        logger.info(f"Generated tokens for user: {user_id}")
        return access_token, refresh_token

    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """
        Generate new access token using refresh token
        """
        try:
            # Decode refresh token
            payload = jwt.decode(refresh_token, self.jwt_secret, algorithms=[self.jwt_algorithm])

            if payload.get('type') != 'refresh':
                raise jwt.InvalidTokenError("Invalid token type")

            user_id = payload['user_id']

            # Verify refresh token in cache
            cache_data = self._load_token_cache()
            cached_token_data = cache_data.get(user_id)

            if not cached_token_data or cached_token_data['refresh_token'] != refresh_token:
                raise jwt.InvalidTokenError("Refresh token not found in cache")

            # Generate new access token
            user_data = cached_token_data.get('user_data', {})
            access_token, _ = self.generate_tokens(user_id, user_data)

            logger.info(f"Refreshed access token for user: {user_id}")
            return access_token

        except jwt.ExpiredSignatureError:
            logger.warning("Refresh token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid refresh token: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error refreshing token: {str(e)}")
            return None

    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate JWT token and return payload
        """
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])

            if payload.get('type') != 'access':
                raise jwt.InvalidTokenError("Invalid token type")

            # Check if token is expired
            exp = payload.get('exp')
            if exp and datetime.utcfromtimestamp(exp) < datetime.utcnow():
                raise jwt.ExpiredSignatureError("Token expired")

            return payload

        except jwt.ExpiredSignatureError:
            logger.warning("Access token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid access token: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error validating token: {str(e)}")
            return None

    def revoke_tokens(self, user_id: str) -> bool:
        """
        Revoke all tokens for a user
        """
        try:
            cache_data = self._load_token_cache()
            if user_id in cache_data:
                del cache_data[user_id]
                self._save_token_cache(cache_data)
                logger.info(f"Revoked tokens for user: {user_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error revoking tokens for user {user_id}: {str(e)}")
            return False

    def require_jwt(self, f):
        """
        Decorator to require valid JWT token
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')

            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({
                    'status': 'error',
                    'error': 'Missing or invalid authorization header',
                    'message': 'Authorization header with Bearer token required'
                }), 401

            token = auth_header.split(' ')[1]
            payload = self.validate_token(token)

            if not payload:
                return jsonify({
                    'status': 'error',
                    'error': 'Invalid or expired token',
                    'message': 'Please refresh your token or login again'
                }), 401

            # Store user info in Flask g object
            g.user_id = payload['user_id']
            g.user_data = payload

            return f(*args, **kwargs)
        return decorated_function

    def cleanup_expired_tokens(self) -> int:
        """
        Clean up expired refresh tokens from cache
        Returns number of tokens cleaned up
        """
        try:
            cache_data = self._load_token_cache()
            cleaned_count = 0

            for user_id, token_data in list(cache_data.items()):
                try:
                    # Decode refresh token to check expiry
                    payload = jwt.decode(
                        token_data['refresh_token'],
                        self.jwt_secret,
                        algorithms=[self.jwt_algorithm],
                        options={"verify_exp": False}
                    )

                    exp = payload.get('exp')
                    if exp and datetime.utcfromtimestamp(exp) < datetime.utcnow():
                        del cache_data[user_id]
                        cleaned_count += 1
                except Exception:
                    # If we can't decode, remove the token
                    del cache_data[user_id]
                    cleaned_count += 1

            if cleaned_count > 0:
                self._save_token_cache(cache_data)
                logger.info(f"Cleaned up {cleaned_count} expired tokens")

            return cleaned_count

        except Exception as e:
            logger.error(f"Error cleaning up expired tokens: {str(e)}")
            return 0

# Global auth middleware instance
auth_middleware = AuthMiddleware()
