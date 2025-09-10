"""
Oscar Broome Security Middleware - Python Implementation
Implements OWASP security headers, input validation, and rate limiting
"""

import os
import re
import time
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

# Security configuration
SECURITY_CONFIG = {
    # Rate limiting
    'RATE_LIMIT_WINDOW_MS': int(os.getenv('RATE_LIMIT_WINDOW_MS', '900000')),  # 15 minutes
    'RATE_LIMIT_MAX_REQUESTS': int(os.getenv('RATE_LIMIT_MAX_REQUESTS', '100')),

    # CORS settings
    'CORS_ORIGINS': os.getenv('CORS_ORIGINS', 'http://localhost:3000,http://localhost:8080').split(','),
    'CORS_METHODS': ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    'CORS_HEADERS': ['Content-Type', 'Authorization', 'X-Requested-With'],

    # Content Security Policy
    'CSP_DEFAULT_SRC': "'self'",
    'CSP_SCRIPT_SRC': "'self' 'unsafe-inline' https://cdn.jsdelivr.net",
    'CSP_STYLE_SRC': "'self' 'unsafe-inline' https://fonts.googleapis.com",
    'CSP_IMG_SRC': "'self' data: https:",
    'CSP_FONT_SRC': "'self' https://fonts.gstatic.com",

    # Security headers
    'HSTS_MAX_AGE': 31536000,  # 1 year
    'HSTS_INCLUDE_SUBDOMAINS': True,
    'HSTS_PRELOAD': False,

    # Input validation
    'MAX_REQUEST_SIZE': '10mb',
    'MAX_URL_LENGTH': 2048,
    'MAX_QUERY_LENGTH': 1024,
    'MAX_BODY_LENGTH': 1048576,  # 1MB

    # XSS protection
    'XSS_PROTECTION': True,
    'XSS_BLOCK': True,

    # Content type options
    'NO_SNIFF': True,

    # Frame options
    'FRAME_OPTIONS': 'DENY',

    # Referrer policy
    'REFERRER_POLICY': 'strict-origin-when-cross-origin'
}

# Rate limiting store
rate_limit_store = {}

# Input validation patterns
VALIDATION_PATTERNS = {
    'EMAIL': re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$'),
    'PASSWORD': re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$'),
    'USERNAME': re.compile(r'^[a-zA-Z0-9_-]{3,20}$'),
    'PHONE': re.compile(r'^\+?[\d\s\-\(\)]{10,}$'),
    'ZIPCODE': re.compile(r'^\d{5}(-\d{4})?$'),
    'CREDIT_CARD': re.compile(r'^\d{4}\s?\d{4}\s?\d{4}\s?\d{4}$'),
    'AMOUNT': re.compile(r'^\d+(\.\d{1,2})?$'),
    'ALPHA_ONLY': re.compile(r'^[a-zA-Z\s]+$'),
    'ALPHA_NUMERIC': re.compile(r'^[a-zA-Z0-9\s]+$')
}

class SecurityMiddleware:
    """Security middleware with rate limiting, input validation, and security headers"""

    def __init__(self):
        self.request_counts = {}
        self.suspicious_activities = {}

    def rate_limit(self, request) -> Optional[Dict[str, Any]]:
        """Rate limiting middleware"""
        client_ip = self.get_client_ip(request)
        key = f"{client_ip}:{request.path}"
        now = time.time() * 1000
        window_start = now - SECURITY_CONFIG['RATE_LIMIT_WINDOW_MS']

        # Clean old entries
        for k, data in list(self.request_counts.items()):
            if data['timestamp'] < window_start:
                del self.request_counts[k]

        # Get or create request count for this key
        request_data = self.request_counts.get(key, {'count': 0, 'timestamp': now})

        if request_data['count'] >= SECURITY_CONFIG['RATE_LIMIT_MAX_REQUESTS']:
            logger.warning(f'Rate limit exceeded for IP: {client_ip}, path: {request.path}')
            return {
                'error': 'Too many requests',
                'message': 'Rate limit exceeded. Please try again later.',
                'retry_after': int((request_data['timestamp'] + SECURITY_CONFIG['RATE_LIMIT_WINDOW_MS'] - now) / 1000)
            }

        request_data['count'] += 1
        request_data['timestamp'] = now
        self.request_counts[key] = request_data

        return None  # No error, continue processing

    def security_headers(self, response) -> None:
        """Add security headers to response"""
        # OWASP Security Headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = SECURITY_CONFIG['FRAME_OPTIONS']
        response.headers['X-XSS-Protection'] = f"{1 if SECURITY_CONFIG['XSS_PROTECTION'] else 0}{'; mode=block' if SECURITY_CONFIG['XSS_BLOCK'] else ''}"
        response.headers['Referrer-Policy'] = SECURITY_CONFIG['REFERRER_POLICY']
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        response.headers['Content-Security-Policy'] = self.build_csp()
        response.headers['Strict-Transport-Security'] = f"max-age={SECURITY_CONFIG['HSTS_MAX_AGE']}{'; includeSubDomains' if SECURITY_CONFIG['HSTS_INCLUDE_SUBDOMAINS'] else ''}{'; preload' if SECURITY_CONFIG['HSTS_PRELOAD'] else ''}"
        response.headers['Server'] = 'Oscar Broome Revenue System'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'

    def cors_headers(self, request, response) -> None:
        """Add CORS headers"""
        origin = request.headers.get('Origin')

        # Check if origin is allowed
        if origin and (origin in SECURITY_CONFIG['CORS_ORIGINS'] or '*' in SECURITY_CONFIG['CORS_ORIGINS']):
            response.headers['Access-Control-Allow-Origin'] = origin if origin != '*' else SECURITY_CONFIG['CORS_ORIGINS'][0]
            response.headers['Access-Control-Allow-Methods'] = ', '.join(SECURITY_CONFIG['CORS_METHODS'])
            response.headers['Access-Control-Allow-Headers'] = ', '.join(SECURITY_CONFIG['CORS_HEADERS'])
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Max-Age'] = '86400'  # 24 hours

    def validate_input(self, request) -> Optional[Dict[str, Any]]:
        """Input validation middleware"""
        try:
            # Check request size
            content_length = int(request.headers.get('Content-Length', '0'))
            if content_length > SECURITY_CONFIG['MAX_BODY_LENGTH']:
                logger.warning(f'Request too large: {content_length} bytes from {self.get_client_ip(request)}')
                return {'error': 'Request entity too large'}

            # Check URL length
            if len(request.url) > SECURITY_CONFIG['MAX_URL_LENGTH']:
                logger.warning(f'URL too long: {len(request.url)} chars from {self.get_client_ip(request)}')
                return {'error': 'URI too long'}

            # Validate query parameters
            if request.args:
                for key, value in request.args.items():
                    if isinstance(value, str) and len(value) > SECURITY_CONFIG['MAX_QUERY_LENGTH']:
                        logger.warning(f'Query parameter too long: {key} from {self.get_client_ip(request)}')
                        return {'error': 'Query parameter too long'}

                    # Check for suspicious patterns
                    if self.contains_suspicious_patterns(value):
                        logger.warning(f'Suspicious query parameter: {key} from {self.get_client_ip(request)}')
                        self.record_suspicious_activity(request)
                        return {'error': 'Invalid input detected'}

            # Validate body if present
            if request.get_json(silent=True):
                data = request.get_json()
                validation_result = self.validate_request_body(data)
                if not validation_result['valid']:
                    logger.warning(f'Invalid request body from {self.get_client_ip(request)}: {", ".join(validation_result["errors"])}')
                    return {
                        'error': 'Invalid input',
                        'details': validation_result['errors']
                    }

            return None  # No validation errors

        except Exception as e:
            logger.error(f'Input validation error: {e}')
            return {'error': 'Internal server error'}

    def sanitize_input(self, request) -> None:
        """Sanitize input data"""
        # Sanitize headers
        for key, value in request.headers.items():
            if isinstance(value, str):
                request.headers[key] = self.sanitize_string(value)

        # Sanitize query parameters
        if request.args:
            for key, value in request.args.items():
                if isinstance(value, str):
                    request.args[key] = self.sanitize_string(value)

        # Sanitize body
        if request.get_json(silent=True):
            data = request.get_json()
            request._cached_json = (self.sanitize_object(data), request._cached_json[1]) if hasattr(request, '_cached_json') else (self.sanitize_object(data), None)

    def get_client_ip(self, request) -> str:
        """Get client IP address"""
        return (request.remote_addr or
                request.environ.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip() or
                request.environ.get('REMOTE_ADDR') or
                'unknown')

    def build_csp(self) -> str:
        """Build Content Security Policy header"""
        return ' '.join([
            f"default-src {SECURITY_CONFIG['CSP_DEFAULT_SRC']}",
            f"script-src {SECURITY_CONFIG['CSP_SCRIPT_SRC']}",
            f"style-src {SECURITY_CONFIG['CSP_STYLE_SRC']}",
            f"img-src {SECURITY_CONFIG['CSP_IMG_SRC']}",
            f"font-src {SECURITY_CONFIG['CSP_FONT_SRC']}",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'"
        ])

    def contains_suspicious_patterns(self, value: str) -> bool:
        """Check for suspicious patterns in input"""
        if not isinstance(value, str):
            return False

        suspicious_patterns = [
            re.compile(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', re.IGNORECASE),
            re.compile(r'javascript:', re.IGNORECASE),
            re.compile(r'on\w+\s*=', re.IGNORECASE),
            re.compile(r'union\s+select', re.IGNORECASE),
            re.compile(r'drop\s+table', re.IGNORECASE),
            re.compile(r'\b(or|and)\b\s+\d+\s*=\s*\d+', re.IGNORECASE),
            re.compile(r'--', re.IGNORECASE),
            re.compile(r'\/\*.*\*\/', re.IGNORECASE)
        ]

        return any(pattern.search(value) for pattern in suspicious_patterns)

    def validate_request_body(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Validate request body data"""
        errors = []

        # Email validation
        if 'email' in body and not VALIDATION_PATTERNS['EMAIL'].match(body['email']):
            errors.append('Invalid email format')

        # Password validation
        if 'password' in body and not VALIDATION_PATTERNS['PASSWORD'].match(body['password']):
            errors.append('Password must be at least 12 characters with uppercase, lowercase, number, and special character')

        # Amount validation
        if 'amount' in body and not VALIDATION_PATTERNS['AMOUNT'].match(str(body['amount'])):
            errors.append('Invalid amount format')

        # Phone validation
        if 'phone' in body and not VALIDATION_PATTERNS['PHONE'].match(body['phone']):
            errors.append('Invalid phone number format')

        return {
            'valid': len(errors) == 0,
            'errors': errors
        }

    def sanitize_string(self, value: str) -> str:
        """Sanitize string input"""
        if not isinstance(value, str):
            return value

        # Remove script tags
        value = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', value, flags=re.IGNORECASE)
        # Remove javascript: URLs
        value = re.sub(r'javascript:', '', value, flags=re.IGNORECASE)
        # Remove event handlers
        value = re.sub(r'on\w+\s*=', '', value, flags=re.IGNORECASE)
        # Remove HTML tags
        value = re.sub(r'<[^>]*>', '', value)

        return value.strip()

    def sanitize_object(self, obj: Any) -> Any:
        """Sanitize object recursively"""
        if obj is None or not isinstance(obj, (dict, list)):
            return obj

        if isinstance(obj, list):
            return [self.sanitize_object(item) for item in obj]

        sanitized = {}
        for key, value in obj.items():
            if isinstance(value, str):
                sanitized[key] = self.sanitize_string(value)
            elif isinstance(value, (dict, list)):
                sanitized[key] = self.sanitize_object(value)
            else:
                sanitized[key] = value

        return sanitized

    def record_suspicious_activity(self, request) -> None:
        """Record suspicious activity"""
        client_ip = self.get_client_ip(request)
        activity = self.suspicious_activities.get(client_ip, {
            'count': 0,
            'last_activity': datetime.utcnow().timestamp(),
            'activities': []
        })

        activity['count'] += 1
        activity['last_activity'] = datetime.utcnow().timestamp()
        activity['activities'].append({
            'timestamp': datetime.utcnow().timestamp(),
            'path': request.path,
            'method': request.method,
            'user_agent': request.headers.get('User-Agent', '')
        })

        # Keep only last 10 activities
        if len(activity['activities']) > 10:
            activity['activities'] = activity['activities'][-10:]

        self.suspicious_activities[client_ip] = activity

        logger.warning(f'Suspicious activity recorded for IP: {client_ip}')

    def get_security_metrics(self) -> Dict[str, Any]:
        """Get security metrics"""
        return {
            'active_rate_limits': len(self.request_counts),
            'suspicious_activities': len(self.suspicious_activities),
            'total_requests': sum(data['count'] for data in self.request_counts.values())
        }

# Create singleton instance
security_middleware = SecurityMiddleware()

# Export functions for compatibility
def rate_limit(request):
    return security_middleware.rate_limit(request)

def security_headers(response):
    security_middleware.security_headers(response)

def cors_headers(request, response):
    security_middleware.cors_headers(request, response)

def validate_input(request):
    return security_middleware.validate_input(request)

def sanitize_input(request):
    security_middleware.sanitize_input(request)

def get_security_metrics():
    return security_middleware.get_security_metrics()
