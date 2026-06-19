/**
 * Oscar Broome Security Middleware
 * Implements OWASP security headers, input validation, and rate limiting
 */

const crypto = require('crypto');
const winston = require('winston');

// Security logger
const securityLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'security-middleware' },
  transports: [
    new winston.transports.File({ filename: 'logs/security.log' }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
  ],
});

// Security configuration
const SECURITY_CONFIG = {
  // Rate limiting
  RATE_LIMIT_WINDOW_MS:
    parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,

  // CORS settings
  CORS_ORIGINS: (
    process.env.CORS_ORIGINS || 'http://localhost:3000,http://localhost:8080'
  ).split(','),
  CORS_METHODS: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  CORS_HEADERS: ['Content-Type', 'Authorization', 'X-Requested-With'],

  // Content Security Policy
  CSP_DEFAULT_SRC: "'self'",
  CSP_SCRIPT_SRC: "'self' 'unsafe-inline' https://cdn.jsdelivr.net",
  CSP_STYLE_SRC: "'self' 'unsafe-inline' https://fonts.googleapis.com",
  CSP_IMG_SRC: "'self' data: https:",
  CSP_FONT_SRC: "'self' https://fonts.gstatic.com",

  // Security headers
  HSTS_MAX_AGE: 31536000, // 1 year
  HSTS_INCLUDE_SUBDOMAINS: true,
  HSTS_PRELOAD: false,

  // Input validation
  MAX_REQUEST_SIZE: '10mb',
  MAX_URL_LENGTH: 2048,
  MAX_QUERY_LENGTH: 1024,
  MAX_BODY_LENGTH: 1048576, // 1MB

  // XSS protection
  XSS_PROTECTION: true,
  XSS_BLOCK: true,

  // Content type options
  NO_SNIFF: true,

  // Frame options
  FRAME_OPTIONS: 'DENY',

  // Referrer policy
  REFERRER_POLICY: 'strict-origin-when-cross-origin',
};

// Rate limiting store
const rateLimitStore = new Map();

// Input validation patterns
const VALIDATION_PATTERNS = {
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  PASSWORD:
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/,
  USERNAME: /^[a-zA-Z0-9_-]{3,20}$/,
  PHONE: /^\+?[\d\s\-()]{10,}$/,
  ZIPCODE: /^\d{5}(-\d{4})?$/,
  CREDIT_CARD: /^\d{4}\s?\d{4}\s?\d{4}\s?\d{4}$/,
  AMOUNT: /^\d+(\.\d{1,2})?$/,
  ALPHA_ONLY: /^[a-zA-Z\s]+$/,
  ALPHA_NUMERIC: /^[a-zA-Z0-9\s]+$/,
};

class SecurityMiddleware {
  constructor() {
    this.requestCounts = new Map();
    this.suspiciousActivities = new Map();
  }

  // Rate limiting middleware
  rateLimit(req, res, next) {
    const clientIP = this.getClientIP(req);
    const key = `${clientIP}:${req.path}`;
    const now = Date.now();
    const windowStart = now - SECURITY_CONFIG.RATE_LIMIT_WINDOW_MS;

    // Clean old entries
    for (const [k, data] of this.requestCounts.entries()) {
      if (data.timestamp < windowStart) {
        this.requestCounts.delete(k);
      }
    }

    // Get or create request count for this key
    const requestData = this.requestCounts.get(key) || {
      count: 0,
      timestamp: now,
    };

    if (requestData.count >= SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS) {
      securityLogger.warn(
        `Rate limit exceeded for IP: ${clientIP}, path: ${req.path}`
      );
      return res.status(429).json({
        error: 'Too many requests',
        message: 'Rate limit exceeded. Please try again later.',
        retryAfter: Math.ceil(
          (requestData.timestamp + SECURITY_CONFIG.RATE_LIMIT_WINDOW_MS - now) /
            1000
        ),
      });
    }

    requestData.count++;
    requestData.timestamp = now;
    this.requestCounts.set(key, requestData);

    // Add rate limit headers
    res.set({
      'X-RateLimit-Limit': SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS,
      'X-RateLimit-Remaining': Math.max(
        0,
        SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS - requestData.count
      ),
      'X-RateLimit-Reset': new Date(
        requestData.timestamp + SECURITY_CONFIG.RATE_LIMIT_WINDOW_MS
      ).toISOString(),
    });

    next();
  }

  // Security headers middleware
  securityHeaders(req, res, next) {
    // OWASP Security Headers
    res.set({
      // Prevent MIME type sniffing
      'X-Content-Type-Options': 'nosniff',

      // Prevent clickjacking
      'X-Frame-Options': SECURITY_CONFIG.FRAME_OPTIONS,

      // XSS protection
      'X-XSS-Protection': `${SECURITY_CONFIG.XSS_PROTECTION ? '1' : '0'}${SECURITY_CONFIG.XSS_BLOCK ? '; mode=block' : ''}`,

      // Referrer policy
      'Referrer-Policy': SECURITY_CONFIG.REFERRER_POLICY,

      // Feature policy (permissions policy)
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',

      // Content Security Policy
      'Content-Security-Policy': this.buildCSP(),

      // HSTS (HTTP Strict Transport Security)
      'Strict-Transport-Security': `max-age=${SECURITY_CONFIG.HSTS_MAX_AGE}${SECURITY_CONFIG.HSTS_INCLUDE_SUBDOMAINS ? '; includeSubDomains' : ''}${SECURITY_CONFIG.HSTS_PRELOAD ? '; preload' : ''}`,

      // Remove server information
      Server: 'Oscar Broome Revenue System',

      // Cache control for sensitive content
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
      Pragma: 'no-cache',
      Expires: '0',
    });

    next();
  }

  // CORS middleware
  cors(req, res, next) {
    const origin = req.headers.origin;

    // Check if origin is allowed
    if (
      SECURITY_CONFIG.CORS_ORIGINS.includes('*') ||
      SECURITY_CONFIG.CORS_ORIGINS.includes(origin)
    ) {
      res.set({
        'Access-Control-Allow-Origin':
          origin || SECURITY_CONFIG.CORS_ORIGINS[0],
        'Access-Control-Allow-Methods': SECURITY_CONFIG.CORS_METHODS.join(', '),
        'Access-Control-Allow-Headers': SECURITY_CONFIG.CORS_HEADERS.join(', '),
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400', // 24 hours
      });
    }

    // Handle preflight requests
    if (req.method === 'OPTIONS') {
      res.status(200).end();
      return;
    }

    next();
  }

  // Input validation middleware
  validateInput(req, res, next) {
    try {
      // Check request size
      const contentLength = parseInt(req.headers['content-length'] || '0');
      if (contentLength > SECURITY_CONFIG.MAX_BODY_LENGTH) {
        securityLogger.warn(
          `Request too large: ${contentLength} bytes from ${this.getClientIP(req)}`
        );
        return res.status(413).json({ error: 'Request entity too large' });
      }

      // Check URL length
      if (req.url.length > SECURITY_CONFIG.MAX_URL_LENGTH) {
        securityLogger.warn(
          `URL too long: ${req.url.length} chars from ${this.getClientIP(req)}`
        );
        return res.status(414).json({ error: 'URI too long' });
      }

      // Validate query parameters
      if (req.query) {
        for (const [key, value] of Object.entries(req.query)) {
          if (
            typeof value === 'string' &&
            value.length > SECURITY_CONFIG.MAX_QUERY_LENGTH
          ) {
            securityLogger.warn(
              `Query parameter too long: ${key} from ${this.getClientIP(req)}`
            );
            return res.status(400).json({ error: 'Query parameter too long' });
          }

          // Check for suspicious patterns
          if (this.containsSuspiciousPatterns(value)) {
            securityLogger.warn(
              `Suspicious query parameter: ${key} from ${this.getClientIP(req)}`
            );
            this.recordSuspiciousActivity(req);
            return res.status(400).json({ error: 'Invalid input detected' });
          }
        }
      }

      // Validate body if present
      if (req.body && typeof req.body === 'object') {
        const validationResult = this.validateRequestBody(req.body);
        if (!validationResult.valid) {
          securityLogger.warn(
            `Invalid request body from ${this.getClientIP(req)}: ${validationResult.errors.join(', ')}`
          );
          return res.status(400).json({
            error: 'Invalid input',
            details: validationResult.errors,
          });
        }
      }

      next();
    } catch (error) {
      securityLogger.error(`Input validation error: ${error.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  // SQL injection and XSS protection
  sanitizeInput(req, res, next) {
    // Sanitize headers
    for (const [key, value] of Object.entries(req.headers)) {
      if (typeof value === 'string') {
        req.headers[key] = this.sanitizeString(value);
      }
    }

    // Sanitize query parameters
    if (req.query) {
      for (const [key, value] of Object.entries(req.query)) {
        if (typeof value === 'string') {
          req.query[key] = this.sanitizeString(value);
        }
      }
    }

    // Sanitize body
    if (req.body) {
      req.body = this.sanitizeObject(req.body);
    }

    next();
  }

  // Helper methods
  getClientIP(req) {
    return (
      req.ip ||
      req.connection.remoteAddress ||
      req.socket.remoteAddress ||
      (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
      'unknown'
    );
  }

  buildCSP() {
    return [
      `default-src ${SECURITY_CONFIG.CSP_DEFAULT_SRC}`,
      `script-src ${SECURITY_CONFIG.CSP_SCRIPT_SRC}`,
      `style-src ${SECURITY_CONFIG.CSP_STYLE_SRC}`,
      `img-src ${SECURITY_CONFIG.CSP_IMG_SRC}`,
      `font-src ${SECURITY_CONFIG.CSP_FONT_SRC}`,
      "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; ');
  }

  containsSuspiciousPatterns(value) {
    if (typeof value !== 'string') return false;

    const suspiciousPatterns = [
      /<script/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /union\s+select/i,
      /drop\s+table/i,
      /\bor\b\s+\d+\s*=\s*\d+|\band\b\s+\d+\s*=\s*\d+/i,
      /--/g,
      /\/\*.*\*\//g,
    ];

    return suspiciousPatterns.some((pattern) => pattern.test(value));
  }

  validateRequestBody(body) {
    const errors = [];

    // Email validation
    if (body.email && !VALIDATION_PATTERNS.EMAIL.test(body.email)) {
      errors.push('Invalid email format');
    }

    // Password validation
    if (body.password && !VALIDATION_PATTERNS.PASSWORD.test(body.password)) {
      errors.push(
        'Password must be at least 12 characters with uppercase, lowercase, number, and special character'
      );
    }

    // Amount validation
    if (
      body.amount &&
      !VALIDATION_PATTERNS.AMOUNT.test(body.amount.toString())
    ) {
      errors.push('Invalid amount format');
    }

    // Phone validation
    if (body.phone && !VALIDATION_PATTERNS.PHONE.test(body.phone)) {
      errors.push('Invalid phone number format');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  sanitizeString(str) {
    if (typeof str !== 'string') return str;

    return str
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      .replace(/javascript:/gi, '')
      .replace(/on\w+\s*=/gi, '')
      .replace(/<[^>]*>/g, '')
      .trim();
  }

  sanitizeObject(obj) {
    if (obj === null || typeof obj !== 'object') return obj;

    if (Array.isArray(obj)) {
      return obj.map((item) => this.sanitizeObject(item));
    }

    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string') {
        sanitized[key] = this.sanitizeString(value);
      } else if (typeof value === 'object') {
        sanitized[key] = this.sanitizeObject(value);
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  recordSuspiciousActivity(req) {
    const clientIP = this.getClientIP(req);
    const activity = this.suspiciousActivities.get(clientIP) || {
      count: 0,
      lastActivity: new Date(),
      activities: [],
    };

    activity.count++;
    activity.lastActivity = new Date();
    activity.activities.push({
      timestamp: new Date(),
      path: req.path,
      method: req.method,
      userAgent: req.headers['user-agent'],
    });

    // Keep only last 10 activities
    if (activity.activities.length > 10) {
      activity.activities = activity.activities.slice(-10);
    }

    this.suspiciousActivities.set(clientIP, activity);

    securityLogger.warn(`Suspicious activity recorded for IP: ${clientIP}`);
  }

  // Get security metrics
  getSecurityMetrics() {
    return {
      activeRateLimits: this.requestCounts.size,
      suspiciousActivities: this.suspiciousActivities.size,
      totalRequests: Array.from(this.requestCounts.values()).reduce(
        (sum, data) => sum + data.count,
        0
      ),
    };
  }
}

// Export middleware functions
const securityMiddleware = new SecurityMiddleware();

module.exports = {
  SecurityMiddleware,
  securityMiddleware,
  rateLimit: (req, res, next) => securityMiddleware.rateLimit(req, res, next),
  securityHeaders: (req, res, next) =>
    securityMiddleware.securityHeaders(req, res, next),
  cors: (req, res, next) => securityMiddleware.cors(req, res, next),
  validateInput: (req, res, next) =>
    securityMiddleware.validateInput(req, res, next),
  sanitizeInput: (req, res, next) =>
    securityMiddleware.sanitizeInput(req, res, next),
  getSecurityMetrics: () => securityMiddleware.getSecurityMetrics(),
};
