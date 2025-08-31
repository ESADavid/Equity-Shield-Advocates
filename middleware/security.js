const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, param, query, validationResult } = require('express-validator');
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
      )
    })
  ]
});

// Rate limiting configurations
const createPaymentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 payment creation requests per windowMs
  message: {
    success: false,
    error: 'Too many payment creation requests, please try again later',
    code: 'RATE_LIMIT_EXCEEDED',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    securityLogger.warn('Rate limit exceeded for payment creation', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.url
    });
    res.status(429).json({
      success: false,
      error: 'Too many payment creation requests, please try again later',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: '15 minutes'
    });
  }
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    success: false,
    error: 'Too many requests, please try again later',
    code: 'RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false
});

const webhookLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 1000, // Allow more webhook requests
  message: {
    success: false,
    error: 'Too many webhook requests',
    code: 'WEBHOOK_RATE_LIMIT_EXCEEDED'
  }
});

// Input validation middleware
const validatePaymentCreation = [
  body('amount')
    .isNumeric()
    .withMessage('Amount must be a number')
    .isFloat({ min: 0.01 })
    .withMessage('Amount must be greater than 0'),

  body('orderId')
    .isString()
    .withMessage('OrderId must be a string')
    .isLength({ min: 1, max: 100 })
    .withMessage('OrderId must be between 1 and 100 characters')
    .matches(/^[a-zA-Z0-9-_]+$/)
    .withMessage('OrderId contains invalid characters'),

  body('currency')
    .optional()
    .isIn(['USD', 'EUR', 'GBP'])
    .withMessage('Currency must be USD, EUR, or GBP'),

  body('description')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Description must not exceed 500 characters'),

  body('customer')
    .optional()
    .isObject()
    .withMessage('Customer must be an object'),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      securityLogger.warn('Input validation failed', {
        ip: req.ip,
        errors: errors.array(),
        body: req.body
      });

      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        code: 'VALIDATION_ERROR',
        details: errors.array(),
        timestamp: new Date().toISOString()
      });
    }
    next();
  }
];

const validateRefund = [
  body('paymentId')
    .isString()
    .withMessage('PaymentId must be a string')
    .isLength({ min: 1, max: 100 })
    .withMessage('PaymentId must be between 1 and 100 characters'),

  body('amount')
    .isNumeric()
    .withMessage('Amount must be a number')
    .isFloat({ min: 0.01 })
    .withMessage('Amount must be greater than 0'),

  body('reason')
    .optional()
    .isLength({ max: 200 })
    .withMessage('Reason must not exceed 200 characters'),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      securityLogger.warn('Refund validation failed', {
        ip: req.ip,
        errors: errors.array()
      });

      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        code: 'VALIDATION_ERROR',
        details: errors.array(),
        timestamp: new Date().toISOString()
      });
    }
    next();
  }
];

const validatePaymentId = [
  param('paymentId')
    .isString()
    .withMessage('PaymentId must be a string')
    .isLength({ min: 1, max: 100 })
    .withMessage('PaymentId must be between 1 and 100 characters'),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      securityLogger.warn('PaymentId validation failed', {
        ip: req.ip,
        errors: errors.array()
      });

      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        code: 'VALIDATION_ERROR',
        details: errors.array(),
        timestamp: new Date().toISOString()
      });
    }
    next();
  }
];

const validateTransactionsQuery = [
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('StartDate must be a valid ISO8601 date'),

  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('EndDate must be a valid ISO8601 date'),

  query('status')
    .optional()
    .isIn(['AUTHORIZED', 'CAPTURED', 'REFUNDED', 'VOIDED', 'FAILED'])
    .withMessage('Invalid status value'),

  query('limit')
    .optional()
    .isInt({ min: 1, max: 1000 })
    .withMessage('Limit must be between 1 and 1000'),

  query('offset')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Offset must be non-negative'),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      securityLogger.warn('Query validation failed', {
        ip: req.ip,
        errors: errors.array()
      });

      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        code: 'VALIDATION_ERROR',
        details: errors.array(),
        timestamp: new Date().toISOString()
      });
    }
    next();
  }
];

// Security headers middleware
const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
});

// Request sanitization middleware
const sanitizeInput = (req, res, next) => {
  // Recursively sanitize object properties
  const sanitize = (obj) => {
    for (let key in obj) {
      if (typeof obj[key] === 'string') {
        // Remove potential XSS vectors
        obj[key] = obj[key]
          .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
          .replace(/javascript:/gi, '')
          .replace(/on\w+\s*=/gi, '')
          .trim();
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        sanitize(obj[key]);
      }
    }
  };

  if (req.body && typeof req.body === 'object') {
    sanitize(req.body);
  }

  if (req.query && typeof req.query === 'object') {
    sanitize(req.query);
  }

  if (req.params && typeof req.params === 'object') {
    sanitize(req.params);
  }

  next();
};

// IP whitelist middleware (optional)
const ipWhitelist = (allowedIPs = []) => {
  return (req, res, next) => {
    if (allowedIPs.length > 0 && !allowedIPs.includes(req.ip)) {
      securityLogger.warn('IP not in whitelist', {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      return res.status(403).json({
        success: false,
        error: 'Access denied',
        code: 'IP_NOT_ALLOWED',
        timestamp: new Date().toISOString()
      });
    }
    next();
  };
};

// Request size limiter
const requestSizeLimiter = (maxSize = '10mb') => {
  return (req, res, next) => {
    const contentLength = parseInt(req.headers['content-length']);

    if (contentLength && contentLength > 10 * 1024 * 1024) { // 10MB
      securityLogger.warn('Request size too large', {
        ip: req.ip,
        contentLength
      });

      return res.status(413).json({
        success: false,
        error: 'Request too large',
        code: 'REQUEST_TOO_LARGE',
        timestamp: new Date().toISOString()
      });
    }
    next();
  };
};

// Export middleware functions
module.exports = {
  createPaymentLimiter,
  generalLimiter,
  webhookLimiter,
  validatePaymentCreation,
  validateRefund,
  validatePaymentId,
  validateTransactionsQuery,
  securityHeaders,
  sanitizeInput,
  ipWhitelist,
  requestSizeLimiter,
  securityLogger
};
