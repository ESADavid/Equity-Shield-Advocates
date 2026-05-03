/**
 * Centralized Error Handler Middleware
 * Provides consistent error handling and logging across the application
 *
 * @module middleware/errorHandler
 */

import { error as logError, warn as logWarn } from '../utils/loggerWrapper.js';

/**
 * Custom Application Error class with additional properties
 * @extends Error
 */
export class AppError extends Error {
  /** @type {number} */
  statusCode;
  /** @type {boolean} */
  isOperational;
  /** @type {string} */
  timestamp;
  /** @type {*} */
  details;
  /** @type {string} */
  requestId;

  /**
   * @param {string} message - Error message
   * @param {number} [statusCode=500] - HTTP status code
   * @param {boolean} [isOperational=true] - Whether this is an operational error
   */
  constructor(message, statusCode = 500, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.timestamp = new Date().toISOString();
    this.details = undefined;
    this.requestId = undefined;
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Extended error type for database errors
 * @typedef {Error & {code?: number, name?: string}} DatabaseError
 */

/**
 * Error classification helper
 * @param {number} statusCode
 * @returns {string}
 */
function classifyError(statusCode) {
  if (statusCode >= 500) return 'server_error';
  if (statusCode >= 400) return 'client_error';
  return 'unknown_error';
}

/**
 * Format error response
 * @param {AppError} err
 * @param {boolean} isDevelopment
 * @returns {Object}
 */
function formatErrorResponse(err, isDevelopment) {
  const statusCode = err.statusCode || 500;
  const errorType = classifyError(statusCode);

  /** @type {Object} */
  const response = {
    success: false,
    error: {
      type: errorType,
      message: err.message || 'An unexpected error occurred',
      statusCode,
      timestamp: err.timestamp || new Date().toISOString(),
    },
  };

  // Add additional details in development
  if (isDevelopment) {
    response.error.stack = err.stack;
    response.error.details = err.details || null;
  }

  // Add request ID if available
  if (err.requestId) {
    response.error.requestId = err.requestId;
  }

  return response;
}

/**
 * Log error with context
 * @param {AppError} err
 * @param {Object} req
 */
function logErrorWithContext(err, req) {
  /** @type {Object} */
  const errorContext = {
    message: err.message,
    statusCode: err.statusCode || 500,
    method: req.method,
    url: req.url,
    path: req.path,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    userId: req.user?.id || req.user?.userId || 'anonymous',
    requestId: req.id || req.headers?.['x-request-id'],
    timestamp: new Date().toISOString(),
  };

  // Add stack trace in development
  if (process.env.NODE_ENV === 'development') {
    errorContext.stack = err.stack;
  }

  // Log based on error severity
  const statusCode = err.statusCode;
  const isOperational = err.isOperational;
  if (statusCode >= 500 || !isOperational) {
    logError('Server Error', errorContext);
  } else {
    logWarn('Client Error', errorContext);
  }
}

/**
 * Main error handler middleware
 * @param {AppError} err
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
export function errorHandler(err, req, res, _next) {
  // Set default status code if not set
  err.statusCode = err.statusCode || 500;
  err.isOperational =
    err.isOperational !== undefined ? err.isOperational : false;

  // Log error with context
  logErrorWithContext(err, req);

  // Determine if we're in development
  const isDevelopment = process.env.NODE_ENV === 'development';

  // Format error response
  const errorResponse = formatErrorResponse(err, isDevelopment);

  // Send error response
  res.status(err.statusCode).json(errorResponse);
}

/**
 * Handle 404 Not Found errors
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
export function notFoundHandler(req, res, next) {
  const error = new AppError(
    `Route not found: ${req.method} ${req.originalUrl}`,
    404,
    true
  );
  next(error);
}

/**
 * Async error wrapper
 * Wraps async route handlers to catch errors
 * @param {Function} fn
 * @returns {Function}
 */
export function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/**
 * Validation error handler
 * @param {Array<{message?: string, msg?: string}>} errors
 * @returns {AppError}
 */
export function validationError(errors) {
  const message = errors.map((err) => err.message || err.msg).join(', ');
  const error = new AppError(`Validation Error: ${message}`, 400, true);
  error.details = errors;
  return error;
}

/**
 * Database error handler
 * @param {DatabaseError} err
 * @returns {AppError}
 */
export function databaseError(err) {
  let message = 'Database operation failed';
  let statusCode = 500;

  // Handle specific database errors
  if (err.code === 11000) {
    message = 'Duplicate entry found';
    statusCode = 409;
  } else if (err.name === 'ValidationError') {
    message = 'Database validation failed';
    statusCode = 400;
  } else if (err.name === 'CastError') {
    message = 'Invalid data format';
    statusCode = 400;
  }

  const error = new AppError(message, statusCode, true);
  error.details = {
    originalError: err.message,
    code: err.code,
    name: err.name,
  };
  return error;
}

/**
 * Authentication error handler
 * @param {string} [message='Authentication failed']
 * @returns {AppError}
 */
export function authenticationError(message = 'Authentication failed') {
  return new AppError(message, 401, true);
}

/**
 * Authorization error handler
 * @param {string} [message='Access denied']
 * @returns {AppError}
 */
export function authorizationError(message = 'Access denied') {
  return new AppError(message, 403, true);
}

/**
 * Payment error handler
 * @param {string} [message='Payment processing failed']
 * @param {Object} [details={}]
 * @returns {AppError}
 */
export function paymentError(message = 'Payment processing failed', details = {}) {
  const error = new AppError(message, 402, true);
  error.details = details;
  return error;
}

/**
 * Rate limit error handler
 * @param {string} [message='Too many requests']
 * @returns {AppError}
 */
export function rateLimitError(message = 'Too many requests') {
  return new AppError(message, 429, true);
}

/**
 * Service unavailable error handler
 * @param {string} [service='Service']
 * @returns {AppError}
 */
export function serviceUnavailableError(service = 'Service') {
  return new AppError(`${service} is temporarily unavailable`, 503, true);
}

/**
 * Unhandled rejection handler
 * Should be registered at application level
 */
export function unhandledRejectionHandler() {
  process.on('unhandledRejection', (reason, promise) => {
    logError('Unhandled Promise Rejection', {
      reason: reason instanceof Error ? reason.message : String(reason),
      stack: reason instanceof Error ? reason.stack : undefined,
      promise: String(promise),
    });

    // In production, you might want to gracefully shutdown
    if (process.env.NODE_ENV === 'production') {
      process.exit(1);
    }
  });
}

/**
 * Uncaught exception handler
 * Should be registered at application level
 */
export function uncaughtExceptionHandler() {
  process.on('uncaughtException', (error) => {
    logError('Uncaught Exception', {
      message: error.message,
      stack: error.stack,
      name: error.name,
    });

    // Exit process after logging
    process.exit(1);
  });
}

/**
 * Setup all unhandled rejection and exception handlers
 */
export function setupUnhandledRejectionHandlers() {
  unhandledRejectionHandler();
  uncaughtExceptionHandler();
}

// Export default error handler
export default errorHandler;
