/**
 * Centralized Error Handler Middleware
 * Provides consistent error handling and logging across the application
 *
 * @module middleware/errorHandler
 */

import { error as logError, warn as logWarn } from 'utils/loggerWrapper.js';

/**
 * Custom Application Error class
 */
export class AppError extends Error {
  constructor(message, statusCode = 500, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.timestamp = new Date().toISOString();
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Error classification helper
 * @param {number} statusCode - HTTP status code
 * @returns {string} Error type
 */
function classifyError(statusCode) {
  if (statusCode >= 500) return 'server_error';
  if (statusCode >= 400) return 'client_error';
  return 'unknown_error';
}

/**
 * Format error response
 * @param {Error} err - Error object
 * @param {boolean} isDevelopment - Is development environment
 * @returns {Object} Formatted error response
 */
function formatErrorResponse(err, isDevelopment) {
  const statusCode = err.statusCode || 500;
  const errorType = classifyError(statusCode);

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
 * @param {Error} err - Error object
 * @param {Object} req - Express request object
 */
function logErrorWithContext(err, req) {
  const errorContext = {
    message: err.message,
    statusCode: err.statusCode || 500,
    method: req.method,
    url: req.url,
    path: req.path,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    userId: req.user?.id || req.user?.userId || 'anonymous',
    requestId: req.id || req.headers['x-request-id'],
    timestamp: new Date().toISOString(),
  };

  // Add stack trace in development
  if (process.env.NODE_ENV === 'development') {
    errorContext.stack = err.stack;
  }

  // Log based on error severity
  if (err.statusCode >= 500 || !err.isOperational) {
    logError('Server Error', errorContext);
  } else {
    logWarn('Client Error', errorContext);
  }
}

/**
 * Main error handler middleware
 * @param {Error} err - Error object
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
export function errorHandler(err, req, res, next) {
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
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
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
 * @param {Function} fn - Async function to wrap
 * @returns {Function} Wrapped function
 */
export function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/**
 * Validation error handler
 * @param {Array} errors - Validation errors
 * @returns {AppError} Formatted validation error
 */
export function validationError(errors) {
  const message = errors.map((err) => err.message || err.msg).join(', ');
  const error = new AppError(`Validation Error: ${message}`, 400, true);
  error.details = errors;
  return error;
}

/**
 * Database error handler
 * @param {Error} err - Database error
 * @returns {AppError} Formatted database error
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
 * @param {string} message - Error message
 * @returns {AppError} Formatted authentication error
 */
export function authenticationError(message = 'Authentication failed') {
  return new AppError(message, 401, true);
}

/**
 * Authorization error handler
 * @param {string} message - Error message
 * @returns {AppError} Formatted authorization error
 */
export function authorizationError(message = 'Access denied') {
  return new AppError(message, 403, true);
}

/**
 * Payment error handler
 * @param {string} message - Error message
 * @param {Object} details - Error details
 * @returns {AppError} Formatted payment error
 */
export function paymentError(
  message = 'Payment processing failed',
  details = {}
) {
  const error = new AppError(message, 402, true);
  error.details = details;
  return error;
}

/**
 * Rate limit error handler
 * @param {string} message - Error message
 * @returns {AppError} Formatted rate limit error
 */
export function rateLimitError(message = 'Too many requests') {
  return new AppError(message, 429, true);
}

/**
 * Service unavailable error handler
 * @param {string} service - Service name
 * @returns {AppError} Formatted service error
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
      reason: reason instanceof Error ? reason.message : reason,
      stack: reason instanceof Error ? reason.stack : undefined,
      promise: promise.toString(),
    });

    // In production, you might want to gracefully shutdown
    if (process.env.NODE_ENV === 'production') {
      // Perform cleanup and exit
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
 * Convenience function to register both handlers at once
 */
export function setupUnhandledRejectionHandlers() {
  unhandledRejectionHandler();
  uncaughtExceptionHandler();
}

// Export default error handler
export default errorHandler;
