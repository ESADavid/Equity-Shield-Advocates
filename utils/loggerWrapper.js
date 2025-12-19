/**
 * Logger Wrapper Utility
 * Provides convenient logging methods with environment-aware configuration
 *
 * @module utils/loggerWrapper
 */

import logger from '../config/logger.js';

/**
 * Environment-aware logger wrapper
 * Provides structured logging with context support
 */
class LoggerWrapper {
  constructor() {
    this.logger = logger;
    this.isDevelopment = process.env.NODE_ENV === 'development';
    this.isProduction = process.env.NODE_ENV === 'production';
  }

  /**
   * Log informational message
   * @param {string} message - Log message
   * @param {Object} meta - Additional metadata
   */
  info(message, meta = {}) {
    this.logger.info(message, {
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV,
      ...meta,
    });
  }

  /**
   * Log error message
   * @param {string} message - Error message
   * @param {Error|Object} error - Error object or metadata
   */
  error(message, error = {}) {
    const errorMeta =
      error instanceof Error
        ? {
            message: error.message,
            stack: this.isProduction ? undefined : error.stack,
            name: error.name,
          }
        : error;

    this.logger.error(message, {
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV,
      ...errorMeta,
    });
  }

  /**
   * Log warning message
   * @param {string} message - Warning message
   * @param {Object} meta - Additional metadata
   */
  warn(message, meta = {}) {
    this.logger.warn(message, {
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV,
      ...meta,
    });
  }

  /**
   * Log debug message (only in development)
   * @param {string} message - Debug message
   * @param {Object} meta - Additional metadata
   */
  debug(message, meta = {}) {
    if (this.isDevelopment) {
      this.logger.debug(message, {
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV,
        ...meta,
      });
    }
  }

  /**
   * Log HTTP request
   * @param {Object} req - Express request object
   * @param {Object} meta - Additional metadata
   */
  logRequest(req, meta = {}) {
    this.info('HTTP Request', {
      method: req.method,
      url: req.url,
      path: req.path,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      ...meta,
    });
  }

  /**
   * Log HTTP response
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {number} duration - Request duration in ms
   */
  logResponse(req, res, duration) {
    const level = res.statusCode >= 400 ? 'error' : 'info';
    this.logger[level]('HTTP Response', {
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Log database operation
   * @param {string} operation - Database operation type
   * @param {string} collection - Collection/table name
   * @param {Object} meta - Additional metadata
   */
  logDatabase(operation, collection, meta = {}) {
    this.debug('Database Operation', {
      operation,
      collection,
      ...meta,
    });
  }

  /**
   * Log authentication event
   * @param {string} event - Auth event type (login, logout, etc.)
   * @param {string} userId - User identifier
   * @param {Object} meta - Additional metadata
   */
  logAuth(event, userId, meta = {}) {
    this.info('Authentication Event', {
      event,
      userId,
      ...meta,
    });
  }

  /**
   * Log payment transaction
   * @param {string} transactionId - Transaction identifier
   * @param {string} status - Transaction status
   * @param {Object} meta - Additional metadata
   */
  logPayment(transactionId, status, meta = {}) {
    this.info('Payment Transaction', {
      transactionId,
      status,
      ...meta,
    });
  }

  /**
   * Log security event
   * @param {string} event - Security event type
   * @param {string} severity - Event severity (low, medium, high, critical)
   * @param {Object} meta - Additional metadata
   */
  logSecurity(event, severity, meta = {}) {
    const level =
      severity === 'critical' || severity === 'high' ? 'error' : 'warn';
    this.logger[level]('Security Event', {
      event,
      severity,
      ...meta,
    });
  }

  /**
   * Log performance metric
   * @param {string} metric - Metric name
   * @param {number} value - Metric value
   * @param {string} unit - Metric unit (ms, bytes, etc.)
   * @param {Object} meta - Additional metadata
   */
  logPerformance(metric, value, unit = 'ms', meta = {}) {
    this.debug('Performance Metric', {
      metric,
      value,
      unit,
      ...meta,
    });
  }

  /**
   * Log business event
   * @param {string} event - Business event type
   * @param {Object} data - Event data
   */
  logBusinessEvent(event, data = {}) {
    this.info('Business Event', {
      event,
      ...data,
    });
  }

  /**
   * Create child logger with context
   * @param {Object} context - Context to add to all logs
   * @returns {Object} Child logger with context
   */
  child(context = {}) {
    const self = this;
    return {
      info: (message, meta = {}) => self.info(message, { ...context, ...meta }),
      error: (message, error = {}) =>
        self.error(message, { ...context, ...error }),
      warn: (message, meta = {}) => self.warn(message, { ...context, ...meta }),
      debug: (message, meta = {}) =>
        self.debug(message, { ...context, ...meta }),
    };
  }
}

// Create singleton instance
const loggerWrapper = new LoggerWrapper();

// Export convenience methods
export const info = (message, meta) => loggerWrapper.info(message, meta);
export const error = (message, err) => loggerWrapper.error(message, err);
export const warn = (message, meta) => loggerWrapper.warn(message, meta);
export const debug = (message, meta) => loggerWrapper.debug(message, meta);
export const logRequest = (req, meta) => loggerWrapper.logRequest(req, meta);
export const logResponse = (req, res, duration) =>
  loggerWrapper.logResponse(req, res, duration);
export const logDatabase = (operation, collection, meta) =>
  loggerWrapper.logDatabase(operation, collection, meta);
export const logAuth = (event, userId, meta) =>
  loggerWrapper.logAuth(event, userId, meta);
export const logPayment = (transactionId, status, meta) =>
  loggerWrapper.logPayment(transactionId, status, meta);
export const logSecurity = (event, severity, meta) =>
  loggerWrapper.logSecurity(event, severity, meta);
export const logPerformance = (metric, value, unit, meta) =>
  loggerWrapper.logPerformance(metric, value, unit, meta);
export const logBusinessEvent = (event, data) =>
  loggerWrapper.logBusinessEvent(event, data);
export const child = (context) => loggerWrapper.child(context);

// Export default instance
export default loggerWrapper;
