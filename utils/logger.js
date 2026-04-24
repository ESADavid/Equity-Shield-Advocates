/**
 * Logger compatibility layer - Re-exports for require('../utils/logger') usage
 * Standardizes all logger imports across the codebase
 */
/* eslint-disable no-undef */

// Re-export core logger
export {
  logger,
  logInfo,
  logError,
  logWarn,
  logDebug,
  createLogger,
} from '../config/logger.js';

// Re-export wrapper methods
export {
  info,
  error,
  warn,
  debug,
  logRequest,
  logResponse,
  logDatabase,
  logAuth,
  logPayment,
  logSecurity,
  logPerformance,
  logBusinessEvent,
  child,
} from 'utils/loggerWrapper.js';

// Default export for require() compatibility
export default {
  info: logInfo,
  error: logError,
  warn: logWarn,
  debug: logDebug,
  logger,
};
