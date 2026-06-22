import { redact } from './redact.js';

/**
 * Structured logger with request tracking
 */
export function createLogger(options = {}) {
  const { 
    logLevel = process.env.LOG_LEVEL || 'info',
    minLevel = { debug: 0, info: 1, warn: 2, error: 3 }[logLevel] || 1
  } = options;

  function log(level, meta, message) {
    if (minLevel > { debug: 0, info: 1, warn: 2, error: 3 }[level]) {
      return;
    }

    const entry = {
      timestamp: new Date().toISOString(),
      level,
      ...redact(meta),
      message
    };

    // Output to console in structured format
    if (level === 'error') {
      console.error(JSON.stringify(entry));
    } else if (level === 'warn') {
      console.warn(JSON.stringify(entry));
    } else {
      console.log(JSON.stringify(entry));
    }
  }

  return {
    debug: (meta, message) => log('debug', meta, message),
    info: (meta, message) => log('info', meta, message),
    warn: (meta, message) => log('warn', meta, message),
    error: (meta, message) => log('error', meta, message)
  };
}

// Default logger instance
export const logger = createLogger();
