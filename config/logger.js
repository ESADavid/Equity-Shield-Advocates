import winston from 'winston';
import { join } from 'path';
import { mkdirSync, existsSync } from 'fs';

// Use process.cwd() for cross-compatibility between ES modules and CommonJS
// This works in both environments after Babel transformation
const projectRoot = process.cwd();

// Ensure logs directory exists
const logsDir = join(projectRoot, 'logs');
if (!existsSync(logsDir)) {
  mkdirSync(logsDir, { recursive: true });
}

// Create Winston logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss',
    }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  defaultMeta: {
    service: 'oscar-broome-revenue',
    environment: process.env.NODE_ENV || 'development',
  },
  transports: [
    // Error logs
    new winston.transports.File({
      filename: join(logsDir, 'error.log'),
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    // Combined logs
    new winston.transports.File({
      filename: join(logsDir, 'combined.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
  ],
});

// Add console transport for non-production environments
if (process.env.NODE_ENV !== 'production') {
  logger.add(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    })
  );
}

// Create convenience methods
export const logInfo = (message, meta = {}) => logger.info(message, meta);
export const logError = (message, error = null, meta = {}) => {
  if (error instanceof Error) {
    logger.error(message, {
      ...meta,
      error: error.message,
      stack: error.stack,
    });
  } else {
    logger.error(message, meta);
  }
};
export const logWarn = (message, meta = {}) => logger.warn(message, meta);
export const logDebug = (message, meta = {}) => logger.debug(message, meta);

// Factory function to create logger instances
export const createLogger = (serviceName) => {
  return winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
      winston.format.timestamp({
        format: 'YYYY-MM-DD HH:mm:ss',
      }),
      winston.format.errors({ stack: true }),
      winston.format.splat(),
      winston.format.json()
    ),
    defaultMeta: {
      service: serviceName || 'oscar-broome-revenue',
      environment: process.env.NODE_ENV || 'development',
    },
    transports: [
      new winston.transports.File({
        filename: join(logsDir, 'error.log'),
        level: 'error',
        maxsize: 5242880,
        maxFiles: 5,
      }),
      new winston.transports.File({
        filename: join(logsDir, 'combined.log'),
        maxsize: 5242880,
        maxFiles: 5,
      }),
    ],
  });
};

// Export logger instance
export { logger };
export default logger;
