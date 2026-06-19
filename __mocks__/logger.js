/**
 * Mock for config/logger.js
 * Provides a mock winston logger for testing
 */

const mockLogger = {
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
  log: jest.fn(),
};

const createLogger = jest.fn(() => mockLogger);

const logger = mockLogger;

export { logger, createLogger };
export default mockLogger;
