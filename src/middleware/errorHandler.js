import { env } from '../config/env.js';

/**
 * Central error handler middleware
 * Maps upstream errors to safe output, includes requestId for traceability
 */
export function errorHandler(err, req, res, next) {
  const requestId = req.requestId || 'unknown';
  
  // Log the error (with redacted details)
  console.error(JSON.stringify({
    requestId,
    route: req.route?.path || req.path,
    method: req.method,
    error: err.message,
    stack: env.enableVerboseErrors ? err.stack : undefined
  }));
  
  // Determine status code
  let statusCode = err.response?.status || err.statusCode || 500;
  
  // Map common errors to appropriate codes
  if (err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT') {
    statusCode = 503; // Service unavailable
  } else if (err.response?.status === 401 || err.response?.status === 403) {
    statusCode = 401; // Unauthorized
  } else if (err.response?.status === 404) {
    statusCode = 404; // Not found
  } else if (err.response?.status >= 400 && err.response?.status < 500) {
    statusCode = 400; // Bad request
  }
  
  // Build safe error response
  const errorResponse = {
    error: statusCode >= 500 ? 'Internal Server Error' : 'Error',
    message: err.response?.data?.error || err.message || 'An unexpected error occurred',
    requestId
  };
  
  // Add status code
  errorResponse.statusCode = statusCode;
  
  // Hide stack traces in production
  if (env.enableVerboseErrors && err.stack) {
    errorResponse.stack = err.stack;
  }
  
  res.status(statusCode).json(errorResponse);
}
