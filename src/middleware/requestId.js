import { randomUUID } from 'crypto';

/**
 * Request ID middleware
 * Generates and attaches a unique request ID to each request for traceability
 */
export function requestIdMiddleware(req, res, next) {
  const requestId = req.headers['x-request-id'] || randomUUID();
  req.requestId = requestId;
  res.setHeader('x-request-id', requestId);
  next();
}
