import { env } from '../config/env.js';
import { logger } from '../utils/logger.js';

export function notFoundHandler(req, res) {
  return res.status(404).json({
    ok: false,
    error: 'Not Found',
    requestId: req.requestId
  });
}

export function errorHandler(err, req, res, next) {
  const isMalformedJson = err?.type === 'entity.parse.failed' || err instanceof SyntaxError;
  const statusCode = isMalformedJson ? 400 : (err.statusCode || err.status || 500);

  logger.error('Request failed', {
    requestId: req.requestId,
    route: req.originalUrl,
    method: req.method,
    statusCode,
    latencyMs: res.locals.latencyMs,
    upstreamStatus: err.upstreamStatus,
    error: err.message
  });

  const payload = {
    ok: false,
    error: isMalformedJson
      ? 'Malformed JSON body'
      : (err.publicMessage || err.message || 'Internal Server Error'),
    requestId: req.requestId
  };

  if (env.verboseErrors && env.nodeEnv !== 'production') {
    payload.details = {
      stack: err.stack,
      upstream: err.upstreamBody || null
    };
  }

  return res.status(statusCode).json(payload);
}
