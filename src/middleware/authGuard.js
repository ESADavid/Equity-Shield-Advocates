import { env } from '../config/env.js';
import { logger } from '../utils/logger.js';

function normalizeToken(value) {
  return String(value ?? '').replace(/\u0000/g, '').trim();
}

export function authGuard(req, res, next) {
  const configuredKey = normalizeToken(process.env.INTERNAL_API_KEY || env.internalApiKey);

  if (!configuredKey) {
    logger.warn('auth_guard_missing_configured_key', {
      requestId: req.requestId
    });
    return res.status(401).json({
      ok: false,
      error: 'Unauthorized',
      requestId: req.requestId
    });
  }

  const authHeader = normalizeToken(req.get('authorization'));
  const apiKeyHeader = normalizeToken(req.get('x-api-key'));

  let bearerToken = '';
  if (/^bearer\s+/i.test(authHeader)) {
    bearerToken = normalizeToken(authHeader.replace(/^bearer\s+/i, ''));
  }

  const validApiKey = apiKeyHeader.length > 0 && apiKeyHeader === configuredKey;
  const validBearer = bearerToken.length > 0 && bearerToken === configuredKey;

  if (!validBearer && !validApiKey) {
    logger.warn('auth_guard_rejected', {
      requestId: req.requestId,
      hasApiKey: apiKeyHeader.length > 0,
      hasBearer: bearerToken.length > 0,
      apiKeyLength: apiKeyHeader.length,
      bearerLength: bearerToken.length,
      configuredKeyLength: configuredKey.length,
      authHeaderPrefix: authHeader.slice(0, 12)
    });
    return res.status(401).json({
      ok: false,
      error: 'Unauthorized',
      requestId: req.requestId
    });
  }

  return next();
}
