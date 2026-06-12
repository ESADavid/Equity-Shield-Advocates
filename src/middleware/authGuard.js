import { env } from '../config/env.js';

export function authGuard(req, res, next) {
  const configuredKey = String(process.env.INTERNAL_API_KEY || env.internalApiKey || '').trim();

  if (!configuredKey) {
    return res.status(401).json({
      ok: false,
      error: 'Unauthorized',
      requestId: req.requestId
    });
  }

  const authHeader = String(req.get('authorization') || '').trim();
  const apiKeyHeader = String(req.get('x-api-key') || '').trim();

  let bearerToken = '';
  if (/^bearer\s+/i.test(authHeader)) {
    bearerToken = authHeader.replace(/^bearer\s+/i, '').trim();
  }

  const validApiKey = apiKeyHeader.length > 0 && apiKeyHeader === configuredKey;
  const validBearer = bearerToken.length > 0 && bearerToken === configuredKey;

  if (!validBearer && !validApiKey) {
    return res.status(401).json({
      ok: false,
      error: 'Unauthorized',
      requestId: req.requestId
    });
  }

  return next();
}
