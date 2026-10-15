import { timingSafeEqual } from 'node:crypto';
import { env } from '../config/env.js';

export function authGuard(req, res, next) {
  const configuredKey = env.internalApiKey;
  if (!configuredKey) {
    return res.status(503).json({
      error: 'Service Unavailable',
      message: 'Internal API authentication is not configured'
    });
  }

  const authorization = req.headers.authorization;
  if (typeof authorization !== 'string' || authorization.length === 0) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Missing authorization header'
    });
  }

  const token = authorization.replace(/^Bearer\s+/i, '');
  const providedKey = Buffer.from(token);
  const expectedKey = Buffer.from(configuredKey);
  if (
    providedKey.length !== expectedKey.length ||
    !timingSafeEqual(providedKey, expectedKey)
  ) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid token'
    });
  }

  next();
}
