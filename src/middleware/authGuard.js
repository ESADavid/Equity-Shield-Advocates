import { env } from '../config/env.js';

export function authGuard(req, res, next) {
  const auth = req.headers.authorization || '';
  const apiKey = req.headers['x-api-key'];

  const expectedBearer = env.internalApiKey ? `Bearer ${env.internalApiKey}` : null;
  const validBearer = expectedBearer && auth === expectedBearer;
  const validApiKey = env.internalApiKey && apiKey === env.internalApiKey;

  if (!validBearer && !validApiKey) {
    return res.status(401).json({
      ok: false,
      error: 'Unauthorized',
      requestId: req.requestId
    });
  }

  return next();
}
