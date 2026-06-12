import { randomUUID } from 'crypto';

export function requestIdMiddleware(req, res, next) {
  const incoming = req.headers['x-request-id'];
  const requestId = incoming && String(incoming).trim() ? String(incoming) : randomUUID();

  req.requestId = requestId;
  res.setHeader('x-request-id', requestId);

  const start = Date.now();
  res.on('finish', () => {
    res.locals.latencyMs = Date.now() - start;
  });

  next();
}
