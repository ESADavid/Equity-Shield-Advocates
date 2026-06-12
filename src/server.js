import express from 'express';
import { env } from './config/env.js';
import { logger } from './utils/logger.js';
import { requestIdMiddleware } from './middleware/requestId.js';
import { errorHandler, notFoundHandler } from './middleware/errorHandler.js';
import healthRoutes from './routes/healthRoutes.js';
import oauthRoutes from './routes/oauthRoutes.js';
import bankingRoutes from './routes/bankingRoutes.js';
import aiRoutes from './routes/aiRoutes.js';

const app = express();

app.use(express.json({ limit: '1mb' }));
app.use(requestIdMiddleware);

app.use((req, res, next) => {
  const started = Date.now();
  res.on('finish', () => {
    logger.info('request_complete', {
      requestId: req.requestId,
      route: req.originalUrl,
      method: req.method,
      statusCode: res.statusCode,
      latency: Date.now() - started
    });
  });
  next();
});

app.use('/health', healthRoutes);
app.use('/api/oauth', oauthRoutes);
app.use('/api/banking', bankingRoutes);
app.use('/api/jpm', bankingRoutes);
app.use('/api/ai', aiRoutes);

app.use(notFoundHandler);
app.use(errorHandler);

app.listen(env.port, () => {
  logger.info('server_started', {
    port: env.port,
    nodeEnv: env.nodeEnv
  });
});
