import express from 'express';
import { env } from './config/env.js';
import { logger } from './utils/logger.js';
import { requestIdMiddleware } from './middleware/requestId.js';
import { errorHandler, notFoundHandler } from './middleware/errorHandler.js';
import healthRoutes from './routes/healthRoutes.js';
import oauthRoutes from './routes/oauthRoutes.js';
import bankingRoutes from './routes/bankingRoutes.js';

async function bootstrap() {
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

  const disableAiRaw = String(process.env.DISABLE_AI_ROUTES || '').trim().toLowerCase();
  const aiRoutesDisabled = ['1', 'true', 'yes', 'on'].includes(disableAiRaw);

  if (aiRoutesDisabled) {
    logger.info('ai_routes_disabled', {
      disableAiRoutes: process.env.DISABLE_AI_ROUTES ?? null
    });
  } else {
    try {
      const aiModule = await import('./routes/aiRoutes.js');
      app.use('/api/ai', aiModule.default);
      logger.info('ai_routes_enabled', {
        disableAiRoutes: process.env.DISABLE_AI_ROUTES ?? null
      });
    } catch (aiRouteErr) {
      logger.error('ai_routes_load_failed', {
        disableAiRoutes: process.env.DISABLE_AI_ROUTES ?? null,
        message: aiRouteErr?.message || 'Unknown AI route load error'
      });
    }
  }

  app.use(notFoundHandler);
  app.use(errorHandler);

  app.listen(env.port, () => {
    logger.info('server_started', {
      port: env.port,
      nodeEnv: env.nodeEnv
    });
  });
}

bootstrap().catch((err) => {
  logger.error('server_bootstrap_failed', {
    message: err?.message || 'Unknown bootstrap error'
  });
  process.exit(1);
});
