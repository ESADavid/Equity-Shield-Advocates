import { Router } from 'express';
import { env } from '../config/env.js';

const router = Router();

/**
 * GET /health
 * Returns service health status
 */
router.get('/', (req, res) => {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    environment: env.nodeEnv,
    version: process.env.npm_package_version || '1.0.0',
    timestamp: new Date().toISOString()
  });
});

export default router;
