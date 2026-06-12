import { Router } from 'express';
import { env } from '../config/env.js';

const router = Router();

router.get('/', (req, res) => {
  res.json({
    ok: true,
    uptime: process.uptime(),
    environment: env.nodeEnv,
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    requestId: req.requestId
  });
});

export default router;
