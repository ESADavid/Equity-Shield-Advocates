import express from 'express';
import { env } from './config/env.js';
import { requestIdMiddleware } from './middleware/requestId.js';
import { errorHandler } from './middleware/errorHandler.js';
import healthRoutes from './routes/healthRoutes.js';
import oauthRoutes from './routes/oauthRoutes.js';
import bankingRoutes from './routes/bankingRoutes.js';

const app = express();

// Middleware
app.use(express.json());
app.use(requestIdMiddleware);

// Routes
app.use('/health', healthRoutes);
app.use('/api/oauth', oauthRoutes);
app.use('/api/banking', bankingRoutes);

// Protected route example (would need additional auth setup)
app.get('/api/jpm/ping', (req, res) => {
  res.json({
    ok: true,
    message: 'JPM Ping endpoint reached',
    requestId: req.requestId
  });
});

// Error handler (must be last)
app.use(errorHandler);

// Start server
const server = app.listen(env.port, () => {
  console.log(JSON.stringify({
    type: 'server_start',
    port: env.port,
    environment: env.nodeEnv,
    timestamp: new Date().toISOString()
  }));
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

export default app;
