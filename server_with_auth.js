#!/usr/bin/env node

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import logger from './utils/loggerWrapper.js';

// Import routes
import authRoutes from './routes/auth.js';
import transactionOverrideRoutes from './routes/transactionOverrideRoutes.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001; // Different port to avoid conflict
const NODE_ENV = process.env.NODE_ENV || 'development';

// Security middleware
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'https:'],
      },
    },
  })
);

// CORS configuration
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(',')
      : ['http://localhost:3001'],
    credentials: true,
  })
);

// Rate limiting
const createRateLimit = (windowMs, max, message) =>
  rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
  });

app.use(
  '/api/',
  createRateLimit(
    15 * 60 * 1000,
    100,
    'Too many requests from this IP, please try again later.'
  )
);

// Compression
app.use(
  compression({
    level: 6,
    threshold: 1024,
    filter: (req, res) => {
      if (req.headers['x-no-compression']) {
        return false;
      }
      return compression.filter(req, res);
    },
  })
);

// Logging
if (NODE_ENV === 'production') {
  const logsDir = path.join(__dirname, 'logs');
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir);
  }
  const accessLogStream = fs.createWriteStream(
    path.join(logsDir, 'access.log'),
    { flags: 'a' }
  );
  app.use(morgan('combined', { stream: accessLogStream }));
} else {
  app.use(morgan('dev'));
}

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/override', transactionOverrideRoutes);

// Health check endpoint
app.get('/health', async (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    version: process.env.npm_package_version || '1.0.0',
    uptime: process.uptime(),
    database: { status: 'json-based' },
    cache: { status: 'skipped' },
  };

  res.json(health);
});

// API status endpoint
app.get('/api/status', (req, res) => {
  const status = {
    auth: { loaded: true },
    override: { loaded: true },
    environment: {
      nodeVersion: process.version,
      environment: NODE_ENV,
      port: PORT,
    },
    services: {
      stripe: !!process.env.STRIPE_SECRET_KEY,
      smtp: !!(
        process.env.SMTP_HOST &&
        process.env.SMTP_USER &&
        process.env.SMTP_PASS
      ),
      twilio: !!(
        process.env.TWILIO_ACCOUNT_SID &&
        process.env.TWILIO_AUTH_TOKEN &&
        process.env.TWILIO_PHONE_NUMBER
      ),
      jpmorgan: !!(
        process.env.JPMORGAN_CLIENT_ID &&
        process.env.JPMORGAN_CLIENT_SECRET &&
        process.env.JPMORGAN_MERCHANT_ID &&
        process.env.JPMORGAN_TERMINAL_ID
      ),
      redis: false,
      database: false,
    },
  };

  res.json(status);
});

// Static file serving
app.use(
  express.static(path.join(__dirname, 'public'), {
    maxAge: '1d',
    setHeaders: (res, path) => {
      if (path.endsWith('.css') || path.endsWith('.js')) {
        res.set('Cache-Control', 'public, max-age=86400');
      }
    },
  })
);

// Catch-all handler for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'override-dashboard.html'));
});

// Error handling
app.use((err, req, res, next) => {
  logger.error('Error:', err);
  res.status(err.status || 500).json({
    error: NODE_ENV === 'production' ? 'Internal server error' : err.message,
    timestamp: new Date().toISOString(),
    path: req.path,
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    path: req.path,
    timestamp: new Date().toISOString(),
  });
});

// Start server
app.listen(PORT, () => {
  logger.info('🚀 OSCAR BROOME REVENUE - Auth Server');
  logger.info('====================================================');
  logger.info(`✅ Server running on port ${PORT}`);
  logger.info(`✅ Environment: ${NODE_ENV}`);
  logger.info(`✅ Health check: http://localhost:${PORT}/health`);
  logger.info(`✅ API status: http://localhost:${PORT}/api/status`);
  logger.info(`✅ Auth API: http://localhost:${PORT}/api/auth`);
  logger.info(`✅ Override API: http://localhost:${PORT}/api/override`);
  logger.info('✅ Database: JSON-based storage');
  logger.info(`✅ Started at: ${new Date().toISOString()}`);
  logger.info('');
});

export default app;
