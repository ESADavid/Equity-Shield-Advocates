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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'],
  credentials: true
}));

// Rate limiting
const createRateLimit = (windowMs, max, message) => rateLimit({
  windowMs,
  max,
  message: { error: message },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', createRateLimit(15 * 60 * 1000, 100, 'Too many requests from this IP, please try again later.'));

// Compression
app.use(compression({
  level: 6,
  threshold: 1024,
  filter: (req, res) => {
    if (req.headers['x-no-compression']) {
      return false;
    }
    return compression.filter(req, res);
  }
}));

// Logging
if (NODE_ENV === 'production') {
  const logsDir = path.join(__dirname, 'logs');
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir);
  }
  const accessLogStream = fs.createWriteStream(path.join(logsDir, 'access.log'), { flags: 'a' });
  app.use(morgan('combined', { stream: accessLogStream }));
} else {
  app.use(morgan('dev'));
}

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health check endpoint
app.get('/health', async (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    version: process.env.npm_package_version || '1.0.0',
    uptime: process.uptime(),
    database: { status: 'skipped' },
    cache: { status: 'skipped' }
  };

  res.json(health);
});

// API status endpoint
app.get('/api/status', (req, res) => {
  const status = {
    merchantBillPay: { loaded: false },
    jpmorganPayment: { loaded: false },
    environment: {
      nodeVersion: process.version,
      environment: NODE_ENV,
      port: PORT
    },
    services: {
      stripe: !!process.env.STRIPE_SECRET_KEY,
      smtp: !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS),
      twilio: !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_PHONE_NUMBER),
      jpmorgan: !!(process.env.JPMORGAN_CLIENT_ID && process.env.JPMORGAN_CLIENT_SECRET && process.env.JPMORGAN_MERCHANT_ID && process.env.JPMORGAN_TERMINAL_ID),
      redis: false,
      database: false
    }
  };

  res.json(status);
});

// Static file serving
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1d',
  setHeaders: (res, path) => {
    if (path.endsWith('.css') || path.endsWith('.js')) {
      res.set('Cache-Control', 'public, max-age=86400');
    }
  }
}));

// Catch-all handler for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'override-dashboard.html'));
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    error: NODE_ENV === 'production' ? 'Internal server error' : err.message,
    timestamp: new Date().toISOString(),
    path: req.path
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    path: req.path,
    timestamp: new Date().toISOString()
  });
});

// Start server
app.listen(PORT, () => {
  console.log('🚀 OSCAR BROOME REVENUE - Simple Server');
  console.log('====================================================');
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`✅ Environment: ${NODE_ENV}`);
  console.log(`✅ Health check: http://localhost:${PORT}/health`);
  console.log(`✅ API status: http://localhost:${PORT}/api/status`);
  console.log('✅ Database and cache skipped for testing');
  console.log(`✅ Started at: ${new Date().toISOString()}`);
  console.log('');
});

export default app;
