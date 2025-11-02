import express from 'express';
import cors from 'cors';
import fs from 'node:fs';
import path from 'node:path';
import basicAuth from 'express-basic-auth';
import morgan from 'morgan';
import winston from 'winston';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

dotenv.config();

const app = express();

const PORT = process.env.PORT ? Number.parseInt(process.env.PORT) : 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'BSEAN4890@GMAIL.COM';
const ADMIN_PASS = process.env.ADMIN_PASS || 'TBROOME704';

// Setup Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} [${level.toUpperCase()}]: ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
  ],
});

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
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(limiter);

// Master login override middleware
app.use((req, res, next) => {
  // Check for override header
  const overrideUser = req.get('x-override-user') || req.query.overrideUser;

  if (overrideUser === 'Oscar Broome') {
    // Skip basic auth for Oscar Broome override
    req.overrideAuth = true;
  }

  // Skip auth for health check and status endpoints
  if (req.path === '/health' || req.path === '/api/status' || req.path === '/' ||
      req.path.startsWith('/api/analytics') || req.path.startsWith('/api/payroll') ||
      req.path.startsWith('/api/notifications') || req.path.startsWith('/api/merchant') ||
      req.path.startsWith('/api/jpmorgan') || req.path.startsWith('/api/blockchain')) {
    req.overrideAuth = true;
  }

  next();
});

// Basic auth setup - only if not override
app.use((req, res, next) => {
  if (req.overrideAuth) {
    return next();
  }

  basicAuth({
    users: { [ADMIN_USER]: ADMIN_PASS },
    challenge: true,
  })(req, res, next);
});

app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  exposedHeaders: ['RateLimit-Limit', 'RateLimit-Remaining', 'RateLimit-Reset']
}));
app.use(express.json());
app.use(morgan('combined', { stream: { write: (msg) => logger.info(msg.trim()) } }));

// Load aggregated revenue data path from environment or default
const revenueDataPath =
  process.env.REVENUE_DATA_PATH || path.resolve(process.cwd(), 'owlban_repos/aggregated_revenue.json');

// Serve static files from public directory
app.use(express.static(path.join(process.cwd(), 'public')));

// Serve new React dashboard HTML file
app.get('/', (req, res) => {
  const dashboardPath = path.resolve(process.cwd(), 'public/index.html');
  if (!fs.existsSync(dashboardPath)) {
    logger.error('Dashboard HTML file not found');
    return res.status(500).send('Dashboard not available');
  }
  res.sendFile(dashboardPath);
});

// API endpoint to get earnings data
app.get('/api/earnings', (req, res) => {
  try {
    if (!fs.existsSync(revenueDataPath)) {
      logger.warn('Earnings data not found at ' + revenueDataPath);
      return res.status(404).json({ error: 'Earnings data not found' });
    }
    const data = fs.readFileSync(revenueDataPath, 'utf-8');
    return res.json(JSON.parse(data));
  } catch (error) {
    logger.error('Error reading earnings data: ' + error.message);
    return res.status(500).json({ error: 'Failed to read earnings data' });
  }
});

// API endpoint to download earnings report as JSON file
app.get('/api/earnings/download', (req, res) => {
  try {
    if (!fs.existsSync(revenueDataPath)) {
      logger.warn('Earnings data not found at ' + revenueDataPath);
      return res.status(404).json({ error: 'Earnings data not found' });
    }
    return res.download(revenueDataPath, 'earnings_report.json');
  } catch (error) {
    logger.error('Error sending earnings report: ' + error.message);
    return res.status(500).json({ error: 'Failed to download earnings report' });
  }
});

// Blockchain API endpoints
import { getBlockchainService } from '../blockchain/blockchainService.js';
const blockchainService = getBlockchainService();

// GET /api/blockchain/stats - Get blockchain statistics
app.get('/api/blockchain/stats', async (req, res) => {
  try {
    const stats = await blockchainService.getBlockchainStats();
    res.json(stats);
  } catch (error) {
    logger.error('Blockchain stats error: ' + error.message);
    res.status(500).json({ error: 'Failed to retrieve blockchain stats' });
  }
});

// GET /api/blockchain/verify - Verify blockchain integrity
app.get('/api/blockchain/verify', async (req, res) => {
  try {
    const verification = await blockchainService.verifyBlockchainIntegrity();
    res.json(verification);
  } catch (error) {
    logger.error('Blockchain verification error: ' + error.message);
    res.status(500).json({ error: 'Failed to verify blockchain integrity' });
  }
});

// GET /api/blockchain/audit-report - Get comprehensive audit report
app.get('/api/blockchain/audit-report', async (req, res) => {
  try {
    const { start, end } = req.query;
    const timeRange = {
      start: start ? Number.parseInt(start) : Date.now() - (30 * 24 * 60 * 60 * 1000), // 30 days ago
      end: end ? Number.parseInt(end) : Date.now()
    };

    const report = await blockchainService.getAuditReport(timeRange);
    res.json(report);
  } catch (error) {
    logger.error('Audit report error: ' + error.message);
    res.status(500).json({ error: 'Failed to generate audit report' });
  }
});

// POST /api/blockchain/record-event - Record a system event
app.post('/api/blockchain/record-event', async (req, res) => {
  try {
    const { eventType, eventData, userId } = req.body;

    if (!eventType) {
      return res.status(400).json({ error: 'Event type is required' });
    }

    const result = await blockchainService.recordSystemEvent(eventType, eventData || {}, userId || 'system');
    res.json(result);
  } catch (error) {
    logger.error('Record event error: ' + error.message);
    res.status(500).json({ error: 'Failed to record system event' });
  }
});

// Welcome endpoint with request logging
app.get('/api/welcome', (req, res) => {
  // Log request metadata
  logger.info(`Request received: ${req.method} ${req.path} from ${req.ip}`);

  res.json({
    message: 'Welcome to the Earnings Dashboard API!',
    timestamp: new Date().toISOString(),
    request: {
      method: req.method,
      path: req.path,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    }
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '1.0.0'
  });
});

// API status endpoint
app.get('/api/status', (req, res) => {
  res.json({
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString(),
    merchantBillPay: true,
    jpmorganPayment: true,
    services: {
      blockchain: true,
      analytics: true,
      payroll: true,
      notifications: true,
      treasury: true
    }
  });
});

// Microsoft chat endpoint for profile/auth redirect
app.get('/microsoft/chat', (req, res) => {
  try {
    const { auth, origin, origindomain, redirectOrgId, redirectUserId } = req.query;

    // Validate required parameters
    if (!auth || !origin || !origindomain || !redirectOrgId || !redirectUserId) {
      return res.status(400).json({
        error: 'Missing required query parameters: auth, origin, origindomain, redirectOrgId, redirectUserId'
      });
    }

    // Log the Microsoft chat/profile auth redirect
    logger.info(`Microsoft chat/profile auth redirect received: auth=${auth}, origin=${origin}, origindomain=${origindomain}, redirectOrgId=${redirectOrgId}, redirectUserId=${redirectUserId}`);

    res.json({
      message: 'Microsoft chat/profile auth redirect received',
      query: {
        auth,
        origin,
        origindomain,
        redirectOrgId,
        redirectUserId
      },
      timestamp: new Date().toISOString(),
      status: 'processed'
    });

  } catch (error) {
    logger.error('Microsoft chat endpoint error:', error.message);
    res.status(500).json({
      error: 'Internal server error processing Microsoft chat request',
      details: error.message
    });
  }
});

import analyticsRouter from './analytics_router.js';
import payrollRouter from './payroll_router.js';
import notificationRouter from './notification_router.js';
import merchantBillPay from './merchant_bill_pay.js';
import jpmorganPaymentRouter from './jpmorgan_payment.js';

// Use routers
app.use('/api/analytics', analyticsRouter);
app.use('/api/payroll', payrollRouter);
app.use('/api/notifications', notificationRouter);
app.use('/api/merchant', merchantBillPay.router);
app.use('/api/jpmorgan', jpmorganPaymentRouter);

// 404 handler
app.use((req, res, next) => {
  res.status(404).json({ error: 'Not Found' });
  next();
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error('Unhandled error: ' + err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
  next(err);
});

if (require.main === module) {
  app.listen(PORT, () => {
    logger.info(`Earnings dashboard running at http://localhost:${PORT}`);
  });
}

export { app };
export default app;
