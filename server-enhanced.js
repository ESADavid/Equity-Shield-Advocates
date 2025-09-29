#!/usr/bin/env node

import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer } from 'http';
import { Server } from 'socket.io';
import NotificationService from './earnings_dashboard/notification_service.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Create HTTP server
const server = createServer(app);

// Initialize Socket.IO
const io = new Server(server, {
  cors: {
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'],
    methods: ['GET', 'POST']
  }
});

// Initialize notification service
const notificationService = new NotificationService(io);

// Import merchant bill pay system
let merchantBillPay;
try {
  const merchantModule = await import('./earnings_dashboard/merchant_bill_pay.js');
  merchantBillPay = merchantModule.default || merchantModule;
  console.log('✅ Merchant bill pay system loaded successfully');
} catch (error) {
  console.error('❌ Failed to load merchant bill pay system:', error.message);
  process.exit(1);
}

// Import JPMorgan payment system
let jpmorganRouter;
try {
  const jpmorganModule = await import('./earnings_dashboard/jpmorgan_payment.js');
  jpmorganRouter = jpmorganModule.default || jpmorganModule;
  console.log('✅ JPMorgan payment system loaded successfully');
} catch (error) {
  console.error('❌ Failed to load JPMorgan payment system:', error.message);
  process.exit(1);
}

// Import payroll system
let payrollRouter;
try {
  const payrollModule = await import('./earnings_dashboard/payroll_router.js');
  payrollRouter = payrollModule.default || payrollModule;
  console.log('✅ Payroll system loaded successfully');
} catch (error) {
  console.error('❌ Failed to load payroll system:', error.message);
  process.exit(1);
}

// Import analytics system
let analyticsRouter;
try {
  const analyticsModule = await import('./earnings_dashboard/analytics_router.js');
  analyticsRouter = analyticsModule.default || analyticsModule;
  console.log('✅ Analytics system loaded successfully');
} catch (error) {
  console.error('❌ Failed to load analytics system:', error.message);
  process.exit(1);
}

// Import notification system
let notificationRouter;
try {
  const { default: createNotificationRouter } = await import('./earnings_dashboard/notification_router.js');
  notificationRouter = createNotificationRouter(notificationService);
  console.log('✅ Notification system loaded successfully');
} catch (error) {
  console.error('❌ Failed to load notification system:', error.message);
  process.exit(1);
}

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
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);

// Compression
app.use(compression());

// Logging
if (NODE_ENV === 'production') {
  // Create logs directory if it doesn't exist
  const logsDir = path.join(__dirname, 'logs');
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir);
  }

  // Write logs to file
  const accessLogStream = fs.createWriteStream(path.join(logsDir, 'access.log'), { flags: 'a' });
  app.use(morgan('combined', { stream: accessLogStream }));
} else {
  app.use(morgan('dev'));
}

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    version: process.env.npm_package_version || '1.0.0',
    uptime: process.uptime()
  });
});

// API status endpoint
app.get('/api/status', (req, res) => {
  const status = {
    merchantBillPay: {
      loaded: !!merchantBillPay,
      functions: merchantBillPay ? Object.keys(merchantBillPay).filter(key => typeof merchantBillPay[key] === 'function') : []
    },
    jpmorganPayment: {
      loaded: !!jpmorganRouter,
      functions: jpmorganRouter ? Object.keys(jpmorganRouter).filter(key => typeof jpmorganRouter[key] === 'function') : []
    },
    environment: {
      nodeVersion: process.version,
      environment: NODE_ENV,
      port: PORT
    },
    services: {
      stripe: !!process.env.STRIPE_SECRET_KEY,
      smtp: !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS),
      twilio: !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_PHONE_NUMBER),
      jpmorgan: !!(process.env.JPMORGAN_CLIENT_ID && process.env.JPMORGAN_CLIENT_SECRET && process.env.JPMORGAN_MERCHANT_ID && process.env.JPMORGAN_TERMINAL_ID)
    }
  };

  res.json(status);
});

// Merchant Bill Pay API Routes
if (merchantBillPay && merchantBillPay.router) {
  app.use('/api/merchant', merchantBillPay.router);
  console.log('✅ Merchant bill pay routes mounted at /api/merchant');
}

// JPMorgan Payment API Routes
if (jpmorganRouter) {
  app.use('/jpmorgan', jpmorganRouter);
  console.log('✅ JPMorgan payment routes mounted at /jpmorgan');
}

// Payroll API Routes
if (payrollRouter) {
  app.use('/api/payroll', payrollRouter);
  console.log('✅ Payroll routes mounted at /api/payroll');
}

// Analytics API Routes
if (analyticsRouter) {
  app.use('/api/analytics', analyticsRouter);
  console.log('✅ Analytics routes mounted at /api/analytics');
}

// Notification API Routes
if (notificationRouter) {
  app.use('/api/notifications', notificationRouter);
  console.log('✅ Notification routes mounted at /api/notifications');
}

// Webhook endpoint for Stripe
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    if (!merchantBillPay || !merchantBillPay.handleMerchantWebhook) {
      return res.status(500).json({ error: 'Webhook handler not available' });
    }

    await merchantBillPay.handleMerchantWebhook(req, res);
  } catch (error) {
    console.error('Webhook processing error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

import { fileURLToPath } from 'url';
import path from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import mime from 'mime';

// Static file serving for frontend with correct MIME types
app.use((req, res, next) => {
  if (req.path === '/styles.css') {
    const cssPath = path.join(__dirname, 'public', 'override-dashboard.css');
    res.type(mime.getType(cssPath));
    res.sendFile(cssPath);
  } else {
    next();
  }
});

app.use(express.static(path.join(__dirname, 'public')));

// Catch-all handler for SPA
app.get('*', (req, res) => {
  // Serve override-dashboard.html instead of missing index.html
  res.sendFile(path.join(__dirname, 'public', 'override-dashboard.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);

  // Don't leak error details in production
  const errorResponse = {
    error: NODE_ENV === 'production' ? 'Internal server error' : err.message,
    timestamp: new Date().toISOString(),
    path: req.path
  };

  res.status(err.status || 500).json(errorResponse);
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    path: req.path,
    timestamp: new Date().toISOString()
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    process.exit(0);
  });
});

// Unhandled promise rejection handler
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Don't exit in production, just log
  if (NODE_ENV !== 'production') {
    process.exit(1);
  }
});

// Uncaught exception handler
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  // Don't exit in production, just log
  if (NODE_ENV !== 'production') {
    process.exit(1);
  }
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('🔌 Client connected:', socket.id);

  socket.on('disconnect', () => {
    console.log('🔌 Client disconnected:', socket.id);
  });

  socket.on('subscribe-notifications', (userId) => {
    socket.join(`user-${userId}`);
    console.log(`📡 User ${userId} subscribed to notifications`);
  });

  socket.on('unsubscribe-notifications', (userId) => {
    socket.leave(`user-${userId}`);
    console.log(`📡 User ${userId} unsubscribed from notifications`);
  });
});

// Start server
server.listen(PORT, () => {
  console.log('🚀 OSCAR BROOME REVENUE - Production Server');
  console.log('==========================================');
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`✅ Environment: ${NODE_ENV}`);
  console.log(`✅ Health check: http://localhost:${PORT}/health`);
  console.log(`✅ API status: http://localhost:${PORT}/api/status`);
  console.log(`✅ WebSocket notifications enabled`);
  console.log(`✅ Started at: ${new Date().toISOString()}`);
  console.log('');

  if (NODE_ENV === 'production') {
    console.log('📊 Production Features:');
    console.log('   - Security headers enabled');
    console.log('   - Rate limiting active');
    console.log('   - Compression enabled');
    console.log('   - Request logging to file');
    console.log('   - Graceful error handling');
    console.log('   - Real-time notifications');
    console.log('');
  }
});

// Export for testing
export default app;

// Export notification service for use in other modules
export { notificationService };
