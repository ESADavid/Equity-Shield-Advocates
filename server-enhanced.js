#!/usr/bin/env node

import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:http';
import { Server } from 'socket.io';
import responseTime from 'response-time';

// Import database and services
import database from './config/database_enhanced.js';
import NotificationService from './earnings_dashboard/notification_service.js';
import cacheService from './services/cacheService.js';

// Import routes
import authRoutes from './routes/auth.js';
import transactionRoutes from './routes/transactionOverrideRoutes.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Performance monitoring
const performanceMetrics = {
  requestCount: 0,
  totalResponseTime: 0,
  averageResponseTime: 0,
  slowRequests: 0,
  errorCount: 0,
  startTime: Date.now()
};

// Create HTTP server
const server = createServer(app);

// Initialize Socket.IO
const io = new Server(server, {
  cors: {
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'],
    methods: ['GET', 'POST']
  }
});

// Initialize database connection with enhanced retry logic
if (process.env.SKIP_DATABASE === 'true') {
  console.log('⚠️ Skipping database connection as SKIP_DATABASE=true');
} else {
  try {
    await database.connect();
    console.log('✅ Database connected successfully');
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    console.log('💡 Enhanced database features available:');
    console.log('   - Automatic retry with exponential backoff');
    console.log('   - Connection pooling optimizations');
    console.log('   - Health monitoring and metrics');
    console.log('   - Query performance monitoring');
    console.log('   - Backup and restore capabilities');
    console.log('   - Multi-database support');
    console.log('   - Transaction support');
    console.log('   - SSL/TLS encryption support');
    console.log('   - Replica set support');
    console.log('   - Connection monitoring and alerting');
    // Don't exit - continue with graceful degradation
  }
}

// Initialize cache service
try {
  await cacheService.connect();
  console.log('✅ Cache service initialized');
} catch (error) {
  console.warn('⚠️ Cache service initialization failed, falling back to memory cache:', error.message);
}

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

// Response time monitoring
app.use(responseTime((req, res, time) => {
  performanceMetrics.requestCount++;
  performanceMetrics.totalResponseTime += time;
  performanceMetrics.averageResponseTime = performanceMetrics.totalResponseTime / performanceMetrics.requestCount;

  // Track slow requests (>500ms)
  if (time > 500) {
    performanceMetrics.slowRequests++;
  }

  // Add performance headers
  res.set('X-Response-Time', `${Math.round(time)}ms`);
}));

// Rate limiting with different tiers
const createRateLimit = (windowMs, max, message) => rateLimit({
  windowMs,
  max,
  message: { error: message },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    performanceMetrics.errorCount++;
    res.status(429).json({ error: message });
  }
});

// General API rate limiting
app.use('/api/', createRateLimit(15 * 60 * 1000, 100, 'Too many requests from this IP, please try again later.'));

// Stricter rate limiting for auth endpoints
app.use('/api/auth/', createRateLimit(15 * 60 * 1000, 5, 'Too many authentication attempts, please try again later.'));

// Compression with custom settings
app.use(compression({
  level: 6, // Balanced compression level
  threshold: 1024 // Only compress responses > 1KB
}));

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

// Body parsing middleware with size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health check endpoint with performance metrics
app.get('/health', async (req, res) => {
  try {
    const dbHealth = await database.healthCheck();
    const cacheHealth = await cacheService.healthCheck();

    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      environment: NODE_ENV,
      version: process.env.npm_package_version || '1.0.0',
      uptime: process.uptime(),
      database: dbHealth,
      cache: cacheHealth,
      performance: {
        ...performanceMetrics,
        uptime: Date.now() - performanceMetrics.startTime
      }
    };

    // Determine overall health status
    if ((dbHealth.status !== 'connected' && process.env.SKIP_DATABASE !== 'true') || cacheHealth.status === 'error') {
      health.status = 'degraded';
    }

    res.json(health);
  } catch (error) {
    console.error('Health check error:', error);
    res.status(503).json({
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Performance metrics endpoint
app.get('/metrics', (req, res) => {
  const metrics = {
    performance: {
      ...performanceMetrics,
      uptime: Date.now() - performanceMetrics.startTime
    },
    database: database.getPerformanceMetrics(),
    cache: cacheService.getMetrics(),
    memory: {
      usage: process.memoryUsage(),
      uptime: process.uptime()
    },
    system: {
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version,
      pid: process.pid
    }
  };

  res.json(metrics);
});

// API status endpoint
app.get('/api/status', (req, res) => {
  const getFunctions = (obj) => {
    const functions = [];
    if (obj) {
      for (const key in obj) {
        if (typeof obj[key] === 'function') {
          functions.push(key);
        }
      }
    }
    return functions;
  };

  const status = {
    merchantBillPay: {
      loaded: !!merchantBillPay,
      functions: getFunctions(merchantBillPay)
    },
    jpmorganPayment: {
      loaded: !!jpmorganRouter,
      functions: getFunctions(jpmorganRouter)
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
      jpmorgan: !!(process.env.JPMORGAN_CLIENT_ID && process.env.JPMORGAN_CLIENT_SECRET && process.env.JPMORGAN_MERCHANT_ID && process.env.JPMORGAN_TERMINAL_ID),
      redis: cacheService.isConnected,
      database: database.isConnected
    },
    performance: performanceMetrics
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

// Authentication API Routes
app.use('/api/auth', authRoutes);
console.log('✅ Authentication routes mounted at /api/auth');

// Transaction Override API Routes
app.use('/api/transactions', transactionRoutes);
console.log('✅ Transaction routes mounted at /api/transactions');

// Webhook endpoint for Stripe
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    if (!merchantBillPay || !merchantBillPay.handleMerchantWebhook) {
      return res.status(500).json({ error: 'Webhook handler not available' });
    }

    await merchantBillPay.handleMerchantWebhook(req, res);
  } catch (error) {
    console.error('Webhook processing error:', error);
    performanceMetrics.errorCount++;
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});



// Static file serving with caching headers
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1d', // Cache static files for 1 day
  setHeaders: (res, path) => {
    if (path.endsWith('.css') || path.endsWith('.js')) {
      res.set('Cache-Control', 'public, max-age=86400'); // 1 day
    }
  }
}));

// Catch-all handler for SPA
app.get('*', (req, res) => {
  // Serve override-dashboard.html instead of missing index.html
  res.sendFile(path.join(__dirname, 'public', 'override-dashboard.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  performanceMetrics.errorCount++;

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
const gracefulShutdown = () => {
  console.log('Graceful shutdown initiated...');

  server.close(async () => {
    console.log('HTTP server closed');

    try {
      await database.disconnect();
      await cacheService.disconnect();
      console.log('Database and cache connections closed');
    } catch (error) {
      console.error('Error during shutdown:', error);
    }

    console.log('Process terminated');
    process.exit(0);
  });

  // Force shutdown after 10 seconds
  setTimeout(() => {
    console.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Unhandled promise rejection handler
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  performanceMetrics.errorCount++;
  // Don't exit in production, just log
  if (NODE_ENV !== 'production') {
    process.exit(1);
  }
});

// Uncaught exception handler
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  performanceMetrics.errorCount++;
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
  console.log('🚀 OSCAR BROOME REVENUE - Performance Optimized Server');
  console.log('====================================================');
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`✅ Environment: ${NODE_ENV}`);
  console.log(`✅ Health check: http://localhost:${PORT}/health`);
  console.log(`✅ Performance metrics: http://localhost:${PORT}/metrics`);
  console.log(`✅ API status: http://localhost:${PORT}/api/status`);
  console.log(`✅ WebSocket notifications enabled`);
  console.log(`✅ Started at: ${new Date().toISOString()}`);
  console.log('');

  if (NODE_ENV === 'production') {
    console.log('📊 Production Features:');
    console.log('   - Security headers enabled');
    console.log('   - Rate limiting active');
    console.log('   - Response compression enabled');
    console.log('   - Request logging to file');
    console.log('   - Performance monitoring');
    console.log('   - Graceful error handling');
    console.log('   - Real-time notifications');
    console.log('   - Redis caching layer');
    console.log('   - Database connection pooling');
    console.log('');
  }
});

// Export for testing
export default app;

// Export services for use in other modules
export { default as cacheService } from './services/cacheService.js';
export { notificationService, performanceMetrics };
