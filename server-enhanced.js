#!/usr/bin/env node

import dotenv from 'dotenv';
import logger from './utils/loggerWrapper.js';

dotenv.config();

import express from 'express';
import {
  errorHandler,
  notFoundHandler,
  setupUnhandledRejectionHandlers,
} from './middleware/errorHandler.js';
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
  startTime: Date.now(),
};

// Create HTTP server
const server = createServer(app);

// Initialize Socket.IO
const io = new Server(server, {
  cors: {
    origin: process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(',')
      : ['http://localhost:3000'],
    methods: ['GET', 'POST'],
  },
});

// Initialize database connection with enhanced retry logic
logger.info(`SKIP_DATABASE value: "${process.env.SKIP_DATABASE}"`);
if (process.env.SKIP_DATABASE === 'true') {
  logger.info('⚠️ Skipping database connection as SKIP_DATABASE=true');
  logger.info('💡 Enhanced database features available:');
  logger.info('   - Automatic retry with exponential backoff');
  logger.info('   - Connection pooling optimizations');
  logger.info('   - Health monitoring and metrics');
  logger.info('   - Query performance monitoring');
  logger.info('   - Backup and restore capabilities');
  logger.info('   - Multi-database support');
  logger.info('   - Transaction support');
  logger.info('   - SSL/TLS encryption support');
  logger.info('   - Replica set support');
  logger.info('   - Connection monitoring and alerting');
} else {
  try {
    await database.connect();
    logger.info('✅ Database connected successfully');
  } catch (error) {
    logger.error('❌ Database connection failed:', error.message);
    logger.info('💡 Enhanced database features available:');
    logger.info('   - Automatic retry with exponential backoff');
    logger.info('   - Connection pooling optimizations');
    logger.info('   - Health monitoring and metrics');
    logger.info('   - Query performance monitoring');
    logger.info('   - Backup and restore capabilities');
    logger.info('   - Multi-database support');
    logger.info('   - Transaction support');
    logger.info('   - SSL/TLS encryption support');
    logger.info('   - Replica set support');
    logger.info('   - Connection monitoring and alerting');
    // Don't exit - continue with graceful degradation
  }
}

// Initialize cache service
try {
  await cacheService.connect();
  logger.info('✅ Cache service initialized');
} catch (error) {
  logger.warn(
    '⚠️ Cache service initialization failed, falling back to memory cache:',
    error.message
  );
}

// Initialize notification service
const notificationService = new NotificationService(io);

// Import merchant bill pay system
let merchantBillPay;
try {
  const merchantModule =
    await import('./earnings_dashboard/merchant_bill_pay.js');
  merchantBillPay = merchantModule.default || merchantModule;
  logger.info('✅ Merchant bill pay system loaded successfully');
} catch (error) {
  logger.error('❌ Failed to load merchant bill pay system:', error.message);
  process.exit(1);
}

// Import JPMorgan payment system
let jpmorganRouter;
try {
  const jpmorganModule =
    await import('./earnings_dashboard/jpmorgan_payment.js');
  jpmorganRouter = jpmorganModule.default || jpmorganModule;
  logger.info('✅ JPMorgan payment system loaded successfully');
} catch (error) {
  logger.error('❌ Failed to load JPMorgan payment system:', error.message);
  process.exit(1);
}

// Import payroll system
let payrollRouter;
try {
  const payrollModule = await import('./earnings_dashboard/payroll_router.js');
  payrollRouter = payrollModule.default || payrollModule;
  logger.info('✅ Payroll system loaded successfully');
} catch (error) {
  logger.warn('⚠️ Payroll system not loaded (TypeScript module issue):', error.message);
  logger.info('   Server will continue without payroll routes');
  // Don't exit - continue without payroll system
}

// Import analytics system
let analyticsRouter;
try {
  const analyticsModule =
    await import('./earnings_dashboard/analytics_router.js');
  analyticsRouter = analyticsModule.default || analyticsModule;
  logger.info('✅ Analytics system loaded successfully');
} catch (error) {
  logger.error('❌ Failed to load analytics system:', error.message);
  process.exit(1);
}

// Import notification system
let notificationRouter;
try {
  const { default: createNotificationRouter } =
    await import('./earnings_dashboard/notification_router.js');
  notificationRouter = createNotificationRouter(notificationService);
  logger.info('✅ Notification system loaded successfully');
} catch (error) {
  logger.error('❌ Failed to load notification system:', error.message);
  process.exit(1);
}

// Import Haiti strategic routes
let haitiStrategicRouter;
try {
  const haitiModule = await import('./routes/haitiStrategicRoutes.js');
  haitiStrategicRouter = haitiModule.default || haitiModule;
  logger.info('✅ Haiti strategic acquisition system loaded successfully');
} catch (error) {
  logger.warn('⚠️ Haiti strategic system not loaded (module issue):', error.message);
  logger.info('   Server will continue without Haiti strategic routes');
  // Don't exit - continue without Haiti strategic system
}

// Import UBI (Universal Basic Income) routes - HEAVEN ON EARTH
let ubiRouter;
try {
  const ubiModule = await import('./routes/ubiRoutes.js');
  ubiRouter = ubiModule.default || ubiModule;
  logger.info('✅ Universal Basic Income system loaded successfully');
} catch (error) {
  logger.error('❌ Failed to load UBI system:', error.message);
  logger.info('   Server will continue without UBI system routes');
}

// Import Education routes - HEAVEN ON EARTH
let educationRouter;
try {
  const educationModule = await import('./routes/educationRoutes.js');
  educationRouter = educationModule.default || educationModule;
  logger.info('✅ Education system loaded successfully');
} catch (error) {
  logger.error('❌ Failed to load Education system:', error.message);
  logger.info('   Server will continue without Education system routes');
}

// Import Partner routes - PHASE 2
let partnerRouter;
try {
  const partnerModule = await import('./routes/partnerRoutes.js');
  partnerRouter = partnerModule.default || partnerModule;
  logger.info('✅ Partner coordination system loaded successfully');
} catch (error) {
  logger.error('❌ Failed to load Partner system:', error.message);
  logger.info('   Server will continue without Partner system routes');
}

// Import Citizen Portal routes - PHASE 2
let citizenPortalRouter;
try {
  const citizenModule = await import('./routes/citizenPortalRoutes.js');
  citizenPortalRouter = citizenModule.default || citizenModule;
  logger.info('✅ Citizen portal system loaded successfully');
} catch (error) {
  logger.error('❌ Failed to load Citizen portal:', error.message);
  logger.info('   Server will continue without Citizen portal routes');
}

// Import UBI Payment routes - PHASE 2
let ubiPaymentRouter;
try {
  const ubiPaymentModule = await import('./routes/ubiPaymentRoutes.js');
  ubiPaymentRouter = ubiPaymentModule.default || ubiPaymentModule;
  logger.info('✅ UBI payment system loaded successfully');
} catch (error) {
  logger.error('❌ Failed to load UBI payment system:', error.message);
  logger.info('   Server will continue without UBI payment system routes');
}

// Import Notification routes - PHASE 2
let notificationRoutesPhase2;
try {
  const notifModule = await import('./routes/notificationRoutes.js');
  notificationRoutesPhase2 = notifModule.default || notifModule;
  logger.info('✅ Multi-channel notification routes loaded successfully');
} catch (error) {
  logger.error('❌ Failed to load notification routes:', error.message);
  logger.info('   Server will continue without notification routes routes');
}

// Import ITG (Integrated Technology Growth) routes - KING SACHEM YOCHANAN
let itgRouter;
try {
  const itgModule = await import('./routes/itgRoutes.js');
  itgRouter = itgModule.default || itgModule;
  logger.info('✅ King Sachem Yochanan ITG Algorithm loaded successfully');
} catch (error) {
  logger.error('❌ Failed to load ITG system:', error.message);
  logger.info('   Server will continue without ITG routes');
}

// Import Divine AI routes - PRIVATE PERSONAL AI
let divineAIRouter;
try {
  const divineAIModule = await import('./routes/divineAIRoutes.js');
  divineAIRouter = divineAIModule.default || divineAIModule;
  logger.info('✅ Divine AI system loaded successfully');
} catch (error) {
  logger.error('❌ Failed to load Divine AI system:', error.message);
  logger.info('   Server will continue without Divine AI routes');
}

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
      : ['http://localhost:3000'],
    credentials: true,
  })
);

// Response time monitoring
app.use(
  responseTime((req, res, time) => {
    performanceMetrics.requestCount++;
    performanceMetrics.totalResponseTime += time;
    performanceMetrics.averageResponseTime =
      performanceMetrics.totalResponseTime / performanceMetrics.requestCount;

    // Track slow requests (>500ms)
    if (time > 500) {
      performanceMetrics.slowRequests++;
    }

    // Add performance headers
    res.set('X-Response-Time', `${Math.round(time)}ms`);
  })
);

// Rate limiting with different tiers
const createRateLimit = (windowMs, max, message) =>
  rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      performanceMetrics.errorCount++;
      res.status(429).json({ error: message });
    },
  });

// General API rate limiting
app.use(
  '/api/',
  createRateLimit(
    15 * 60 * 1000,
    100,
    'Too many requests from this IP, please try again later.'
  )
);

// Stricter rate limiting for auth endpoints
app.use(
  '/api/auth/',
  createRateLimit(
    15 * 60 * 1000,
    5,
    'Too many authentication attempts, please try again later.'
  )
);

// Compression with custom settings
app.use(
  compression({
    level: 6, // Balanced compression level
    threshold: 1024, // Only compress responses > 1KB
  })
);

// Logging
if (NODE_ENV === 'production') {
  // Create logs directory if it doesn't exist
  const logsDir = path.join(__dirname, 'logs');
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir);
  }

  // Write logs to file
  const accessLogStream = fs.createWriteStream(
    path.join(logsDir, 'access.log'),
    { flags: 'a' }
  );
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
        uptime: Date.now() - performanceMetrics.startTime,
      },
    };

    // Determine overall health status
    if (
      (dbHealth.status !== 'connected' &&
        process.env.SKIP_DATABASE !== 'true') ||
      cacheHealth.status === 'error'
    ) {
      health.status = 'degraded';
    }

    res.json(health);
  } catch (error) {
    logger.error('Health check error:', error);
    res.status(503).json({
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString(),
    });
  }
});

// Performance metrics endpoint
app.get('/metrics', (req, res) => {
  const metrics = {
    performance: {
      ...performanceMetrics,
      uptime: Date.now() - performanceMetrics.startTime,
    },
    database: database.getPerformanceMetrics(),
    cache: cacheService.getMetrics(),
    memory: {
      usage: process.memoryUsage(),
      uptime: process.uptime(),
    },
    system: {
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version,
      pid: process.pid,
    },
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
      functions: getFunctions(merchantBillPay),
    },
    jpmorganPayment: {
      loaded: !!jpmorganRouter,
      functions: getFunctions(jpmorganRouter),
    },
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
      redis: cacheService.isConnected,
      database: database.isConnected,
    },
    performance: performanceMetrics,
  };

  res.json(status);
});

// Merchant Bill Pay API Routes
if (merchantBillPay && merchantBillPay.router) {
  app.use('/api/merchant', merchantBillPay.router);
  logger.info('✅ Merchant bill pay routes mounted at /api/merchant');
}

// JPMorgan Payment API Routes
if (jpmorganRouter) {
  app.use('/jpmorgan', jpmorganRouter);
  logger.info('✅ JPMorgan payment routes mounted at /jpmorgan');
}

// Payroll API Routes
if (payrollRouter) {
  app.use('/api/payroll', payrollRouter);
  logger.info('✅ Payroll routes mounted at /api/payroll');
}

// Analytics API Routes
if (analyticsRouter) {
  app.use('/api/analytics', analyticsRouter);
  logger.info('✅ Analytics routes mounted at /api/analytics');
}

// Notification API Routes
if (notificationRouter) {
  app.use('/api/notifications', notificationRouter);
  logger.info('✅ Notification routes mounted at /api/notifications');
}

// Authentication API Routes
app.use('/api/auth', authRoutes);
logger.info('✅ Authentication routes mounted at /api/auth');

// Transaction Override API Routes
app.use('/api/transactions', transactionRoutes);
logger.info('✅ Transaction routes mounted at /api/transactions');

// Haiti Strategic Acquisition API Routes
if (haitiStrategicRouter) {
  app.use('/api/haiti', haitiStrategicRouter);
  logger.info('✅ Haiti strategic routes mounted at /api/haiti');
}

// Universal Basic Income API Routes - HEAVEN ON EARTH
if (ubiRouter) {
  app.use('/api/ubi', ubiRouter);
  logger.info('✅ UBI routes mounted at /api/ubi');
  logger.info('   💰 $33,000/year per citizen system active');
}

// Education API Routes - HEAVEN ON EARTH
if (educationRouter) {
  app.use('/api/education', educationRouter);
  logger.info('✅ Education routes mounted at /api/education');
  logger.info('   🎓 Mandatory training: Military, Law, Tech, Agriculture');
}

// ITG API Routes - KING SACHEM YOCHANAN
if (itgRouter) {
  app.use('/api/itg', itgRouter);
  logger.info('✅ ITG routes mounted at /api/itg');
  logger.info('   👑 King Sachem Yochanan ITG Algorithm active');
  logger.info('   ✨ Sacred Geometry + Divine Wisdom + Quantum Enhancement');
}

// Divine AI API Routes - PRIVATE PERSONAL AI
if (divineAIRouter) {
  app.use('/api/divine-ai', divineAIRouter);
  logger.info('✅ Divine AI routes mounted at /api/divine-ai');
  logger.info('   🤖 Divine AI active - Personal benefit only');
  logger.info('   🔐 Private access - King Sachem Yochanan exclusive');
}

// Partner API Routes - PHASE 2
if (partnerRouter) {
  app.use('/api/partners', partnerRouter);
  logger.info('✅ Partner routes mounted at /api/partners');
  logger.info('   🤝 Partner coordination & PMC integration active');
}

// Citizen Portal API Routes - PHASE 2
if (citizenPortalRouter) {
  app.use('/api/citizen-portal', citizenPortalRouter);
  logger.info('✅ Citizen portal routes mounted at /api/citizen-portal');
  logger.info('   👥 Citizen registration & services active');
}

// UBI Payment API Routes - PHASE 2
if (ubiPaymentRouter) {
  app.use('/api/ubi-payments', ubiPaymentRouter);
  logger.info('✅ UBI payment routes mounted at /api/ubi-payments');
  logger.info('   💵 UBI payment processing active');
}

// Multi-Channel Notification API Routes - PHASE 2
if (notificationRoutesPhase2) {
  app.use('/api/notifications-v2', notificationRoutesPhase2);
  logger.info('✅ Multi-channel notification routes mounted at /api/notifications-v2');
  logger.info('   📧 Email, SMS, Push, In-App notifications active');
}

// Webhook endpoint for Stripe
app.post(
  '/api/webhooks/stripe',
  express.raw({ type: 'application/json' }),
  async (req, res, next) => {
    try {
      if (!merchantBillPay || !merchantBillPay.handleMerchantWebhook) {
        return res.status(500).json({ error: 'Webhook handler not available' });
      }

      await merchantBillPay.handleMerchantWebhook(req, res);
    } catch (error) {
      next(error);
    }
  }
);

// Static file serving with caching headers
app.use(
  express.static(path.join(__dirname, 'public'), {
    maxAge: '1d', // Cache static files for 1 day
    setHeaders: (res, path) => {
      if (path.endsWith('.css') || path.endsWith('.js')) {
        res.set('Cache-Control', 'public, max-age=86400'); // 1 day
      }
    },
  })
);

// Catch-all handler for SPA (must be before 404 handler)
app.get('*', (req, res, next) => {
  // Only serve SPA for non-API routes and exclude health/metrics endpoints
  if (req.path.startsWith('/api/') || req.path.startsWith('/jpmorgan/') || req.path === '/health' || req.path === '/metrics' || req.path === '/api/status') {
    return next();
  }
  // Serve override-dashboard.html instead of missing index.html
  res.sendFile(path.join(__dirname, 'public', 'override-dashboard.html'));
});

// 404 handler for API routes (must be before error handler)
app.use(notFoundHandler);

// Enterprise error handling middleware (must be last)
app.use((err, req, res, next) => {
  performanceMetrics.errorCount++;
  errorHandler(err, req, res, next);
});

// Graceful shutdown
const gracefulShutdown = () => {
  logger.info('Graceful shutdown initiated...');

  server.close(async () => {
    logger.info('HTTP server closed');

    try {
      await database.disconnect();
      await cacheService.disconnect();
      logger.info('Database and cache connections closed');
    } catch (error) {
      logger.error('Error during shutdown:', error);
    }

    logger.info('Process terminated');
    process.exit(0);
  });

  // Force shutdown after 10 seconds
  setTimeout(() => {
    logger.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Setup unhandled rejection and exception handlers
setupUnhandledRejectionHandlers((error) => {
  performanceMetrics.errorCount++;
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  logger.info('🔌 Client connected:', socket.id);

  socket.on('disconnect', () => {
    logger.info('🔌 Client disconnected:', socket.id);
  });

  socket.on('subscribe-notifications', (userId) => {
    socket.join(`user-${userId}`);
    logger.info(`📡 User ${userId} subscribed to notifications`);
  });

  socket.on('unsubscribe-notifications', (userId) => {
    socket.leave(`user-${userId}`);
    logger.info(`📡 User ${userId} unsubscribed from notifications`);
  });
});

// Start server
server.listen(PORT, () => {
  logger.info('🚀 OSCAR BROOME REVENUE - Performance Optimized Server');
  logger.info('====================================================');
  logger.info(`✅ Server running on port ${PORT}`);
  logger.info(`✅ Environment: ${NODE_ENV}`);
  logger.info(`✅ Health check: http://localhost:${PORT}/health`);
  logger.info(`✅ Performance metrics: http://localhost:${PORT}/metrics`);
  logger.info(`✅ API status: http://localhost:${PORT}/api/status`);
  logger.info(`✅ WebSocket notifications enabled`);
  logger.info(`✅ Started at: ${new Date().toISOString()}`);
  logger.info('');
  logger.info('✨ HEAVEN ON EARTH - OWLBAN GROUP SYSTEMS ACTIVE ✨');
  logger.info('====================================================');
  logger.info(
    '💰 Universal Basic Income: http://localhost:${PORT}/api/ubi/welcome'
  );
  logger.info(
    '🎓 Education System: http://localhost:${PORT}/api/education/welcome'
  );
  logger.info('🌍 Mission: $33,000/year + Mandatory Education for All');
  logger.info('');
  logger.info('👑 KING SACHEM YOCHANAN ITG ALGORITHM ACTIVE 👑');
  logger.info('====================================================');
  logger.info(
    '📊 ITG Dashboard: http://localhost:${PORT}/api/itg/dashboard-data'
  );
  logger.info(
    '⚡ Quick Assessment: http://localhost:${PORT}/api/itg/quick-assessment'
  );
  logger.info('✨ Sacred Geometry + Divine Wisdom + Quantum Computing');
  logger.info('🔐 Blockchain-Verified Sovereignty Tracking');
  logger.info('');

  if (NODE_ENV === 'production') {
    logger.info('📊 Production Features:');
    logger.info('   - Security headers enabled');
    logger.info('   - Rate limiting active');
    logger.info('   - Response compression enabled');
    logger.info('   - Request logging to file');
    logger.info('   - Performance monitoring');
    logger.info('   - Graceful error handling');
    logger.info('   - Real-time notifications');
    logger.info('   - Redis caching layer');
    logger.info('   - Database connection pooling');
    logger.info('');
  }
});

// Export for testing
export default app;

// Export services for use in other modules
export { default as cacheService } from './services/cacheService.js';
export { notificationService, performanceMetrics };
