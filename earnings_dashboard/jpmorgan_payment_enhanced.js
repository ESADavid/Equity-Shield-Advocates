const express = require('express');
const router = express.Router();
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const winston = require('winston');

// Enhanced logging configuration
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'jpmorgan-payment' },
  transports: [
    new winston.transports.File({
      filename: 'logs/jpmorgan-error.log',
      level: 'error',
    }),
    new winston.transports.File({ filename: 'logs/jpmorgan-combined.log' }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
  ],
});

// Create logs directory if it doesn't exist
if (!fs.existsSync('logs')) {
  fs.mkdirSync('logs');
}

// Custom error classes
class JPMorganPaymentError extends Error {
  constructor(message, statusCode = 500, code = 'PAYMENT_ERROR') {
    super(message);
    this.name = 'JPMorganPaymentError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

class ValidationError extends JPMorganPaymentError {
  constructor(message) {
    super(message, 400, 'VALIDATION_ERROR');
    this.name = 'ValidationError';
  }
}

class AuthenticationError extends JPMorganPaymentError {
  constructor(message) {
    super(message, 401, 'AUTHENTICATION_ERROR');
    this.name = 'AuthenticationError';
  }
}

// JPMorgan Payments API Configuration
const CONFIG = {
  BASE_URL:
    process.env.JPMORGAN_BASE_URL || 'https://api-mock.payments.jpmorgan.com',
  CLIENT_ID: process.env.JPMORGAN_CLIENT_ID,
  CLIENT_SECRET: process.env.JPMORGAN_CLIENT_SECRET,
  MERCHANT_ID: process.env.JPMORGAN_MERCHANT_ID,
  TERMINAL_ID: process.env.JPMORGAN_TERMINAL_ID,
  WEBHOOK_SECRET: process.env.JPMORGAN_WEBHOOK_SECRET,
  TIMEOUT: parseInt(process.env.JPMORGAN_API_TIMEOUT) || 10000,
  RETRY_ATTEMPTS: parseInt(process.env.JPMORGAN_RETRY_ATTEMPTS) || 3,
};

// Revenue data path
const revenueDataPath = path.resolve(
  __dirname,
  '../owlban_repos/sample_repo/revenue.json'
);

// Input validation schemas
const validatePaymentRequest = (data) => {
  const { amount, currency = 'USD', orderId, description, customer } = data;

  if (!amount || typeof amount !== 'number' || amount <= 0) {
    throw new ValidationError('Valid amount is required');
  }

  if (!orderId || typeof orderId !== 'string' || orderId.trim().length === 0) {
    throw new ValidationError('Valid orderId is required');
  }

  if (currency && !['USD', 'EUR', 'GBP'].includes(currency.toUpperCase())) {
    throw new ValidationError('Invalid currency. Supported: USD, EUR, GBP');
  }

  if (description && description.length > 500) {
    throw new ValidationError('Description too long (max 500 characters)');
  }

  return {
    amount,
    currency: currency.toUpperCase(),
    orderId: orderId.trim(),
    description: description?.trim(),
    customer,
  };
};

const validateRefundRequest = (data) => {
  const { paymentId, amount, reason } = data;

  if (!paymentId || typeof paymentId !== 'string') {
    throw new ValidationError('Valid paymentId is required');
  }

  if (!amount || typeof amount !== 'number' || amount <= 0) {
    throw new ValidationError('Valid refund amount is required');
  }

  if (reason && reason.length > 200) {
    throw new ValidationError('Refund reason too long (max 200 characters)');
  }

  return {
    paymentId: paymentId.trim(),
    amount,
    reason: reason?.trim(),
  };
};

// Enhanced axios instance with retry logic
const axiosInstance = axios.create({
  baseURL: CONFIG.BASE_URL,
  timeout: CONFIG.TIMEOUT,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for logging
axiosInstance.interceptors.request.use(
  (config) => {
    logger.info('JPMorgan API Request', {
      method: config.method?.toUpperCase(),
      url: config.url,
      timestamp: new Date().toISOString(),
    });
    return config;
  },
  (error) => {
    logger.error('JPMorgan API Request Error', { error: error.message });
    return Promise.reject(error);
  }
);

// Response interceptor for logging
axiosInstance.interceptors.response.use(
  (response) => {
    logger.info('JPMorgan API Response', {
      status: response.status,
      url: response.config.url,
      duration: Date.now() - response.config.metadata?.startTime,
    });
    return response;
  },
  (error) => {
    logger.error('JPMorgan API Response Error', {
      status: error.response?.status,
      url: error.config?.url,
      error: error.response?.data || error.message,
      duration: Date.now() - error.config?.metadata?.startTime,
    });
    return Promise.reject(error);
  }
);

// Utility functions
function readRevenueData() {
  try {
    if (!fs.existsSync(revenueDataPath)) {
      logger.warn('Revenue data file not found', { path: revenueDataPath });
      return null;
    }
    const data = JSON.parse(fs.readFileSync(revenueDataPath, 'utf-8'));
    if (!data.payments) {
      data.payments = [];
    }
    return data;
  } catch (error) {
    logger.error('Error reading revenue data', { error: error.message });
    return null;
  }
}

function writeRevenueData(data) {
  try {
    fs.writeFileSync(revenueDataPath, JSON.stringify(data, null, 2), 'utf-8');
    logger.info('Revenue data updated successfully');
  } catch (error) {
    logger.error('Error writing revenue data', { error: error.message });
    throw new JPMorganPaymentError('Failed to update revenue data');
  }
}

// Enhanced authentication headers generation
function generateAuthHeaders() {
  if (!CONFIG.CLIENT_ID || !CONFIG.CLIENT_SECRET) {
    throw new AuthenticationError('JPMorgan credentials not configured');
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(16).toString('hex');
  const message = `${CONFIG.CLIENT_ID}${timestamp}${nonce}`;

  const signature = crypto
    .createHmac('sha256', CONFIG.CLIENT_SECRET)
    .update(message)
    .digest('base64');

  return {
    'Content-Type': 'application/json',
    'Client-Id': CONFIG.CLIENT_ID,
    Timestamp: timestamp.toString(),
    Nonce: nonce,
    Signature: signature,
    'Merchant-Id': CONFIG.MERCHANT_ID,
    'Terminal-Id': CONFIG.TERMINAL_ID,
  };
}

// Request logging middleware
const logRequest = (req, res, next) => {
  const startTime = Date.now();
  const requestId = crypto.randomBytes(8).toString('hex');

  logger.info('Incoming request', {
    requestId,
    method: req.method,
    url: req.url,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
  });

  // Override res.json to log response
  const originalJson = res.json;
  res.json = function (data) {
    const duration = Date.now() - startTime;
    logger.info('Request completed', {
      requestId,
      statusCode: res.statusCode,
      duration,
      success: data.success !== false,
    });
    return originalJson.call(this, data);
  };

  next();
};

// Error handling middleware
const handleErrors = (error, req, res, next) => {
  if (error instanceof JPMorganPaymentError) {
    logger.warn('Application error', {
      name: error.name,
      message: error.message,
      code: error.code,
      statusCode: error.statusCode,
      stack: error.stack,
    });

    return res.status(error.statusCode).json({
      success: false,
      error: error.message,
      code: error.code,
      timestamp: new Date().toISOString(),
    });
  }

  if (error.response) {
    // API error
    logger.error('JPMorgan API error', {
      status: error.response.status,
      data: error.response.data,
      url: error.config?.url,
    });

    return res.status(error.response.status).json({
      success: false,
      error: 'JPMorgan API error',
      details: error.response.data,
      timestamp: new Date().toISOString(),
    });
  }

  if (error.code === 'ECONNABORTED') {
    logger.error('JPMorgan API timeout', { url: error.config?.url });
    return res.status(504).json({
      success: false,
      error: 'Request timeout',
      timestamp: new Date().toISOString(),
    });
  }

  logger.error('Unexpected error', {
    message: error.message,
    stack: error.stack,
  });

  res.status(500).json({
    success: false,
    error: 'Internal server error',
    timestamp: new Date().toISOString(),
  });
};

// Apply middleware
router.use(logRequest);

// Create payment transaction with enhanced validation
router.post('/create-payment', async (req, res, next) => {
  try {
    const validatedData = validatePaymentRequest(req.body);
    const headers = generateAuthHeaders();

    const paymentData = {
      amount: {
        value: validatedData.amount,
        currency: validatedData.currency,
      },
      order: {
        id: validatedData.orderId,
        description: validatedData.description || 'Payment for services',
      },
      customer: validatedData.customer || {},
      merchant: {
        id: CONFIG.MERCHANT_ID,
        terminalId: CONFIG.TERMINAL_ID,
      },
      paymentMethod: {
        type: 'CARD',
      },
      metadata: {
        source: 'oscar-broome-revenue',
        timestamp: new Date().toISOString(),
      },
    };

    const response = await axiosInstance.post('/v1/payments', paymentData, {
      headers,
      metadata: { startTime: Date.now() },
    });

    // Update local revenue data
    const revenueData = readRevenueData();
    if (revenueData) {
      revenueData.payments.push({
        id: response.data.id,
        amount: validatedData.amount,
        currency: validatedData.currency,
        orderId: validatedData.orderId,
        status: response.data.status,
        createdAt: new Date().toISOString(),
      });
      writeRevenueData(revenueData);
    }

    res.json({
      success: true,
      paymentId: response.data.id,
      status: response.data.status,
      authorizationCode: response.data.authorizationCode,
      transactionDetails: response.data,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

// Get payment status with caching
const paymentCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

router.get('/payment-status/:paymentId', async (req, res, next) => {
  try {
    const { paymentId } = req.params;

    if (!paymentId || typeof paymentId !== 'string') {
      throw new ValidationError('Valid paymentId is required');
    }

    // Check cache first
    const cacheKey = `payment_${paymentId}`;
    const cached = paymentCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      logger.info('Returning cached payment status', { paymentId });
      return res.json({
        success: true,
        paymentStatus: cached.data,
        cached: true,
        timestamp: new Date().toISOString(),
      });
    }

    const headers = generateAuthHeaders();

    const response = await axiosInstance.get(`/v1/payments/${paymentId}`, {
      headers,
      metadata: { startTime: Date.now() },
    });

    // Cache the result
    paymentCache.set(cacheKey, {
      data: response.data,
      timestamp: Date.now(),
    });

    res.json({
      success: true,
      paymentStatus: response.data,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

// Enhanced refund with business logic validation
router.post('/refund', async (req, res, next) => {
  try {
    const validatedData = validateRefundRequest(req.body);
    const headers = generateAuthHeaders();

    // Check if payment exists and is refundable
    const paymentResponse = await axiosInstance.get(
      `/v1/payments/${validatedData.paymentId}`,
      {
        headers,
        metadata: { startTime: Date.now() },
      }
    );

    const payment = paymentResponse.data;
    if (!['CAPTURED', 'AUTHORIZED'].includes(payment.status)) {
      throw new ValidationError(
        `Cannot refund payment with status: ${payment.status}`
      );
    }

    if (validatedData.amount > payment.amount.value) {
      throw new ValidationError(
        'Refund amount cannot exceed original payment amount'
      );
    }

    const refundData = {
      amount: {
        value: validatedData.amount,
        currency: 'USD',
      },
      reason: validatedData.reason || 'Customer request',
      metadata: {
        source: 'oscar-broome-revenue',
        timestamp: new Date().toISOString(),
      },
    };

    const response = await axiosInstance.post(
      `/v1/payments/${validatedData.paymentId}/refunds`,
      refundData,
      {
        headers,
        metadata: { startTime: Date.now() },
      }
    );

    // Update local revenue data
    const revenueData = readRevenueData();
    if (revenueData) {
      const paymentIndex = revenueData.payments.findIndex(
        (p) => p.id === validatedData.paymentId
      );
      if (paymentIndex !== -1) {
        revenueData.payments[paymentIndex].refunds =
          revenueData.payments[paymentIndex].refunds || [];
        revenueData.payments[paymentIndex].refunds.push({
          id: response.data.id,
          amount: validatedData.amount,
          reason: validatedData.reason,
          createdAt: new Date().toISOString(),
        });
        writeRevenueData(revenueData);
      }
    }

    res.json({
      success: true,
      refundId: response.data.id,
      status: response.data.status,
      refundDetails: response.data,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

// Capture with enhanced validation
router.post('/capture', async (req, res, next) => {
  try {
    const { paymentId, amount } = req.body;

    if (!paymentId || typeof paymentId !== 'string') {
      throw new ValidationError('Valid paymentId is required');
    }

    const headers = generateAuthHeaders();

    // Verify payment status before capture
    const paymentResponse = await axiosInstance.get(
      `/v1/payments/${paymentId}`,
      {
        headers,
        metadata: { startTime: Date.now() },
      }
    );

    if (paymentResponse.data.status !== 'AUTHORIZED') {
      throw new ValidationError(
        `Cannot capture payment with status: ${paymentResponse.data.status}`
      );
    }

    const captureData = amount
      ? {
          amount: {
            value: amount,
            currency: 'USD',
          },
        }
      : {};

    const response = await axiosInstance.post(
      `/v1/payments/${paymentId}/capture`,
      captureData,
      {
        headers,
        metadata: { startTime: Date.now() },
      }
    );

    res.json({
      success: true,
      captureId: response.data.id,
      status: response.data.status,
      captureDetails: response.data,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

// Void with business rules
router.post('/void', async (req, res, next) => {
  try {
    const { paymentId, reason } = req.body;

    if (!paymentId || typeof paymentId !== 'string') {
      throw new ValidationError('Valid paymentId is required');
    }

    if (reason && reason.length > 200) {
      throw new ValidationError('Void reason too long (max 200 characters)');
    }

    const headers = generateAuthHeaders();

    // Check if payment can be voided
    const paymentResponse = await axiosInstance.get(
      `/v1/payments/${paymentId}`,
      {
        headers,
        metadata: { startTime: Date.now() },
      }
    );

    if (!['AUTHORIZED', 'PENDING'].includes(paymentResponse.data.status)) {
      throw new ValidationError(
        `Cannot void payment with status: ${paymentResponse.data.status}`
      );
    }

    const voidData = {
      reason: reason || 'Customer request',
      metadata: {
        source: 'oscar-broome-revenue',
        timestamp: new Date().toISOString(),
      },
    };

    const response = await axiosInstance.post(
      `/v1/payments/${paymentId}/void`,
      voidData,
      {
        headers,
        metadata: { startTime: Date.now() },
      }
    );

    res.json({
      success: true,
      voidId: response.data.id,
      status: response.data.status,
      voidDetails: response.data,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

// Enhanced transaction history with filtering
router.get('/transactions', async (req, res, next) => {
  try {
    const { startDate, endDate, status, limit = 50, offset = 0 } = req.query;

    // Validate query parameters
    if (limit && (isNaN(limit) || limit < 1 || limit > 1000)) {
      throw new ValidationError('Limit must be between 1 and 1000');
    }

    if (offset && (isNaN(offset) || offset < 0)) {
      throw new ValidationError('Offset must be non-negative');
    }

    if (startDate && isNaN(Date.parse(startDate))) {
      throw new ValidationError('Invalid startDate format');
    }

    if (endDate && isNaN(Date.parse(endDate))) {
      throw new ValidationError('Invalid endDate format');
    }

    const headers = generateAuthHeaders();

    const params = new URLSearchParams();
    if (startDate) params.append('startDate', startDate);
    if (endDate) params.append('endDate', endDate);
    if (status) params.append('status', status);
    params.append('limit', limit.toString());
    params.append('offset', offset.toString());

    const response = await axiosInstance.get(`/v1/transactions?${params}`, {
      headers,
      metadata: { startTime: Date.now() },
    });

    res.json({
      success: true,
      transactions: response.data.transactions || [],
      totalCount: response.data.totalCount || 0,
      limit: parseInt(limit),
      offset: parseInt(offset),
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

// Enhanced webhook verification with timestamp validation
const verifyWebhookSignature = (req, res, next) => {
  try {
    const signature = req.headers['x-jpmorgan-signature'];
    const timestamp = req.headers['x-jpmorgan-timestamp'];
    const nonce = req.headers['x-jpmorgan-nonce'];

    if (!signature || !timestamp || !nonce) {
      logger.warn('Missing webhook authentication headers');
      return res.status(401).json({
        success: false,
        error: 'Missing authentication headers',
      });
    }

    // Validate timestamp (within 5 minutes)
    const now = Math.floor(Date.now() / 1000);
    const timeDiff = Math.abs(now - parseInt(timestamp));
    if (timeDiff > 300) {
      logger.warn('Webhook timestamp too old', { timeDiff });
      return res.status(401).json({
        success: false,
        error: 'Webhook timestamp expired',
      });
    }

    const message = `${timestamp}${nonce}${JSON.stringify(req.body)}`;
    const expectedSignature = crypto
      .createHmac('sha256', CONFIG.WEBHOOK_SECRET || CONFIG.CLIENT_SECRET)
      .update(message)
      .digest('base64');

    if (signature !== expectedSignature) {
      logger.warn('Invalid webhook signature');
      return res.status(401).json({
        success: false,
        error: 'Invalid webhook signature',
      });
    }

    logger.info('Webhook signature verified successfully');
    next();
  } catch (error) {
    logger.error('Webhook verification error', { error: error.message });
    res.status(500).json({
      success: false,
      error: 'Webhook verification failed',
    });
  }
};

// Enhanced webhook endpoint
router.post(
  '/webhook',
  express.json({ limit: '10mb' }),
  verifyWebhookSignature,
  async (req, res, next) => {
    try {
      const event = req.body;

      logger.info('Received JPMorgan webhook event', {
        type: event.type,
        id: event.id,
        paymentId: event.data?.paymentId,
      });

      // Update local revenue data based on webhook events
      const revenueData = readRevenueData();
      if (revenueData && event.data?.paymentId) {
        const paymentIndex = revenueData.payments.findIndex(
          (p) => p.id === event.data.paymentId
        );
        if (paymentIndex !== -1) {
          revenueData.payments[paymentIndex].status = event.type.split('.')[1];
          revenueData.payments[paymentIndex].updatedAt =
            new Date().toISOString();
          revenueData.payments[paymentIndex].webhookEvents =
            revenueData.payments[paymentIndex].webhookEvents || [];
          revenueData.payments[paymentIndex].webhookEvents.push({
            type: event.type,
            timestamp: new Date().toISOString(),
            data: event.data,
          });
          writeRevenueData(revenueData);
        }
      }

      // Process different event types
      switch (event.type) {
        case 'payment.authorized':
          logger.info('Payment authorized', {
            paymentId: event.data.paymentId,
          });
          break;

        case 'payment.captured':
          logger.info('Payment captured', { paymentId: event.data.paymentId });
          break;

        case 'payment.refunded':
          logger.info('Payment refunded', { paymentId: event.data.paymentId });
          break;

        case 'payment.voided':
          logger.info('Payment voided', { paymentId: event.data.paymentId });
          break;

        case 'payment.failed':
          logger.error('Payment failed', {
            paymentId: event.data.paymentId,
            reason: event.data.reason,
          });
          break;

        default:
          logger.info('Unhandled webhook event type', { type: event.type });
      }

      res.json({
        success: true,
        received: true,
        eventType: event.type,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  }
);

// Enhanced health check with detailed status
router.get('/health', async (req, res, next) => {
  try {
    const headers = generateAuthHeaders();

    const startTime = Date.now();
    const response = await axiosInstance.get('/v1/health', {
      headers,
      timeout: 5000,
      metadata: { startTime },
    });

    const responseTime = Date.now() - startTime;

    // Check configuration
    const configStatus = {
      clientId: !!CONFIG.CLIENT_ID,
      clientSecret: !!CONFIG.CLIENT_SECRET,
      merchantId: !!CONFIG.MERCHANT_ID,
      terminalId: !!CONFIG.TERMINAL_ID,
      baseUrl: !!CONFIG.BASE_URL,
    };

    const configHealthy = Object.values(configStatus).every(Boolean);

    // Check local data
    const revenueData = readRevenueData();
    const dataStatus = {
      revenueFile: !!revenueData,
      payments: revenueData ? revenueData.payments?.length || 0 : 0,
    };

    res.json({
      success: true,
      status: 'healthy',
      jpmorganStatus: response.data.status,
      responseTime: `${responseTime}ms`,
      config: configStatus,
      data: dataStatus,
      timestamp: new Date().toISOString(),
      version: '2.0.0',
    });
  } catch (error) {
    logger.error('Health check failed', { error: error.message });

    res.status(503).json({
      success: false,
      status: 'unhealthy',
      error: 'JPMorgan API unavailable',
      details: error.message,
      timestamp: new Date().toISOString(),
    });
  }
});

// Metrics endpoint
router.get('/metrics', (req, res) => {
  const metrics = {
    cacheSize: paymentCache.size,
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    timestamp: new Date().toISOString(),
  };

  res.json({
    success: true,
    metrics,
  });
});

// Apply error handling middleware
router.use(handleErrors);

module.exports = router;
