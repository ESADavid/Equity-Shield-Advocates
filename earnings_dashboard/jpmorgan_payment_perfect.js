const express = require('express');
const router = express.Router();
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const winston = require('winston');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const Joi = require('joi');

// Enhanced Configuration with Validation
const config = {
  jpmorgan: {
    baseUrl: process.env.JPMORGAN_BASE_URL || 'https://api.payments.jpmorgan.com',
    organizationId: process.env.JPMORGAN_ORGANIZATION_ID || 'D3R56WRGSR3R',
    projectId: process.env.JPMORGAN_PROJECT_ID || 'D4YZRR0LSDXX',
    clientId: process.env.JPMORGAN_CLIENT_ID,
    clientSecret: process.env.JPMORGAN_CLIENT_SECRET,
    merchantId: process.env.JPMORGAN_MERCHANT_ID,
    terminalId: process.env.JPMORGAN_TERMINAL_ID,
    webhookSecret: process.env.JPMORGAN_WEBHOOK_SECRET,
    timeout: parseInt(process.env.JPMORGAN_API_TIMEOUT) || 30000,
    retryAttempts: parseInt(process.env.JPMORGAN_RETRY_ATTEMPTS) || 3,
    retryDelay: parseInt(process.env.JPMORGAN_RETRY_DELAY) || 1000,
    rateLimitWindow: parseInt(process.env.JPMORGAN_RATE_LIMIT_WINDOW) || 15 * 60 * 1000, // 15 minutes
    rateLimitMax: parseInt(process.env.JPMORGAN_RATE_LIMIT_MAX) || 100
  },
  security: {
    enableRateLimiting: process.env.ENABLE_RATE_LIMITING !== 'false',
    enableHelmet: process.env.ENABLE_HELMET !== 'false',
    logLevel: process.env.LOG_LEVEL || 'info',
    enableAuditLogging: process.env.ENABLE_AUDIT_LOGGING !== 'false'
  }
};

// Validate required configuration
const requiredConfig = ['clientId', 'clientSecret', 'merchantId', 'terminalId'];
const missingConfig = requiredConfig.filter(key => !config.jpmorgan[key]);
if (missingConfig.length > 0) {
  throw new Error(`Missing required JPMorgan configuration: ${missingConfig.join(', ')}`);
}

// Enhanced Logging Setup
const logger = winston.createLogger({
  level: config.security.logLevel,
  format: winston.format.combine(
