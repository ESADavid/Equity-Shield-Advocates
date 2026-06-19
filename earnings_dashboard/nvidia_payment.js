import { info, error, warn, debug } from 'utils/loggerWrapper.js';

const express = require('express');
const router = express.Router();
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// NVIDIA AIQ Payments Configuration
const NVIDIA_AIQ_BASE_URL =
  process.env.NVIDIA_AIQ_BASE_URL || 'https://api.aiq.nvidia.com';
const NVIDIA_AIQ_API_KEY = process.env.NVIDIA_AIQ_API_KEY;
const NVIDIA_AIQ_MERCHANT_ID = process.env.NVIDIA_AIQ_MERCHANT_ID;
const NVIDIA_AIQ_SECRET_KEY = process.env.NVIDIA_AIQ_SECRET_KEY;

// Revenue data path
const revenueDataPath = path.resolve(
  __dirname,
  '../earnings_report_updated.json'
);

function readRevenueData() {
  if (!fs.existsSync(revenueDataPath)) {
    return null;
  }
  const data = JSON.parse(fs.readFileSync(revenueDataPath, 'utf-8'));
  if (!data.purchases) {
    data.purchases = {
      corporateHomes: 0,
      autoFleet: 0,
      autoFleetDetails: [],
    };
  }
  return data;
}

function writeRevenueData(data) {
  fs.writeFileSync(revenueDataPath, JSON.stringify(data, null, 2), 'utf-8');
}

// Generate NVIDIA AIQ authentication headers
function generateAuthHeaders() {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(16).toString('hex');

  const message = `${NVIDIA_AIQ_API_KEY}${timestamp}${nonce}`;
  const signature = crypto
    .createHmac('sha256', NVIDIA_AIQ_SECRET_KEY)
    .update(message)
    .digest('hex');

  return {
    'Content-Type': 'application/json',
    'X-NVIDIA-API-Key': NVIDIA_AIQ_API_KEY,
    'X-NVIDIA-Timestamp': timestamp.toString(),
    'X-NVIDIA-Nonce': nonce,
    'X-NVIDIA-Signature': signature,
    'X-NVIDIA-Merchant-ID': NVIDIA_AIQ_MERCHANT_ID,
  };
}

// Create AI inference payment
router.post('/create-inference-payment', async (req, res) => {
  try {
    const {
      modelId,
      inferenceType,
      amount,
      currency = 'USD',
      customerEmail,
      inferenceParameters,
    } = req.body;

    if (!modelId || !inferenceType || !amount) {
      return res.status(400).json({
        success: false,
        error: 'Model ID, inference type, and amount are required',
      });
    }

    const headers = generateAuthHeaders();

    const paymentData = {
      merchantId: NVIDIA_AIQ_MERCHANT_ID,
      transactionType: 'inference',
      modelId: modelId,
      inferenceType: inferenceType,
      amount: {
        value: amount,
        currency: currency,
      },
      customer: {
        email: customerEmail,
      },
      inferenceParameters: inferenceParameters || {},
      metadata: {
        timestamp: new Date().toISOString(),
        source: 'oscar-broome-revenue-system',
      },
    };

    const response = await axios.post(
      `${NVIDIA_AIQ_BASE_URL}/v1/payments/inference`,
      paymentData,
      { headers }
    );

    res.json({
      success: true,
      paymentId: response.data.paymentId,
      inferenceId: response.data.inferenceId,
      status: response.data.status,
      costBreakdown: response.data.costBreakdown,
      transactionDetails: response.data,
    });
  } catch (error) {
    logger.error(
      'NVIDIA AIQ payment creation error:',
      error.response?.data || error.message
    );
    res.status(500).json({
      success: false,
      error: 'Failed to create inference payment',
      details: error.response?.data || error.message,
    });
  }
});

// Get inference payment status
router.get('/payment-status/:paymentId', async (req, res) => {
  try {
    const { paymentId } = req.params;

    const headers = generateAuthHeaders();

    const response = await axios.get(
      `${NVIDIA_AIQ_BASE_URL}/v1/payments/${paymentId}`,
      { headers }
    );

    res.json({
      success: true,
      paymentStatus: response.data.status,
      inferenceResults: response.data.inferenceResults,
      costDetails: response.data.costDetails,
      transactionInfo: response.data,
    });
  } catch (error) {
    logger.error(
      'NVIDIA AIQ payment status error:',
      error.response?.data || error.message
    );
    res.status(500).json({
      success: false,
      error: 'Failed to get payment status',
      details: error.response?.data || error.message,
    });
  }
});

// Get GPU usage billing
router.post('/gpu-usage-billing', async (req, res) => {
  try {
    const { gpuType, hoursUsed, memoryUsageGB, customerId, projectId } =
      req.body;

    if (!gpuType || !hoursUsed) {
      return res.status(400).json({
        success: false,
        error: 'GPU type and hours used are required',
      });
    }

    const headers = generateAuthHeaders();

    const billingData = {
      merchantId: NVIDIA_AIQ_MERCHANT_ID,
      transactionType: 'gpu_usage',
      gpuType: gpuType,
      hoursUsed: hoursUsed,
      memoryUsageGB: memoryUsageGB || 0,
      customerId: customerId,
      projectId: projectId,
      metadata: {
        timestamp: new Date().toISOString(),
        billingPeriod: 'hourly',
      },
    };

    const response = await axios.post(
      `${NVIDIA_AIQ_BASE_URL}/v1/billing/gpu-usage`,
      billingData,
      { headers }
    );

    res.json({
      success: true,
      billingId: response.data.billingId,
      totalCost: response.data.totalCost,
      costBreakdown: response.data.costBreakdown,
      usageDetails: response.data.usageDetails,
    });
  } catch (error) {
    logger.error(
      'NVIDIA GPU billing error:',
      error.response?.data || error.message
    );
    res.status(500).json({
      success: false,
      error: 'Failed to process GPU usage billing',
      details: error.response?.data || error.message,
    });
  }
});

// Get available GPU models and pricing
router.get('/gpu-models', async (req, res) => {
  try {
    const headers = generateAuthHeaders();

    const response = await axios.get(
      `${NVIDIA_AIQ_BASE_URL}/v1/catalog/gpu-models`,
      { headers }
    );

    res.json({
      success: true,
      gpuModels: response.data.models,
      pricingTiers: response.data.pricing,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error(
      'NVIDIA GPU models error:',
      error.response?.data || error.message
    );
    res.status(500).json({
      success: false,
      error: 'Failed to fetch GPU models',
      details: error.response?.data || error.message,
    });
  }
});

// Create subscription for recurring AI services
router.post('/create-subscription', async (req, res) => {
  try {
    const {
      planId,
      customerEmail,
      billingInterval = 'monthly',
      paymentMethod = 'card',
    } = req.body;

    if (!planId || !customerEmail) {
      return res.status(400).json({
        success: false,
        error: 'Plan ID and customer email are required',
      });
    }

    const headers = generateAuthHeaders();

    const subscriptionData = {
      merchantId: NVIDIA_AIQ_MERCHANT_ID,
      planId: planId,
      customer: {
        email: customerEmail,
      },
      billingInterval: billingInterval,
      paymentMethod: paymentMethod,
      startDate: new Date().toISOString().split('T')[0],
      metadata: {
        created: new Date().toISOString(),
        source: 'oscar-broome-revenue-system',
      },
    };

    const response = await axios.post(
      `${NVIDIA_AIQ_BASE_URL}/v1/subscriptions`,
      subscriptionData,
      { headers }
    );

    res.json({
      success: true,
      subscriptionId: response.data.subscriptionId,
      status: response.data.status,
      nextBillingDate: response.data.nextBillingDate,
      subscriptionDetails: response.data,
    });
  } catch (error) {
    logger.error(
      'NVIDIA subscription creation error:',
      error.response?.data || error.message
    );
    res.status(500).json({
      success: false,
      error: 'Failed to create subscription',
      details: error.response?.data || error.message,
    });
  }
});

// Health check endpoint for NVIDIA integration
router.get('/health', async (req, res) => {
  try {
    const headers = generateAuthHeaders();

    // Simple health check by making a small API call
    const response = await axios.get(`${NVIDIA_AIQ_BASE_URL}/v1/health`, {
      headers,
      timeout: 5000,
    });

    res.json({
      status: 'healthy',
      nvidiaStatus: response.data.status,
      gpuAvailability: response.data.gpuAvailability,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      error: 'NVIDIA AIQ API unavailable',
      details: error.message,
    });
  }
});

module.exports = {
  router,
  generateAuthHeaders,
};
