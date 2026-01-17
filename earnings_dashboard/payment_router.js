import { info, error, warn, debug } from '../utils/loggerWrapper.js';

const express = require('express');
const router = express.Router();

// Import Node.js payment integrations
const jpmorganPayment = require('./jpmorgan_payment_perfect');
const microsoftPayment = require('./microsoft_payment');
const nvidiaPayment = require('./nvidia_payment');

// For Python integrations, we'll create proxy endpoints
// Note: Chase integration is a Python Flask app that would need to run separately

// Payment service orchestrator
class PaymentOrchestrator {
  constructor() {
    this.providers = {
      jpmorgan: {
        type: 'nodejs',
        module: jpmorganPayment,
        processPayment: async (data) => {
          // JPMorgan specific payment processing
          return await this._processJPMorganPayment(data);
        },
        getPaymentStatus: async (paymentId) => {
          return await this._getJPMorganPaymentStatus(paymentId);
        },
        refundPayment: async (paymentId, amount) => {
          return await this._refundJPMorganPayment(paymentId, amount);
        },
      },
      microsoft: {
        type: 'nodejs',
        module: microsoftPayment,
        processPayment: async (data) => {
          return await this._processMicrosoftPayment(data);
        },
        getPaymentStatus: async (paymentId) => {
          return await this._getMicrosoftPaymentStatus(paymentId);
        },
        refundPayment: async (paymentId, amount) => {
          return await this._refundMicrosoftPayment(paymentId, amount);
        },
      },
      nvidia: {
        type: 'nodejs',
        module: nvidiaPayment,
        processPayment: async (data) => {
          return await this._processNvidiaPayment(data);
        },
        getPaymentStatus: async (paymentId) => {
          return await this._getNvidiaPaymentStatus(paymentId);
        },
        refundPayment: async (paymentId, amount) => {
          return await this._refundNvidiaPayment(paymentId, amount);
        },
      },
      chase: {
        type: 'python',
        baseUrl:
          process.env.CHASE_PAYMENT_SERVICE_URL || 'http://localhost:5001',
        processPayment: async (data) => {
          return await this._proxyToPythonService(
            'chase',
            'process-payment',
            data
          );
        },
        getPaymentStatus: async (paymentId) => {
          return await this._proxyToPythonService(
            'chase',
            `payment-status/${paymentId}`
          );
        },
        refundPayment: async (paymentId, amount) => {
          return await this._proxyToPythonService(
            'chase',
            `refund/${paymentId}`,
            { amount }
          );
        },
      },
    };
  }

  async processPayment(provider, paymentData) {
    const paymentProvider = this.providers[provider];
    if (!paymentProvider) {
      throw new Error(`Payment provider '${provider}' not found`);
    }

    try {
      return await paymentProvider.processPayment(paymentData);
    } catch (error) {
      logger.error(`Payment processing error for ${provider}:`, error);
      throw error;
    }
  }

  async getPaymentStatus(provider, paymentId) {
    const paymentProvider = this.providers[provider];
    if (!paymentProvider) {
      throw new Error(`Payment provider '${provider}' not found`);
    }

    try {
      return await paymentProvider.getPaymentStatus(paymentId);
    } catch (error) {
      logger.error(`Payment status error for ${provider}:`, error);
      throw error;
    }
  }

  async refundPayment(provider, paymentId, amount) {
    const paymentProvider = this.providers[provider];
    if (!paymentProvider) {
      throw new Error(`Payment provider '${provider}' not found`);
    }

    try {
      return await paymentProvider.refundPayment(paymentId, amount);
    } catch (error) {
      logger.error(`Payment refund error for ${provider}:`, error);
      throw error;
    }
  }

  // JPMorgan specific methods
  async _processJPMorganPayment(data) {
    // This would integrate with JPMorgan's actual payment processing
    // For now, return a mock response
    return {
      success: true,
      paymentId: `jpm_${Date.now()}`,
      status: 'processed',
      amount: data.amount,
      currency: data.currency || 'USD',
      timestamp: new Date().toISOString(),
    };
  }

  async _getJPMorganPaymentStatus(paymentId) {
    return {
      success: true,
      paymentId,
      status: 'completed',
      details: { processedAt: new Date().toISOString() },
    };
  }

  async _refundJPMorganPayment(paymentId, amount) {
    return {
      success: true,
      refundId: `refund_${Date.now()}`,
      originalPaymentId: paymentId,
      amount,
      status: 'processed',
    };
  }

  // Microsoft specific methods
  async _processMicrosoftPayment(data) {
    return {
      success: true,
      paymentId: `ms_${Date.now()}`,
      status: 'processed',
      amount: data.amount,
      currency: data.currency || 'USD',
      timestamp: new Date().toISOString(),
    };
  }

  async _getMicrosoftPaymentStatus(paymentId) {
    return {
      success: true,
      paymentId,
      status: 'completed',
      details: { processedAt: new Date().toISOString() },
    };
  }

  async _refundMicrosoftPayment(paymentId, amount) {
    return {
      success: true,
      refundId: `ms_refund_${Date.now()}`,
      originalPaymentId: paymentId,
      amount,
      status: 'processed',
    };
  }

  // NVIDIA specific methods
  async _processNvidiaPayment(data) {
    return {
      success: true,
      paymentId: `nv_${Date.now()}`,
      status: 'processed',
      amount: data.amount,
      currency: data.currency || 'USD',
      timestamp: new Date().toISOString(),
    };
  }

  async _getNvidiaPaymentStatus(paymentId) {
    return {
      success: true,
      paymentId,
      status: 'completed',
      details: { processedAt: new Date().toISOString() },
    };
  }

  async _refundNvidiaPayment(paymentId, amount) {
    return {
      success: true,
      refundId: `nv_refund_${Date.now()}`,
      originalPaymentId: paymentId,
      amount,
      status: 'processed',
    };
  }

  // Python service proxy
  async _proxyToPythonService(provider, endpoint, data = null) {
    const providerConfig = this.providers[provider];
    const axios = require('axios');

    try {
      const url = `${providerConfig.baseUrl}/api/${endpoint}`;
      const config = {
        method: data ? 'POST' : 'GET',
        url,
        headers: {
          'Content-Type': 'application/json',
        },
      };

      if (data) {
        config.data = data;
      }

      const response = await axios(config);
      return response.data;
    } catch (error) {
      logger.error(
        `Python service proxy error for ${provider}:`,
        error.message
      );
      throw new Error(`Failed to communicate with ${provider} payment service`);
    }
  }
}

const orchestrator = new PaymentOrchestrator();

// Unified payment endpoints
router.post('/create-payment', async (req, res) => {
  try {
    const { provider, ...paymentData } = req.body;

    if (!provider) {
      return res.status(400).json({
        success: false,
        message: 'Payment provider is required',
      });
    }

    const result = await orchestrator.processPayment(provider, paymentData);
    res.json(result);
  } catch (error) {
    logger.error('Payment creation error:', error);
    res.status(500).json({
      success: false,
      message: 'Payment processing failed',
      error: error.message,
    });
  }
});

router.get('/payment-status/:provider/:paymentId', async (req, res) => {
  try {
    const { provider, paymentId } = req.params;
    const result = await orchestrator.getPaymentStatus(provider, paymentId);
    res.json(result);
  } catch (error) {
    logger.error('Payment status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get payment status',
      error: error.message,
    });
  }
});

router.post('/refund/:provider/:paymentId', async (req, res) => {
  try {
    const { provider, paymentId } = req.params;
    const { amount } = req.body;

    const result = await orchestrator.refundPayment(
      provider,
      paymentId,
      amount
    );
    res.json(result);
  } catch (error) {
    logger.error('Payment refund error:', error);
    res.status(500).json({
      success: false,
      message: 'Refund processing failed',
      error: error.message,
    });
  }
});

// Provider-specific routes for Node.js integrations
router.use('/jpmorgan', jpmorganPayment.router);
router.use('/microsoft', microsoftPayment.router);
router.use('/nvidia', nvidiaPayment.router);

// Proxy routes for Python integrations
router.post('/chase/:endpoint(*)', async (req, res) => {
  try {
    const endpoint = req.params.endpoint;
    const result = await orchestrator._proxyToPythonService(
      'chase',
      endpoint,
      req.body
    );
    res.json(result);
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Chase payment service error',
      error: error.message,
    });
  }
});

router.get('/chase/:endpoint(*)', async (req, res) => {
  try {
    const endpoint = req.params.endpoint;
    const result = await orchestrator._proxyToPythonService('chase', endpoint);
    res.json(result);
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Chase payment service error',
      error: error.message,
    });
  }
});

// Health check
router.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Payment service is healthy',
    providers: Object.keys(orchestrator.providers),
    timestamp: new Date().toISOString(),
  });
});

module.exports = router;
