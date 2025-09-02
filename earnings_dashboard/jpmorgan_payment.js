const express = require('express');
const router = express.Router();
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// JPMorgan Payments API Configuration
const JPMORGAN_BASE_URL = process.env.JPMORGAN_BASE_URL || 'https://api.payments.jpmorgan.com';
const JPMORGAN_ORGANIZATION_ID = process.env.JPMORGAN_ORGANIZATION_ID || 'D3R56WRGSR3R';
const JPMORGAN_PROJECT_ID = process.env.JPMORGAN_PROJECT_ID || 'D4YZRR0LSDXX';
const JPMORGAN_CLIENT_ID = process.env.JPMORGAN_CLIENT_ID;
const JPMORGAN_CLIENT_SECRET = process.env.JPMORGAN_CLIENT_SECRET;
const JPMORGAN_MERCHANT_ID = process.env.JPMORGAN_MERCHANT_ID;
const JPMORGAN_TERMINAL_ID = process.env.JPMORGAN_TERMINAL_ID;

// Revenue data path
const revenueDataPath = path.resolve(__dirname, '../owlban_repos/sample_repo/revenue.json');

function readRevenueData() {
  if (!fs.existsSync(revenueDataPath)) {
    return null;
  }
  const data = JSON.parse(fs.readFileSync(revenueDataPath, 'utf-8'));
  if (!data.purchases) {
    data.purchases = {
      corporateHomes: 0,
      autoFleet: 0,
      autoFleetDetails: []
    };
  }
  return data;
}

function writeRevenueData(data) {
  fs.writeFileSync(revenueDataPath, JSON.stringify(data, null, 2), 'utf-8');
}

// Generate JPMorgan authentication headers
function generateAuthHeaders() {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(16).toString('hex');
  const message = `${JPMORGAN_CLIENT_ID}${timestamp}${nonce}`;
  const signature = crypto
    .createHmac('sha256', JPMORGAN_CLIENT_SECRET)
    .update(message)
    .digest('base64');

  return {
    'Content-Type': 'application/json',
    'Client-Id': JPMORGAN_CLIENT_ID,
    'Timestamp': timestamp.toString(),
    'Nonce': nonce,
    'Signature': signature,
    'Merchant-Id': JPMORGAN_MERCHANT_ID,
    'Terminal-Id': JPMORGAN_TERMINAL_ID
  };
}

// Create payment transaction
router.post('/create-payment', async (req, res) => {
  try {
    const { amount, currency = 'USD', orderId, description, customer } = req.body;

    if (!amount || !orderId) {
      return res.status(400).json({ 
        success: false, 
        error: 'Amount and orderId are required' 
      });
    }

    const headers = generateAuthHeaders();

    const paymentData = {
      amount: {
        value: amount,
        currency: currency
      },
      order: {
        id: orderId,
        description: description || 'Payment for services'
      },
      customer: customer || {},
      merchant: {
        id: JPMORGAN_MERCHANT_ID,
        terminalId: JPMORGAN_TERMINAL_ID
      },
      paymentMethod: {
        type: 'CARD' // Default to card, can be extended for other methods
      }
    };

    const response = await axios.post(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/payments`,
      paymentData,
      { headers }
    );

    res.json({
      success: true,
      paymentId: response.data.id,
      status: response.data.status,
      authorizationCode: response.data.authorizationCode,
      transactionDetails: response.data
    });

  } catch (error) {
    console.error('JPMorgan payment creation error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to create payment',
      details: error.response?.data || error.message
    });
  }
});

// Get payment status
router.get('/payment-status/:paymentId', async (req, res) => {
  try {
    const { paymentId } = req.params;
    
    const headers = generateAuthHeaders();
    
    const response = await axios.get(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/payments/${paymentId}`,
      { headers }
    );

    res.json({
      success: true,
      paymentStatus: response.data
    });

  } catch (error) {
    console.error('JPMorgan payment status error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to get payment status',
      details: error.response?.data || error.message
    });
  }
});

// Refund payment
router.post('/refund', async (req, res) => {
  try {
    const { paymentId, amount, reason } = req.body;

    if (!paymentId || !amount) {
      return res.status(400).json({
        success: false,
        error: 'Payment ID and amount are required for refund'
      });
    }

    const headers = generateAuthHeaders();

    const refundData = {
      amount: {
        value: amount,
        currency: 'USD'
      },
      reason: reason || 'Customer request'
    };

    const response = await axios.post(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/payments/${paymentId}/refunds`,
      refundData,
      { headers }
    );

    res.json({
      success: true,
      refundId: response.data.id,
      status: response.data.status,
      refundDetails: response.data
    });

  } catch (error) {
    console.error('JPMorgan refund error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to process refund',
      details: error.response?.data || error.message
    });
  }
});

// Capture authorized payment
router.post('/capture', async (req, res) => {
  try {
    const { paymentId, amount } = req.body;

    if (!paymentId) {
      return res.status(400).json({
        success: false,
        error: 'Payment ID is required'
      });
    }

    const headers = generateAuthHeaders();

    const captureData = {
      amount: amount ? {
        value: amount,
        currency: 'USD'
      } : undefined
    };

    const response = await axios.post(
      `${JPMORGAN_BASE_URL}/v1/payments/${paymentId}/capture`,
      captureData,
      { headers }
    );

    res.json({
      success: true,
      captureId: response.data.id,
      status: response.data.status,
      captureDetails: response.data
    });

  } catch (error) {
    console.error('JPMorgan capture error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to capture payment',
      details: error.response?.data || error.message
    });
  }
});

// Void/Cancel payment
router.post('/void', async (req, res) => {
  try {
    const { paymentId, reason } = req.body;

    if (!paymentId) {
      return res.status(400).json({
        success: false,
        error: 'Payment ID is required'
      });
    }

    const headers = generateAuthHeaders();

    const voidData = {
      reason: reason || 'Customer request'
    };

    const response = await axios.post(
      `${JPMORGAN_BASE_URL}/v1/payments/${paymentId}/void`,
      voidData,
      { headers }
    );

    res.json({
      success: true,
      voidId: response.data.id,
      status: response.data.status,
      voidDetails: response.data
    });

  } catch (error) {
    console.error('JPMorgan void error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to void payment',
      details: error.response?.data || error.message
    });
  }
});

// Get transaction history
router.get('/transactions', async (req, res) => {
  try {
    const { startDate, endDate, status, limit = 50 } = req.query;

    const headers = generateAuthHeaders();

    const params = new URLSearchParams();
    if (startDate) params.append('startDate', startDate);
    if (endDate) params.append('endDate', endDate);
    if (status) params.append('status', status);
    params.append('limit', limit.toString());

    const response = await axios.get(
      `${JPMORGAN_BASE_URL}/v1/transactions?${params}`,
      { headers }
    );

    res.json({
      success: true,
      transactions: response.data.transactions,
      totalCount: response.data.totalCount
    });

  } catch (error) {
    console.error('JPMorgan transactions error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch transactions',
      details: error.response?.data || error.message
    });
  }
});

// Webhook verification middleware
const verifyWebhookSignature = (req, res, next) => {
  try {
    const signature = req.headers['x-jpmorgan-signature'];
    const timestamp = req.headers['x-jpmorgan-timestamp'];
    const nonce = req.headers['x-jpmorgan-nonce'];

    if (!signature || !timestamp || !nonce) {
      return res.status(401).json({ error: 'Missing authentication headers' });
    }

    const message = `${timestamp}${nonce}${JSON.stringify(req.body)}`;
    const expectedSignature = crypto
      .createHmac('sha256', JPMORGAN_CLIENT_SECRET)
      .update(message)
      .digest('base64');

    if (signature !== expectedSignature) {
      return res.status(401).json({ error: 'Invalid webhook signature' });
    }

    next();
  } catch (error) {
    console.error('Webhook verification error:', error);
    res.status(500).json({ error: 'Webhook verification failed' });
  }
};

// Webhook endpoint for JPMorgan Payments events
router.post('/webhook', express.json(), verifyWebhookSignature, async (req, res) => {
  try {
    const event = req.body;

    console.log('Received JPMorgan webhook event:', event.type, event.id);

    switch (event.type) {
      case 'payment.authorized':
        // Handle authorized payment
        console.log('Payment authorized:', event.data.paymentId);
        break;

      case 'payment.captured':
        // Handle captured payment
        console.log('Payment captured:', event.data.paymentId);
        break;

      case 'payment.refunded':
        // Handle refund
        console.log('Payment refunded:', event.data.paymentId);
        break;

      case 'payment.voided':
        // Handle voided payment
        console.log('Payment voided:', event.data.paymentId);
        break;

      case 'payment.failed':
        // Handle failed payment
        console.log('Payment failed:', event.data.paymentId, event.data.reason);
        break;

      default:
        console.log('Unhandled webhook event type:', event.type);
    }

    res.json({ received: true });

  } catch (error) {
    console.error('Webhook processing error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Health check endpoint for JPMorgan integration
router.get('/health', async (req, res) => {
  try {
    const headers = generateAuthHeaders();
    
    // Simple health check by making a small API call
    const response = await axios.get(
      `${JPMORGAN_BASE_URL}/v1/health`,
      { headers, timeout: 5000 }
    );

    res.json({
      status: 'healthy',
      jpmorganStatus: response.data.status,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      error: 'JPMorgan API unavailable',
      details: error.message
    });
  }
});

module.exports = router;
