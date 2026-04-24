import express from 'express';
import crypto from 'node:crypto';
import axios from 'axios';
import { info, error } from 'utils/loggerWrapper.js';

const router = express.Router();

// Health check endpoint for JPMorgan integration
router.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'JPMorgan Payment Integration',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    endpoints: [
      'POST /jpmorgan/create-payment',
      'GET /jpmorgan/payment-status/:paymentId',
      'POST /jpmorgan/refund',
      'POST /jpmorgan/capture',
      'POST /jpmorgan/void',
      'GET /jpmorgan/transactions',
      'POST /jpmorgan/webhook',
    ],
  });
});

// Environment variables
const JPMORGAN_CLIENT_ID = process.env.JPMORGAN_CLIENT_ID;
const JPMORGAN_CLIENT_SECRET = process.env.JPMORGAN_CLIENT_SECRET;
const JPMORGAN_BASE_URL =
  process.env.JPMORGAN_BASE_URL || 'https://api-mock.payments.jpmorgan.com';
const JPMORGAN_ORGANIZATION_ID = process.env.JPMORGAN_ORGANIZATION_ID;
const JPMORGAN_PROJECT_ID = process.env.JPMORGAN_PROJECT_ID || 'DK2MQSR1FS7V';
const JPMORGAN_MERCHANT_ID = process.env.JPMORGAN_MERCHANT_ID;
const JPMORGAN_TERMINAL_ID = process.env.JPMORGAN_TERMINAL_ID;

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
    Timestamp: timestamp.toString(),
    Nonce: nonce,
    Signature: signature,
    'Merchant-Id': JPMORGAN_MERCHANT_ID,
    'Terminal-Id': JPMORGAN_TERMINAL_ID,
  };
}

// Wallet Decryption API endpoint
router.post('/wallet-decrypt', async (req, res) => {
  try {
    const { encryptedWalletData } = req.body;

    if (!encryptedWalletData) {
      return res.status(400).json({
        success: false,
        error: 'encryptedWalletData is required',
      });
    }

    const headers = generateAuthHeaders();

    const decryptPayload = {
      encryptedWalletData,
    };

    const response = await axios.post(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/wallet/decrypt`,
      decryptPayload,
      { headers }
    );

    res.json({
      success: true,
      decryptedWallet: response.data,
    });
  } catch (error) {
    error(
      'JPMorgan wallet decryption error:',
      error.response?.data || error.message
    );
    res.status(500).json({
      success: false,
      error: 'Failed to decrypt wallet data',
      details: error.response?.data || error.message,
    });
  }
});

// Create payment transaction
router.post('/create-payment', async (req, res) => {
  try {
    const {
      amount,
      currency = 'USD',
      orderId,
      description,
      customer,
    } = req.body;

    if (!amount || !orderId) {
      return res.status(400).json({
        success: false,
        error: 'Amount and orderId are required',
      });
    }

    // Check if credentials are configured for live API calls
    const hasCredentials =
      JPMORGAN_CLIENT_ID &&
      JPMORGAN_CLIENT_SECRET &&
      JPMORGAN_MERCHANT_ID &&
      JPMORGAN_TERMINAL_ID;

    if (!hasCredentials) {
      // Mock mode - return mock response
      const mockPaymentId = `mock-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

      // Handle both simple format {amount: 100, currency: 'USD'} and nested format {amount: {value: 100, currency: 'USD'}}
      let paymentAmount;
      if (typeof amount === 'object' && amount.value !== undefined) {
        // Nested format: {amount: {value: 100, currency: 'USD'}}
        paymentAmount = {
          value: amount.value,
          currency: amount.currency || currency,
        };
      } else {
        // Simple format: {amount: 100, currency: 'USD'}
        paymentAmount = {
          value: amount,
          currency: currency,
        };
      }

      return res.json({
        success: true,
        paymentId: mockPaymentId,
        status: 'AUTHORIZED',
        authorizationCode: `AUTH-${Date.now()}`,
        transactionDetails: {
          id: mockPaymentId,
          amount: paymentAmount,
          status: 'AUTHORIZED',
          orderId: orderId,
          description: description || 'Payment for services',
          customer: customer || {},
          createdAt: new Date().toISOString(),
          mock: true,
        },
      });
    }

    const headers = generateAuthHeaders();

    // Handle both simple format {amount: 100, currency: 'USD'} and nested format {amount: {value: 100, currency: 'USD'}}
    let paymentAmount;
    if (typeof amount === 'object' && amount.value !== undefined) {
      // Nested format: {amount: {value: 100, currency: 'USD'}}
      paymentAmount = {
        value: amount.value,
        currency: amount.currency || currency,
      };
    } else {
      // Simple format: {amount: 100, currency: 'USD'}
      paymentAmount = {
        value: amount,
        currency: currency,
      };
    }

    const paymentData = {
      amount: paymentAmount,
      order: {
        id: orderId,
        description: description || 'Payment for services',
      },
      customer: customer || {},
      merchant: {
        id: JPMORGAN_MERCHANT_ID,
        terminalId: JPMORGAN_TERMINAL_ID,
      },
      paymentMethod: {
        type: 'CARD',
      },
    };

    const response = await axios.post(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/payments`,
      paymentData,
      { headers, timeout: 30000 }
    );

    res.json({
      success: true,
      paymentId: response.data.id,
      status: response.data.status,
      authorizationCode: response.data.authorizationCode,
      transactionDetails: response.data,
    });
  } catch (err) {
    error(
      'JPMorgan payment creation error:',
      err.response?.data || err.message
    );
    res.status(500).json({
      success: false,
      error: 'Failed to create payment',
      details: err.response?.data || err.message,
    });
  }
});

// Get payment status
router.get('/payment-status/:paymentId', async (req, res) => {
  try {
    const { paymentId } = req.params;

    // Check if credentials are configured for live API calls
    const hasCredentials =
      JPMORGAN_CLIENT_ID &&
      JPMORGAN_CLIENT_SECRET &&
      JPMORGAN_MERCHANT_ID &&
      JPMORGAN_TERMINAL_ID;

    if (!hasCredentials || paymentId.startsWith('mock-')) {
      // Mock mode - return mock response
      return res.json({
        success: true,
        paymentStatus: {
          id: paymentId,
          status: 'AUTHORIZED',
          amount: {
            value: 100.0,
            currency: 'USD',
          },
          orderId: `TEST-${Date.now()}`,
          createdAt: new Date().toISOString(),
          mock: true,
        },
      });
    }

    const headers = generateAuthHeaders();

    const response = await axios.get(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/payments/${paymentId}`,
      { headers, timeout: 30000 }
    );

    res.json({
      success: true,
      paymentStatus: response.data,
    });
  } catch (error) {
    error(
      'JPMorgan payment status error:',
      error.response?.data || error.message
    );
    res.status(500).json({
      success: false,
      error: 'Failed to get payment status',
      details: error.response?.data || error.message,
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
        error: 'Payment ID and amount are required for refund',
      });
    }

    // Check if credentials are configured for live API calls
    const hasCredentials =
      JPMORGAN_CLIENT_ID &&
      JPMORGAN_CLIENT_SECRET &&
      JPMORGAN_MERCHANT_ID &&
      JPMORGAN_TERMINAL_ID;

    if (!hasCredentials || paymentId.startsWith('mock-')) {
      // Mock mode - return mock response
      const mockRefundId = `refund-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      return res.json({
        success: true,
        refundId: mockRefundId,
        status: 'COMPLETED',
        refundDetails: {
          id: mockRefundId,
          paymentId: paymentId,
          amount: {
            value: amount,
            currency: 'USD',
          },
          reason: reason || 'Customer request',
          status: 'COMPLETED',
          createdAt: new Date().toISOString(),
          mock: true,
        },
      });
    }

    const headers = generateAuthHeaders();

    const refundData = {
      amount: {
        value: amount,
        currency: 'USD',
      },
      reason: reason || 'Customer request',
    };

    const response = await axios.post(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/payments/${paymentId}/refunds`,
      refundData,
      { headers, timeout: 30000 }
    );

    res.json({
      success: true,
      refundId: response.data.id,
      status: response.data.status,
      refundDetails: response.data,
    });
  } catch (error) {
    error('JPMorgan refund error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to process refund',
      details: error.response?.data || error.message,
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
        error: 'Payment ID is required',
      });
    }

    // Check if credentials are configured for live API calls
    const hasCredentials =
      JPMORGAN_CLIENT_ID &&
      JPMORGAN_CLIENT_SECRET &&
      JPMORGAN_MERCHANT_ID &&
      JPMORGAN_TERMINAL_ID;

    if (!hasCredentials || paymentId.startsWith('mock-')) {
      // Mock mode - return mock response
      const mockCaptureId = `capture-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      return res.json({
        success: true,
        captureId: mockCaptureId,
        status: 'COMPLETED',
        captureDetails: {
          id: mockCaptureId,
          paymentId: paymentId,
          amount: amount
            ? {
                value: amount,
                currency: 'USD',
              }
            : {
                value: 100.0,
                currency: 'USD',
              },
          status: 'COMPLETED',
          createdAt: new Date().toISOString(),
          mock: true,
        },
      });
    }

    const headers = generateAuthHeaders();

    const captureData = {
      amount: amount
        ? {
            value: amount,
            currency: 'USD',
          }
        : undefined,
    };

    const response = await axios.post(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/payments/${paymentId}/capture`,
      captureData,
      { headers, timeout: 30000 }
    );

    res.json({
      success: true,
      captureId: response.data.id,
      status: response.data.status,
      captureDetails: response.data,
    });
  } catch (error) {
    error('JPMorgan capture error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to capture payment',
      details: error.response?.data || error.message,
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
        error: 'Payment ID is required',
      });
    }

    // Check if credentials are configured for live API calls
    const hasCredentials =
      JPMORGAN_CLIENT_ID &&
      JPMORGAN_CLIENT_SECRET &&
      JPMORGAN_MERCHANT_ID &&
      JPMORGAN_TERMINAL_ID;

    if (!hasCredentials || paymentId.startsWith('mock-')) {
      // Mock mode - return mock response
      const mockVoidId = `void-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      return res.json({
        success: true,
        voidId: mockVoidId,
        status: 'COMPLETED',
        voidDetails: {
          id: mockVoidId,
          paymentId: paymentId,
          reason: reason || 'Customer request',
          status: 'COMPLETED',
          createdAt: new Date().toISOString(),
          mock: true,
        },
      });
    }

    const headers = generateAuthHeaders();

    const voidData = {
      reason: reason || 'Customer request',
    };

    const response = await axios.post(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/payments/${paymentId}/void`,
      voidData,
      { headers, timeout: 30000 }
    );

    res.json({
      success: true,
      voidId: response.data.id,
      status: response.data.status,
      voidDetails: response.data,
    });
  } catch (error) {
    error('JPMorgan void error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to void payment',
      details: error.response?.data || error.message,
    });
  }
});

// Get transaction history
router.get('/transactions', async (req, res) => {
  try {
    const { startDate, endDate, status, limit = 50 } = req.query;

    // Check if credentials are configured for live API calls
    const hasCredentials =
      JPMORGAN_CLIENT_ID &&
      JPMORGAN_CLIENT_SECRET &&
      JPMORGAN_MERCHANT_ID &&
      JPMORGAN_TERMINAL_ID;

    if (!hasCredentials) {
      // Mock mode - return mock response
      const mockTransactions = [];
      const limitNum = parseInt(limit) || 10;

      for (let i = 0; i < Math.min(limitNum, 5); i++) {
        mockTransactions.push({
          id: `txn-${Date.now()}-${i}`,
          paymentId: `mock-${Date.now()}-${i}`,
          amount: {
            value: Math.floor(Math.random() * 500) + 50,
            currency: 'USD',
          },
          status: ['AUTHORIZED', 'CAPTURED', 'COMPLETED'][
            Math.floor(Math.random() * 3)
          ],
          createdAt: new Date(
            Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000
          ).toISOString(),
          mock: true,
        });
      }

      return res.json({
        success: true,
        transactions: mockTransactions,
        totalCount: mockTransactions.length,
      });
    }

    const headers = generateAuthHeaders();

    const params = new URLSearchParams();
    if (startDate) params.append('startDate', startDate);
    if (endDate) params.append('endDate', endDate);
    if (status) params.append('status', status);
    params.append('limit', limit.toString());

    const response = await axios.get(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/transactions?${params}`,
      { headers, timeout: 30000 }
    );

    res.json({
      success: true,
      transactions: response.data.transactions,
      totalCount: response.data.totalCount,
    });
  } catch (error) {
    error(
      'JPMorgan transactions error:',
      error.response?.data || error.message
    );
    res.status(500).json({
      success: false,
      error: 'Failed to fetch transactions',
      details: error.response?.data || error.message,
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
    error('Webhook verification error:', error);
    res.status(500).json({ error: 'Webhook verification failed' });
  }
};

// Webhook endpoint for JPMorgan Payments events
router.post(
  '/webhook',
  express.json(),
  verifyWebhookSignature,
  async (req, res) => {
    try {
      const event = req.body;

      info('Received JPMorgan webhook event:', event.type, event.id);

      switch (event.type) {
        case 'payment.authorized':
          info('Payment authorized:', event.data.paymentId);
          break;

        case 'payment.captured':
          info('Payment captured:', event.data.paymentId);
          break;

        case 'payment.refunded':
          info('Payment refunded:', event.data.paymentId);
          break;

        case 'payment.voided':
          info('Payment voided:', event.data.paymentId);
          break;

        case 'payment.failed':
          info('Payment failed:', event.data.paymentId, event.data.reason);
          break;

        default:
          info('Unhandled webhook event type:', event.type);
      }

      res.json({ received: true });
    } catch (error) {
      error('Webhook processing error:', error);
      res.status(500).json({ error: 'Webhook processing failed' });
    }
  }
);

export default router;
