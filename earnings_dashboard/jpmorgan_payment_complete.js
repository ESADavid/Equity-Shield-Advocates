import express from 'express';
import crypto from 'node:crypto';
import axios from 'axios';

// Utility function for currency formatting
const formatCurrency = (amount, currency = 'USD') => {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: currency
  }).format(amount);
};

const router = express.Router();

// Import middleware
import { securityHeaders, createRateLimit, validateInput } from '../../config/security.js';
import {
  validatePayment,
  validatePagination
} from '../../middleware/validation.js';

// Environment variables
const JPMORGAN_CLIENT_ID = process.env.JPMORGAN_CLIENT_ID;
const JPMORGAN_CLIENT_SECRET = process.env.JPMORGAN_CLIENT_SECRET;
const JPMORGAN_BASE_URL = process.env.JPMORGAN_BASE_URL || 'https://api-mock.payments.jpmorgan.com';
const JPMORGAN_ORGANIZATION_ID = process.env.JPMORGAN_ORGANIZATION_ID;
const JPMORGAN_PROJECT_ID = process.env.JPMORGAN_PROJECT_ID || 'DK2MQSR1FS7V';
const JPMORGAN_MERCHANT_ID = process.env.JPMORGAN_MERCHANT_ID;
const JPMORGAN_TERMINAL_ID = process.env.JPMORGAN_TERMINAL_ID;

// Rate limiters
const createPaymentLimiter = createRateLimit(15 * 60 * 1000, 10); // 10 requests per 15 minutes
const generalLimiter = createRateLimit(15 * 60 * 1000, 100);
const webhookLimiter = createRateLimit(60 * 1000, 10); // 10 requests per minute

// Apply global security middleware
router.use(securityHeaders);
router.use(express.json());
router.use(validateInput);

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

// Wallet Decryption API endpoint
router.post('/wallet-decrypt', async (req, res) => {
  try {
    const { encryptedWalletData } = req.body;

    if (!encryptedWalletData) {
      return res.status(400).json({
        success: false,
        error: 'encryptedWalletData is required'
      });
    }

    const headers = generateAuthHeaders();

    const decryptPayload = {
      encryptedWalletData: encryptedWalletData
    };

    const response = await axios.post(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/wallet/decrypt`,
      decryptPayload,
      { headers }
    );

    res.json({
      success: true,
      decryptedWallet: response.data
    });

  } catch (error) {
    console.error('JPMorgan wallet decryption error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to decrypt wallet data',
      details: error.response?.data || error.message
    });
  }
});

// Wallet Encryption API endpoint
router.post('/wallet-encrypt', async (req, res) => {
  try {
    const { cardNumber, expiryDate, cvv, cardholderName, billingAddress } = req.body;

    if (!cardNumber || !expiryDate || !cvv || !cardholderName) {
      return res.status(400).json({
        success: false,
        error: 'cardNumber, expiryDate, cvv, and cardholderName are required'
      });
    }

    const headers = generateAuthHeaders();

    const encryptPayload = {
      cardNumber: cardNumber.replaceAll(/\s/g, ''), // Remove spaces
      expiryDate: expiryDate,
      cvv: cvv,
      cardholderName: cardholderName,
      billingAddress: billingAddress || {}
    };

    const response = await axios.post(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/wallet/encrypt`,
      encryptPayload,
      { headers }
    );

    res.json({
      success: true,
      encryptedData: response.data.encryptedWalletData,
      walletId: response.data.walletId
    });

  } catch (error) {
    console.error('JPMorgan wallet encryption error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to encrypt wallet data',
      details: error.response?.data || error.message
    });
  }
});

// Wallet Validation API endpoint
router.post('/wallet-validate', async (req, res) => {
  try {
    const { walletData } = req.body;

    if (!walletData) {
      return res.status(400).json({
        success: false,
        error: 'walletData is required'
      });
    }

    const headers = generateAuthHeaders();

    const validatePayload = {
      walletData: walletData
    };

    const response = await axios.post(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/wallet/validate`,
      validatePayload,
      { headers }
    );

    res.json({
      success: true,
      isValid: response.data.isValid,
      message: response.data.message,
      validationDetails: response.data.details
    });

  } catch (error) {
    console.error('JPMorgan wallet validation error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to validate wallet data',
      details: error.response?.data || error.message
    });
  }
});

// Wallet Tokenization API endpoint
router.post('/wallet-tokenize', async (req, res) => {
  try {
    const { cardNumber, expiryDate, cvv, cardholderName, billingAddress } = req.body;

    if (!cardNumber || !expiryDate || !cvv || !cardholderName) {
      return res.status(400).json({
        success: false,
        error: 'cardNumber, expiryDate, cvv, and cardholderName are required'
      });
    }

    const headers = generateAuthHeaders();

    const tokenizePayload = {
      cardNumber: cardNumber.replaceAll(/\s/g, ''), // Remove spaces
      expiryDate: expiryDate,
      cvv: cvv,
      cardholderName: cardholderName,
      billingAddress: billingAddress || {}
    };

    const response = await axios.post(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/wallet/tokenize`,
      tokenizePayload,
      { headers }
    );

    res.json({
      success: true,
      token: response.data.token,
      tokenId: response.data.tokenId,
      expiresAt: response.data.expiresAt
    });

  } catch (error) {
    console.error('JPMorgan wallet tokenization error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to tokenize wallet data',
      details: error.response?.data || error.message
    });
  }
});

// Wallet Detokenization API endpoint
router.post('/wallet-detokenize', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({
        success: false,
        error: 'token is required'
      });
    }

    const headers = generateAuthHeaders();

    const detokenizePayload = {
      token: token
    };

    const response = await axios.post(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/wallet/detokenize`,
      detokenizePayload,
      { headers }
    );

    res.json({
      success: true,
      walletData: response.data
    });

  } catch (error) {
    console.error('JPMorgan wallet detokenization error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to detokenize wallet data',
      details: error.response?.data || error.message
    });
  }
});

// Create payment transaction
router.post('/create-payment', createPaymentLimiter, validatePayment, async (req, res) => {
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
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/payments/${paymentId}/capture`,
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
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/payments/${paymentId}/void`,
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
router.get('/transactions', generalLimiter, async (req, res) => {
  try {
    const { startDate, endDate, status, limit = 50 } = req.query;

    const headers = generateAuthHeaders();

    const params = new URLSearchParams();
    if (startDate) params.append('startDate', startDate);
    if (endDate) params.append('endDate', endDate);
    if (status) params.append('status', status);
    params.append('limit', limit.toString());

    const response = await axios.get(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/transactions?${params}`,
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
router.post('/webhook', webhookLimiter, express.json(), verifyWebhookSignature, async (req, res) => {
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

export default router;
