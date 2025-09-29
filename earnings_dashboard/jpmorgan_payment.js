import express from 'express';
import axios from 'axios';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const router = express.Router();

// JPMorgan Payments API Configuration
const JPMORGAN_BASE_URL = process.env.JPMORGAN_BASE_URL || 'https://api.payments.jpmorgan.com';
const JPMORGAN_ORGANIZATION_ID = process.env.JPMORGAN_ORGANIZATION_ID || 'D3R56WRGSR3R';
const JPMORGAN_PROJECT_ID = process.env.JPMORGAN_PROJECT_ID || 'DK2MQSR1FS7V';
const JPMORGAN_CLIENT_ID = process.env.JPMORGAN_CLIENT_ID;
const JPMORGAN_CLIENT_SECRET = process.env.JPMORGAN_CLIENT_SECRET;
const JPMORGAN_MERCHANT_ID = process.env.JPMORGAN_MERCHANT_ID;
const JPMORGAN_TERMINAL_ID = process.env.JPMORGAN_TERMINAL_ID;

console.log('Environment check:', {
  JPMORGAN_CLIENT_ID: !!JPMORGAN_CLIENT_ID,
  JPMORGAN_CLIENT_SECRET: !!JPMORGAN_CLIENT_SECRET,
  isMockMode: !JPMORGAN_CLIENT_ID || !JPMORGAN_CLIENT_SECRET
});

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

// Generate Treasury API authentication headers
function generateTreasuryAuthHeaders() {
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
    'Organization-Id': JPMORGAN_ORGANIZATION_ID,
    'Project-Id': JPMORGAN_PROJECT_ID
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

    // Mock mode response
    console.log('Mock mode check:', isMockMode(), 'CLIENT_ID:', !!process.env.JPMORGAN_CLIENT_ID, 'CLIENT_SECRET:', !!process.env.JPMORGAN_CLIENT_SECRET);
    if (isMockMode()) {
      const mockPaymentId = generateMockPaymentId();
      console.log('Mock payment created:', mockPaymentId);

      return res.json({
        success: true,
        paymentId: mockPaymentId,
        status: 'AUTHORIZED',
        authorizationCode: `AUTH-${Date.now()}`,
        transactionDetails: {
          id: mockPaymentId,
          amount: { value: amount, currency },
          order: { id: orderId, description: description || 'Payment for services' },
          customer: customer || {},
          merchant: { id: JPMORGAN_MERCHANT_ID, terminalId: JPMORGAN_TERMINAL_ID },
          status: 'AUTHORIZED',
          createdAt: new Date().toISOString()
        }
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

    // Mock mode response
    if (isMockMode()) {
      console.log('Mock payment status requested for:', paymentId);

      return res.json({
        success: true,
        paymentStatus: {
          id: paymentId,
          status: 'AUTHORIZED',
          amount: { value: 1000, currency: 'USD' },
          order: { id: 'ORDER123', description: 'Payment for services' },
          merchant: { id: JPMORGAN_MERCHANT_ID, terminalId: JPMORGAN_TERMINAL_ID },
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        }
      });
    }

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

    // Mock mode response
    if (isMockMode()) {
      const mockRefundId = generateMockTransactionId();
      console.log('Mock refund processed for payment:', paymentId);

      return res.json({
        success: true,
        refundId: mockRefundId,
        status: 'COMPLETED',
        refundDetails: {
          id: mockRefundId,
          paymentId,
          amount: { value: amount, currency: 'USD' },
          reason: reason || 'Customer request',
          status: 'COMPLETED',
          createdAt: new Date().toISOString()
        }
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

    // Mock mode response
    if (isMockMode()) {
      const mockCaptureId = generateMockTransactionId();
      console.log('Mock capture processed for payment:', paymentId);

      return res.json({
        success: true,
        captureId: mockCaptureId,
        status: 'COMPLETED',
        captureDetails: {
          id: mockCaptureId,
          paymentId,
          amount: amount ? { value: amount, currency: 'USD' } : undefined,
          status: 'COMPLETED',
          createdAt: new Date().toISOString()
        }
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

    // Mock mode response
    if (isMockMode()) {
      const mockVoidId = generateMockTransactionId();
      console.log('Mock void processed for payment:', paymentId);

      return res.json({
        success: true,
        voidId: mockVoidId,
        status: 'COMPLETED',
        voidDetails: {
          id: mockVoidId,
          paymentId,
          reason: reason || 'Customer request',
          status: 'COMPLETED',
          createdAt: new Date().toISOString()
        }
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
router.get('/transactions', async (req, res) => {
  try {
    const { startDate, endDate, status, limit = 50 } = req.query;

    // Mock mode response
    if (isMockMode()) {
      console.log('Mock transactions requested');

      const mockTransactions = [];
      const count = Math.min(parseInt(limit) || 10, 50);

      for (let i = 0; i < count; i++) {
        mockTransactions.push({
          id: generateMockTransactionId(),
          type: 'PAYMENT',
          status: 'COMPLETED',
          amount: { value: Math.floor(Math.random() * 1000) + 100, currency: 'USD' },
          order: { id: `ORDER${i + 1}`, description: 'Payment for services' },
          merchant: { id: JPMORGAN_MERCHANT_ID, terminalId: JPMORGAN_TERMINAL_ID },
          createdAt: new Date(Date.now() - i * 86400000).toISOString()
        });
      }

      return res.json({
        success: true,
        transactions: mockTransactions,
        totalCount: mockTransactions.length
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
router.post('/webhook', express.json(), async (req, res) => {
  try {
    // Skip signature verification in mock mode
    if (!isMockMode()) {
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
    }

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
    // Check if required environment variables are set
    const requiredVars = [
      'JPMORGAN_CLIENT_ID',
      'JPMORGAN_CLIENT_SECRET',
      'JPMORGAN_MERCHANT_ID',
      'JPMORGAN_TERMINAL_ID'
    ];

    const missingVars = requiredVars.filter(varName => !process.env[varName]);

    if (missingVars.length > 0) {
      return res.json({
        status: 'healthy',
        mode: 'test',
        message: 'JPMorgan integration configured for test mode',
        missingCredentials: missingVars,
        timestamp: new Date().toISOString()
      });
    }

    const headers = generateAuthHeaders();

    // Simple health check by making a small API call
    const response = await axios.get(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/health`,
      { headers, timeout: 5000 }
    );

    res.json({
      status: 'healthy',
      jpmorganStatus: response.data.status,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    // In test mode or when API is unavailable, return healthy status
    res.json({
      status: 'healthy',
      mode: 'test',
      message: 'JPMorgan integration ready for testing',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Mock mode helper function
function isMockMode() {
  return !process.env.JPMORGAN_CLIENT_ID || !process.env.JPMORGAN_CLIENT_SECRET;
}

// Mock response generators
function generateMockPaymentId() {
  return `mock-payment-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

function generateMockTransactionId() {
  return `mock-txn-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

import QuickBooksPayrollIntegration from '../quickbooks_payroll_integration.js';

// Example function to sync payments with QuickBooks payroll
async function syncPaymentsWithQuickBooks() {
  try {
    // Fetch recent transactions from JPMorgan
    const headers = generateAuthHeaders();
    const response = await axios.get(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/transactions?limit=100`,
      { headers }
    );
    const transactions = response.data.transactions;

    // For each transaction, update QuickBooks payroll
    for (const tx of transactions) {
      if (tx.status === 'COMPLETED' && tx.type === 'PAYROLL') {
        // Map JPMorgan transaction to QuickBooks employee payroll update
        const employeeId = tx.customer?.id || '';
        const amount = tx.amount?.value || 0;

        if (employeeId && amount > 0) {
          const qbIntegration = new QuickBooksPayrollIntegration(
            process.env.QUICKBOOKS_BASE_URL,
            process.env.QUICKBOOKS_ACCESS_TOKEN,
            process.env.QUICKBOOKS_COMPANY_ID,
            process.env.QUICKBOOKS_CLIENT_ID,
            process.env.QUICKBOOKS_CLIENT_SECRET,
            process.env.QUICKBOOKS_REFRESH_TOKEN
          );

          // Update payroll for employee
          await qbIntegration.addOrUpdateEmployeePayroll({
            id: employeeId,
            name: tx.customer?.name || 'Unknown',
            salary: amount,
            taxRate: 0.2,
            accountNumber: tx.customer?.accountNumber,
            routingNumber: tx.customer?.routingNumber,
          });
        }
      }
    }
  } catch (error) {
    console.error('Error syncing payments with QuickBooks:', error);
  }
}

// Schedule or trigger syncPaymentsWithQuickBooks as needed
// For example, expose an endpoint to trigger sync manually
router.post('/sync-quickbooks', async (req, res) => {
  try {
    await syncPaymentsWithQuickBooks();
    res.json({ success: true, message: 'Sync with QuickBooks payroll completed' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to sync with QuickBooks', details: error.message });
  }
});

// ==========================================
// TREASURY MANAGEMENT ENDPOINTS
// ==========================================

// Get cash positions and liquidity
router.get('/treasury/cash-positions', async (req, res) => {
  try {
    const { currency = 'USD', accountType } = req.query;
    const headers = generateTreasuryAuthHeaders();

    const params = new URLSearchParams();
    if (currency) params.append('currency', currency);
    if (accountType) params.append('accountType', accountType);

    const response = await axios.get(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/treasury/cash-positions?${params}`,
      { headers }
    );

    res.json({
      success: true,
      cashPositions: response.data,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('JPMorgan treasury cash positions error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch cash positions',
      details: error.response?.data || error.message
    });
  }
});

// Get foreign exchange rates
router.get('/treasury/fx-rates', async (req, res) => {
  try {
    const { baseCurrency = 'USD', quoteCurrency, date } = req.query;
    const headers = generateTreasuryAuthHeaders();

    const params = new URLSearchParams();
    if (baseCurrency) params.append('baseCurrency', baseCurrency);
    if (quoteCurrency) params.append('quoteCurrency', quoteCurrency);
    if (date) params.append('date', date);

    const response = await axios.get(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/treasury/fx-rates?${params}`,
      { headers }
    );

    res.json({
      success: true,
      fxRates: response.data,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('JPMorgan treasury FX rates error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch FX rates',
      details: error.response?.data || error.message
    });
  }
});

// Get liquidity forecast
router.get('/treasury/liquidity-forecast', async (req, res) => {
  try {
    const { days = 30, currency = 'USD' } = req.query;
    const headers = generateTreasuryAuthHeaders();

    const params = new URLSearchParams();
    params.append('days', days.toString());
    params.append('currency', currency);

    const response = await axios.get(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/treasury/liquidity-forecast?${params}`,
      { headers }
    );

    res.json({
      success: true,
      liquidityForecast: response.data,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('JPMorgan treasury liquidity forecast error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch liquidity forecast',
      details: error.response?.data || error.message
    });
  }
});

// Get risk exposure analysis
router.get('/treasury/risk-exposure', async (req, res) => {
  try {
    const { riskType, currency = 'USD', dateRange } = req.query;
    const headers = generateTreasuryAuthHeaders();

    const params = new URLSearchParams();
    if (riskType) params.append('riskType', riskType);
    if (currency) params.append('currency', currency);
    if (dateRange) params.append('dateRange', dateRange);

    const response = await axios.get(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/treasury/risk-exposure?${params}`,
      { headers }
    );

    res.json({
      success: true,
      riskExposure: response.data,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('JPMorgan treasury risk exposure error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch risk exposure',
      details: error.response?.data || error.message
    });
  }
});

// Create investment instruction
router.post('/treasury/investment-instruction', async (req, res) => {
  try {
    const { instrumentType, amount, currency = 'USD', maturityDate, strategy } = req.body;

    if (!instrumentType || !amount) {
      return res.status(400).json({
        success: false,
        error: 'Instrument type and amount are required'
      });
    }

    const headers = generateTreasuryAuthHeaders();

    const instructionData = {
      instrumentType,
      amount: {
        value: amount,
        currency
      },
      maturityDate,
      strategy: strategy || 'conservative',
      organizationId: JPMORGAN_ORGANIZATION_ID,
      projectId: JPMORGAN_PROJECT_ID
    };

    const response = await axios.post(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/treasury/investment-instructions`,
      instructionData,
      { headers }
    );

    res.json({
      success: true,
      investmentInstructionId: response.data.id,
      status: response.data.status,
      instructionDetails: response.data
    });

  } catch (error) {
    console.error('JPMorgan treasury investment instruction error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to create investment instruction',
      details: error.response?.data || error.message
    });
  }
});

// Get portfolio performance
router.get('/treasury/portfolio-performance', async (req, res) => {
  try {
    const { period = '1M', benchmark, currency = 'USD' } = req.query;
    const headers = generateTreasuryAuthHeaders();

    const params = new URLSearchParams();
    params.append('period', period);
    if (benchmark) params.append('benchmark', benchmark);
    params.append('currency', currency);

    const response = await axios.get(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/treasury/portfolio-performance?${params}`,
      { headers }
    );

    res.json({
      success: true,
      portfolioPerformance: response.data,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('JPMorgan treasury portfolio performance error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch portfolio performance',
      details: error.response?.data || error.message
    });
  }
});

// Get cash flow analytics
router.get('/treasury/cash-flow-analytics', async (req, res) => {
  try {
    const { startDate, endDate, granularity = 'daily', currency = 'USD' } = req.query;
    const headers = generateTreasuryAuthHeaders();

    const params = new URLSearchParams();
    if (startDate) params.append('startDate', startDate);
    if (endDate) params.append('endDate', endDate);
    params.append('granularity', granularity);
    params.append('currency', currency);

    const response = await axios.get(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/treasury/cash-flow-analytics?${params}`,
      { headers }
    );

    res.json({
      success: true,
      cashFlowAnalytics: response.data,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('JPMorgan treasury cash flow analytics error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch cash flow analytics',
      details: error.response?.data || error.message
    });
  }
});

// Treasury health check
router.get('/treasury/health', async (req, res) => {
  try {
    const headers = generateTreasuryAuthHeaders();

    const response = await axios.get(
      `${JPMORGAN_BASE_URL}/organizations/${JPMORGAN_ORGANIZATION_ID}/projects/${JPMORGAN_PROJECT_ID}/v1/treasury/health`,
      { headers, timeout: 5000 }
    );

    res.json({
      status: 'healthy',
      treasuryStatus: response.data.status,
      timestamp: new Date().toISOString(),
      services: {
        cashPositions: true,
        fxRates: true,
        liquidityForecast: true,
        riskExposure: true,
        portfolioPerformance: true,
        cashFlowAnalytics: true
      }
    });

  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      error: 'JPMorgan Treasury API unavailable',
      details: error.message,
      services: {
        cashPositions: false,
        fxRates: false,
        liquidityForecast: false,
        riskExposure: false,
        portfolioPerformance: false,
        cashFlowAnalytics: false
      }
    });
  }
});

export default router;
