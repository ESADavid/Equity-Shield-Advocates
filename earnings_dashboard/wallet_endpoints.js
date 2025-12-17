// Additional Wallet Management Endpoints for JPMorgan Integration
import express from 'express';
import axios from 'axios';
import crypto from 'node:crypto';
const router = express.Router();

// JPMorgan Payments API Configuration
const JPMORGAN_BASE_URL = process.env.JPMORGAN_BASE_URL || 'https://api.payments.jpmorgan.com';
const JPMORGAN_ORGANIZATION_ID = process.env.JPMORGAN_ORGANIZATION_ID || 'D3R56WRGSR3R';
const JPMORGAN_PROJECT_ID = process.env.JPMORGAN_PROJECT_ID || 'DK2MQSR1FS7V';
const JPMORGAN_CLIENT_ID = process.env.JPMORGAN_CLIENT_ID;
const JPMORGAN_CLIENT_SECRET = process.env.JPMORGAN_CLIENT_SECRET;
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
    'Timestamp': timestamp.toString(),
    'Nonce': nonce,
    'Signature': signature,
    'Merchant-Id': JPMORGAN_MERCHANT_ID,
    'Terminal-Id': JPMORGAN_TERMINAL_ID
  };
}

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
      cardNumber: cardNumber.replace(/\s/g, ''), // Remove spaces
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
      cardNumber: cardNumber.replace(/\s/g, ''), // Remove spaces
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

export default router;
