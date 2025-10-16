import express from 'express';
import plaidService from '../services/plaidService.js';

const router = express.Router();

// Create link token for account linking
router.post('/create-link-token', async (req, res) => {
  try {
    const { userId, products } = req.body;

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: 'User ID is required'
      });
    }

    const linkTokenData = await plaidService.createLinkToken(userId, products);

    res.json({
      success: true,
      data: linkTokenData
    });
  } catch (error) {
    console.error('Error creating link token:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create link token',
      error: error.message
    });
  }
});

// Exchange public token for access token
router.post('/exchange-public-token', async (req, res) => {
  try {
    const { publicToken } = req.body;

    if (!publicToken) {
      return res.status(400).json({
        success: false,
        message: 'Public token is required'
      });
    }

    const tokenData = await plaidService.exchangePublicToken(publicToken);

    res.json({
      success: true,
      data: tokenData
    });
  } catch (error) {
    console.error('Error exchanging public token:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to exchange public token',
      error: error.message
    });
  }
});

// Get account information
router.get('/accounts/:accessToken', async (req, res) => {
  try {
    const { accessToken } = req.params;

    const accounts = await plaidService.getAccounts(accessToken);

    res.json({
      success: true,
      data: accounts
    });
  } catch (error) {
    console.error('Error getting accounts:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get accounts',
      error: error.message
    });
  }
});

// Get account balances
router.get('/balances/:accessToken', async (req, res) => {
  try {
    const { accessToken } = req.params;

    const balances = await plaidService.getBalances(accessToken);

    res.json({
      success: true,
      data: balances
    });
  } catch (error) {
    console.error('Error getting balances:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get balances',
      error: error.message
    });
  }
});

// Get transactions
router.get('/transactions/:accessToken', async (req, res) => {
  try {
    const { accessToken } = req.params;
    const { startDate, endDate, count, offset } = req.query;

    if (!startDate || !endDate) {
      return res.status(400).json({
        success: false,
        message: 'Start date and end date are required'
      });
    }

    const transactions = await plaidService.getTransactions(accessToken, startDate, endDate, {
      count: Number.parseInt(count) || 100,
      offset: Number.parseInt(offset) || 0
    });

    res.json({
      success: true,
      data: transactions
    });
  } catch (error) {
    console.error('Error getting transactions:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get transactions',
      error: error.message
    });
  }
});

// Get income information
router.get('/income/:accessToken', async (req, res) => {
  try {
    const { accessToken } = req.params;

    const income = await plaidService.getIncome(accessToken);

    res.json({
      success: true,
      data: income
    });
  } catch (error) {
    console.error('Error getting income:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get income',
      error: error.message
    });
  }
});

// Verify account ownership (proof of funds)
router.post('/verify-ownership/:accessToken/:accountId', async (req, res) => {
  try {
    const { accessToken, accountId } = req.params;
    const { amounts } = req.body;

    if (!amounts || !Array.isArray(amounts)) {
      return res.status(400).json({
        success: false,
        message: 'Amounts array is required'
      });
    }

    const verification = await plaidService.verifyAccountOwnership(accessToken, accountId, amounts);

    res.json({
      success: true,
      data: verification
    });
  } catch (error) {
    console.error('Error verifying account ownership:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to verify account ownership',
      error: error.message
    });
  }
});

// Get identity information
router.get('/identity/:accessToken', async (req, res) => {
  try {
    const { accessToken } = req.params;

    const identity = await plaidService.getIdentity(accessToken);

    res.json({
      success: true,
      data: identity
    });
  } catch (error) {
    console.error('Error getting identity:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get identity',
      error: error.message
    });
  }
});

// Remove item (disconnect account)
router.delete('/item/:accessToken', async (req, res) => {
  try {
    const { accessToken } = req.params;

    const result = await plaidService.removeItem(accessToken);

    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    console.error('Error removing item:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to remove item',
      error: error.message
    });
  }
});

// Webhook endpoint
router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    // Verify webhook signature (in production, implement proper verification)
    const event = JSON.parse(req.body);

    const result = await plaidService.handleWebhook(event);

    res.json(result);
  } catch (error) {
    console.error('Error handling webhook:', error);
    res.status(500).json({
      success: false,
      message: 'Webhook processing failed',
      error: error.message
    });
  }
});

export default router;
