import express from 'express';
import plaidService from '../services/plaidService.js';
import { authenticateToken } from '../../config/security.js';
import transferEventsMonitor from '../../services/transferEventsMonitor.js';

const router = express.Router();

// Create link token for account linking
router.post('/create-link-token', authenticateToken, async (req, res) => {
  try {
    const { userId, products } = req.body;

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: 'User ID is required',
      });
    }

    const linkTokenData = await plaidService.createLinkToken(userId, products);

    res.json({
      success: true,
      data: linkTokenData,
    });
  } catch (error) {
    console.error('Error creating link token:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create link token',
      error: error.message,
    });
  }
});

// Exchange public token for access token
router.post('/exchange-public-token', authenticateToken, async (req, res) => {
  try {
    const { publicToken } = req.body;

    if (!publicToken) {
      return res.status(400).json({
        success: false,
        message: 'Public token is required',
      });
    }

    const tokenData = await plaidService.exchangePublicToken(publicToken);

    res.json({
      success: true,
      data: tokenData,
    });
  } catch (error) {
    console.error('Error exchanging public token:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to exchange public token',
      error: error.message,
    });
  }
});

// Get account information
router.get('/accounts/:accessToken', authenticateToken, async (req, res) => {
  try {
    const { accessToken } = req.params;

    const accounts = await plaidService.getAccounts(accessToken);

    res.json({
      success: true,
      data: accounts,
    });
  } catch (error) {
    console.error('Error getting accounts:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get accounts',
      error: error.message,
    });
  }
});

// Get account balances
router.get('/balances/:accessToken', authenticateToken, async (req, res) => {
  try {
    const { accessToken } = req.params;

    const balances = await plaidService.getBalances(accessToken);

    res.json({
      success: true,
      data: balances,
    });
  } catch (error) {
    console.error('Error getting balances:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get balances',
      error: error.message,
    });
  }
});

// Get transactions
router.get('/transactions/:accessToken', authenticateToken, async (req, res) => {
  try {
    const { accessToken } = req.params;
    const { startDate, endDate, count, offset } = req.query;

    if (!startDate || !endDate) {
      return res.status(400).json({
        success: false,
        message: 'Start date and end date are required',
      });
    }

    const transactions = await plaidService.getTransactions(
      accessToken,
      startDate,
      endDate,
      {
        count: Number.parseInt(count) || 100,
        offset: Number.parseInt(offset) || 0,
      }
    );

    res.json({
      success: true,
      data: transactions,
    });
  } catch (error) {
    console.error('Error getting transactions:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get transactions',
      error: error.message,
    });
  }
});

// Get income information
router.get('/income/:accessToken', authenticateToken, async (req, res) => {
  try {
    const { accessToken } = req.params;

    const income = await plaidService.getIncome(accessToken);

    res.json({
      success: true,
      data: income,
    });
  } catch (error) {
    console.error('Error getting income:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get income',
      error: error.message,
    });
  }
});

// Get auth information (account and routing numbers)
router.get('/auth/:accessToken', authenticateToken, async (req, res) => {
  try {
    const { accessToken } = req.params;

    const auth = await plaidService.getAuth(accessToken);

    res.json({
      success: true,
      data: auth,
    });
  } catch (error) {
    console.error('Error getting auth:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get auth',
      error: error.message,
    });
  }
});

// Verify account ownership (proof of funds)
router.post('/verify-ownership/:accessToken/:accountId', authenticateToken, async (req, res) => {
  try {
    const { accessToken, accountId } = req.params;
    const { amounts } = req.body;

    if (!amounts || !Array.isArray(amounts)) {
      return res.status(400).json({
        success: false,
        message: 'Amounts array is required',
      });
    }

    const verification = await plaidService.verifyAccountOwnership(
      accessToken,
      accountId,
      amounts
    );

    res.json({
      success: true,
      data: verification,
    });
  } catch (error) {
    console.error('Error verifying account ownership:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to verify account ownership',
      error: error.message,
    });
  }
});

// Get identity information
router.get('/identity/:accessToken', authenticateToken, async (req, res) => {
  try {
    const { accessToken } = req.params;

    const identity = await plaidService.getIdentity(accessToken);

    res.json({
      success: true,
      data: identity,
    });
  } catch (error) {
    console.error('Error getting identity:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get identity',
      error: error.message,
    });
  }
});

// Remove item (disconnect account)
router.delete('/item/:accessToken', authenticateToken, async (req, res) => {
  try {
    const { accessToken } = req.params;

    const result = await plaidService.removeItem(accessToken);

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error('Error removing item:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to remove item',
      error: error.message,
    });
  }
});

// Get institutions
router.get('/institutions', authenticateToken, async (req, res) => {
  try {
    const { count, offset, country_codes } = req.query;

    const options = {
      count: count ? parseInt(count) : undefined,
      offset: offset ? parseInt(offset) : undefined,
      country_codes: country_codes ? country_codes.split(',') : undefined,
    };

    const institutions = await plaidService.getInstitutions(options);

    res.json({
      success: true,
      data: institutions,
    });
  } catch (error) {
    console.error('Error getting institutions:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get institutions',
      error: error.message,
    });
  }
});

// Get webhook verification key
router.get('/webhook-verification-key', authenticateToken, async (req, res) => {
  try {
    const verificationKey = await plaidService.getWebhookVerificationKey();

    res.json({
      success: true,
      data: {
        key: verificationKey,
      },
    });
  } catch (error) {
    console.error('Error getting webhook verification key:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get webhook verification key',
      error: error.message,
    });
  }
});

// Webhook endpoint
router.post(
  '/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    try {
      const rawBody = req.body;
      const signature = req.headers['plaid-webhook-signature'];

      // Get webhook verification key dynamically (fallback to env var)
      let verificationKey = process.env.PLAID_WEBHOOK_VERIFICATION_KEY;
      if (!verificationKey) {
        try {
          verificationKey = await plaidService.getWebhookVerificationKey();
        } catch (error) {
          console.error('Failed to retrieve webhook verification key:', error);
          return res.status(500).json({
            success: false,
            message: 'Webhook verification key unavailable',
          });
        }
      }

      // Verify webhook signature in production
      if (process.env.NODE_ENV === 'production' && verificationKey) {
        const isValidSignature = await plaidService.verifyWebhookSignature(
          rawBody,
          signature,
          verificationKey
        );

        if (!isValidSignature) {
          console.warn('Invalid webhook signature received');
          return res.status(401).json({
            success: false,
            message: 'Invalid webhook signature',
          });
        }
      }

      const event = JSON.parse(rawBody);

      // Validate webhook event structure
      if (!event.webhook_type || !event.webhook_code) {
        console.warn('Invalid webhook event structure:', event);
        return res.status(400).json({
          success: false,
          message: 'Invalid webhook event structure',
        });
      }

      const result = await plaidService.handleWebhook(event);

      res.json(result);
    } catch (error) {
      console.error('Error handling webhook:', error);
      res.status(500).json({
        success: false,
        message: 'Webhook processing failed',
        error: error.message,
      });
    }
  }
);

// Initiate SMS microdeposits for account verification
router.post('/microdeposits/initiate/:accessToken/:accountId', authenticateToken, async (req, res) => {
  try {
    const { accessToken, accountId } = req.params;

    const result = await plaidService.initiateMicrodeposits(accessToken, accountId);

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error('Error initiating microdeposits:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to initiate microdeposits',
      error: error.message,
    });
  }
});

// Verify SMS microdeposits with deposit amounts
router.post('/microdeposits/verify/:accessToken/:accountId', authenticateToken, async (req, res) => {
  try {
    const { accessToken, accountId } = req.params;
    const { amounts } = req.body;

    if (!amounts || !Array.isArray(amounts)) {
      return res.status(400).json({
        success: false,
        message: 'Amounts array is required',
      });
    }

    const result = await plaidService.verifyMicrodeposits(accessToken, accountId, amounts);

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error('Error verifying microdeposits:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to verify microdeposits',
      error: error.message,
    });
  }
});

// Get microdeposits verification status
router.get('/microdeposits/status/:accessToken/:accountId', authenticateToken, async (req, res) => {
  try {
    const { accessToken, accountId } = req.params;

    const status = await plaidService.getMicrodepositsStatus(accessToken, accountId);

    res.json({
      success: true,
      data: status,
    });
  } catch (error) {
    console.error('Error getting microdeposits status:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get microdeposits status',
      error: error.message,
    });
  }
});

// Get transfer events (transfer event sync)
router.get('/transfer-events/:accessToken', authenticateToken, async (req, res) => {
  const { accessToken } = req.params;
  try {
    const { count, offset, eventTypes, transferId, accountId, transferType, originationAccountId, startDate, endDate } = req.query;

    const options = {
      count: count ? parseInt(count) : 25,
      offset: offset ? parseInt(offset) : 0,
      eventTypes: eventTypes ? eventTypes.split(',') : undefined,
      transferId,
      accountId,
      transferType,
      originationAccountId,
      startDate,
      endDate,
    };

    // Remove undefined values
    Object.keys(options).forEach(key => {
      if (options[key] === undefined) {
        delete options[key];
      }
    });

    const tracker = transferEventsMonitor.recordRequest(accessToken, options);

    const transferEvents = await plaidService.getBankTransferEvents(accessToken, options);

    tracker.success(transferEvents.length);

    res.json({
      success: true,
      data: transferEvents,
    });
  } catch (error) {
    transferEventsMonitor.recordRequest(accessToken, req.query).error(error);
    console.error('Error getting transfer events:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get transfer events',
      error: error.message,
    });
  }
});

// List transfer sweeps
router.get('/transfer-sweeps', authenticateToken, async (req, res) => {
  try {
    const { startDate, endDate, count, offset } = req.query;

    if (!startDate || !endDate) {
      return res.status(400).json({
        success: false,
        message: 'Start date and end date are required',
      });
    }

    const sweeps = await plaidService.listTransferSweeps(
      startDate,
      endDate,
      count ? parseInt(count) : 14,
      offset ? parseInt(offset) : 0
    );

    res.json({
      success: true,
      data: sweeps,
    });
  } catch (error) {
    console.error('Error listing transfer sweeps:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to list transfer sweeps',
      error: error.message,
    });
  }
});

// Create a transfer
router.post('/transfers', authenticateToken, async (req, res) => {
  try {
    const { accessToken, accountId, amount, description, achClass, type, network, idempotencyKey, metadata, originatorClientId, user } = req.body;

    if (!accessToken || !accountId || !amount || !description) {
      return res.status(400).json({
        success: false,
        message: 'Access token, account ID, amount, and description are required',
      });
    }

    const transferData = {
      accountId,
      amount,
      description,
      achClass,
      type,
      network,
      idempotencyKey,
      metadata,
      originatorClientId,
      user,
    };

    const transfer = await plaidService.createTransfer(accessToken, transferData);

    res.json({
      success: true,
      data: transfer,
    });
  } catch (error) {
    console.error('Error creating transfer:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create transfer',
      error: error.message,
    });
  }
});

// List transfers
router.get('/transfers', authenticateToken, async (req, res) => {
  try {
    const { accessToken, startDate, endDate, count, offset } = req.query;

    if (!accessToken) {
      return res.status(400).json({
        success: false,
        message: 'Access token is required',
      });
    }

    const options = {
      startDate,
      endDate,
      count: count ? parseInt(count) : 25,
      offset: offset ? parseInt(offset) : 0,
    };

    const transfers = await plaidService.listTransfers(accessToken, options);

    res.json({
      success: true,
      data: transfers,
    });
  } catch (error) {
    console.error('Error listing transfers:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to list transfers',
      error: error.message,
    });
  }
});

// Get transfer details
router.get('/transfers/:transferId', authenticateToken, async (req, res) => {
  try {
    const { transferId } = req.params;

    const transfer = await plaidService.getTransfer(transferId);

    res.json({
      success: true,
      data: transfer,
    });
  } catch (error) {
    console.error('Error getting transfer:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get transfer',
      error: error.message,
    });
  }
});

// Cancel a transfer
router.delete('/transfers/:transferId', authenticateToken, async (req, res) => {
  try {
    const { transferId } = req.params;

    const result = await plaidService.cancelTransfer(transferId);

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error('Error canceling transfer:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to cancel transfer',
      error: error.message,
    });
  }
});

// Create transfer intent
router.post('/transfer-intents', authenticateToken, async (req, res) => {
  try {
    const { accessToken, accountId, amount, description, achClass, mode, network, idempotencyKey, metadata, user } = req.body;

    if (!accessToken || !accountId || !amount || !description) {
      return res.status(400).json({
        success: false,
        message: 'Access token, account ID, amount, and description are required',
      });
    }

    const intentData = {
      accountId,
      amount,
      description,
      achClass,
      mode,
      network,
      idempotencyKey,
      metadata,
      user,
    };

    const intent = await plaidService.createTransferIntent(accessToken, intentData);

    res.json({
      success: true,
      data: intent,
    });
  } catch (error) {
    console.error('Error creating transfer intent:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create transfer intent',
      error: error.message,
    });
  }
});

// Get transfer intent
router.get('/transfer-intents/:intentId', authenticateToken, async (req, res) => {
  try {
    const { intentId } = req.params;

    const intent = await plaidService.getTransferIntent(intentId);

    res.json({
      success: true,
      data: intent,
    });
  } catch (error) {
    console.error('Error getting transfer intent:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get transfer intent',
      error: error.message,
    });
  }
});

// List transfer intents
router.get('/transfer-intents', authenticateToken, async (req, res) => {
  try {
    const { accessToken, transferId, accountId, count, offset } = req.query;

    if (!accessToken) {
      return res.status(400).json({
        success: false,
        message: 'Access token is required',
      });
    }

    const options = {
      transferId,
      accountId,
      count: count ? parseInt(count) : 25,
      offset: offset ? parseInt(offset) : 0,
    };

    const intents = await plaidService.listTransferIntents(accessToken, options);

    res.json({
      success: true,
      data: intents,
    });
  } catch (error) {
    console.error('Error listing transfer intents:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to list transfer intents',
      error: error.message,
    });
  }
});

export default router;
