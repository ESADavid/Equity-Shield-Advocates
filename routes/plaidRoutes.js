import express from 'express';
import plaidService from '../services/plaidService.js';
import { authenticateToken } from '../config/security.js';
import transferEventsMonitor from '../services/transferEventsMonitor.js';
import logger from '../config/logger.js';
import Item from '../models/Item.js';

const router = express.Router();

// Create link token for account linking
router.post('/create-link-token', authenticateToken, async (req, res) => {
  try {
    const { userId, products, oauth, redirectUri, countryCodes, language, user, webhook, linkCustomizationName, institutionId, accountFilters, paymentInitiation, mode } = req.body;

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: 'User ID is required',
      });
    }

    const options = {};
    if (oauth !== undefined) options.oauth = oauth;
    if (redirectUri) options.redirectUri = redirectUri;
    if (countryCodes) options.countryCodes = countryCodes;
    if (language) options.language = language;
    if (user) options.user = user;
    if (webhook) options.webhook = webhook;
    if (linkCustomizationName) options.linkCustomizationName = linkCustomizationName;
    if (institutionId) options.institutionId = institutionId;
    if (accountFilters) options.accountFilters = accountFilters;
    if (paymentInitiation) options.paymentInitiation = paymentInitiation;
    if (mode) options.mode = mode;

    const linkTokenData = await plaidService.createLinkToken(userId, products, options);

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

// Get investments auth information (for ACATS transfers)
router.get('/investments/auth/:accessToken', authenticateToken, async (req, res) => {
  try {
    const { accessToken } = req.params;

    const investmentsAuth = await plaidService.getInvestmentsAuth(accessToken);

    res.json({
      success: true,
      data: investmentsAuth,
    });
  } catch (error) {
    console.error('Error getting investments auth:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get investments auth',
      error: error.message,
    });
  }
});

// Get investments holdings and transactions
router.get('/investments/:accessToken', authenticateToken, async (req, res) => {
  try {
    const { accessToken } = req.params;
    const { count, offset } = req.query;

    const options = {
      count: count ? parseInt(count) : undefined,
      offset: offset ? parseInt(offset) : undefined,
    };

    const investments = await plaidService.getInvestments(accessToken, options);

    res.json({
      success: true,
      data: investments,
    });
  } catch (error) {
    console.error('Error getting investments:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get investments',
      error: error.message,
    });
  }
});

// Get liabilities information (debt details)
router.get('/liabilities/:accessToken', authenticateToken, async (req, res) => {
  try {
    const { accessToken } = req.params;

    const liabilities = await plaidService.getLiabilities(accessToken);

    res.json({
      success: true,
      data: liabilities,
    });
  } catch (error) {
    console.error('Error getting liabilities:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get liabilities',
      error: error.message,
    });
  }
});

// Enrich transactions data
router.post('/enrich/transactions', authenticateToken, async (req, res) => {
  try {
    const { transactions, account_type, country_code } = req.body;

    if (!transactions || !Array.isArray(transactions)) {
      return res.status(400).json({
        success: false,
        message: 'Transactions array is required',
      });
    }

    const options = {};
    if (account_type) options.account_type = account_type;
    if (country_code) options.country_code = country_code;

    const enrichedData = await plaidService.enrichTransactions(transactions, options);

    res.json({
      success: true,
      data: enrichedData,
    });
  } catch (error) {
    console.error('Error enriching transactions:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to enrich transactions',
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

// Match user identity information against institution data
router.post('/identity/match/:accessToken', authenticateToken, async (req, res) => {
  try {
    const { accessToken } = req.params;
    const { legal_name, phone_number, email_address, address } = req.body;

    // Validate required user identity data
    if (!legal_name && !phone_number && !email_address && !address) {
      return res.status(400).json({
        success: false,
        message: 'At least one identity field (legal_name, phone_number, email_address, or address) is required',
      });
    }

    // Validate address structure if provided
    if (address && typeof address !== 'object') {
      return res.status(400).json({
        success: false,
        message: 'Address must be an object with street, city, region, postal_code, and country fields',
      });
    }

    const userIdentity = {};
    if (legal_name) userIdentity.legal_name = legal_name;
    if (phone_number) userIdentity.phone_number = phone_number;
    if (email_address) userIdentity.email_address = email_address;
    if (address) userIdentity.address = address;

    const matchResult = await plaidService.identityMatch(accessToken, userIdentity);

    res.json({
      success: true,
      data: matchResult,
    });
  } catch (error) {
    console.error('Error matching identity:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to match identity',
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

// OAuth redirect handler
router.get('/oauth/redirect', async (req, res) => {
  try {
    const { oauth_state_id, public_token } = req.query;

    if (!public_token) {
      return res.status(400).json({
        success: false,
        message: 'Public token is required',
      });
    }

    // Exchange public token for access token (same as regular flow)
    const tokenData = await plaidService.exchangePublicToken(public_token);

    // For OAuth, you might want to store the oauth_state_id for verification
    // and redirect to your frontend with the token data

    // Redirect to frontend with success
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    const redirectUrl = `${frontendUrl}/plaid/oauth/success?access_token=${tokenData.access_token}&item_id=${tokenData.item_id}`;

    res.redirect(redirectUrl);
  } catch (error) {
    console.error('Error handling OAuth redirect:', error);

    // Redirect to frontend with error
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    const redirectUrl = `${frontendUrl}/plaid/oauth/error?error=${encodeURIComponent(error.message)}`;

    res.redirect(redirectUrl);
  }
});

// Auth-specific routes

// Get items for user
router.get('/items', authenticateToken, async (req, res) => {
  try {
    const userId = req.user._id;
    const tenantId = req.user.tenantId;

    const items = await Item.findByUser(userId, tenantId);

    const publicItems = items.map(item => item.toPublicJSON());

    res.json({
      success: true,
      data: publicItems,
    });
  } catch (error) {
    console.error('Error getting items:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get items',
      error: error.message,
    });
  }
});

// Get item by ID
router.get('/items/:itemId', authenticateToken, async (req, res) => {
  try {
    const { itemId } = req.params;
    const userId = req.user._id;
    const tenantId = req.user.tenantId;

    const item = await Item.findOne({ itemId, userId, tenantId });

    if (!item) {
      return res.status(404).json({
        success: false,
        message: 'Item not found',
      });
    }

    res.json({
      success: true,
      data: item.toPublicJSON(),
    });
  } catch (error) {
    console.error('Error getting item:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get item',
      error: error.message,
    });
  }
});

// Update consent expiration
router.put('/items/:itemId/consent', authenticateToken, async (req, res) => {
  try {
    const { itemId } = req.params;
    const { consentExpiration } = req.body;
    const userId = req.user._id;
    const tenantId = req.user.tenantId;

    if (!consentExpiration) {
      return res.status(400).json({
        success: false,
        message: 'Consent expiration date is required',
      });
    }

    const item = await Item.findOne({ itemId, userId, tenantId });

    if (!item) {
      return res.status(404).json({
        success: false,
        message: 'Item not found',
      });
    }

    await item.updateConsentExpiration(new Date(consentExpiration));

    res.json({
      success: true,
      data: item.toPublicJSON(),
    });
  } catch (error) {
    console.error('Error updating consent:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update consent',
      error: error.message,
    });
  }
});

// Update TAN (Tokenized Account Number)
router.put('/items/:itemId/tan', authenticateToken, async (req, res) => {
  try {
    const { itemId } = req.params;
    const { tan, tanExpiration } = req.body;
    const userId = req.user._id;
    const tenantId = req.user.tenantId;

    if (!tan || !tanExpiration) {
      return res.status(400).json({
        success: false,
        message: 'TAN and expiration date are required',
      });
    }

    const item = await Item.findOne({ itemId, userId, tenantId });

    if (!item) {
      return res.status(404).json({
        success: false,
        message: 'Item not found',
      });
    }

    await item.updateTan(tan, new Date(tanExpiration));

    res.json({
      success: true,
      data: item.toPublicJSON(),
    });
  } catch (error) {
    console.error('Error updating TAN:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update TAN',
      error: error.message,
    });
  }
});

// Get items needing consent renewal
router.get('/items/consent/renewal-needed', authenticateToken, async (req, res) => {
  try {
    const tenantId = req.user.tenantId;
    const { daysAhead = 7 } = req.query;

    const items = await Item.findItemsNeedingConsentRenewal(tenantId, parseInt(daysAhead));

    const publicItems = items.map(item => item.toPublicJSON());

    res.json({
      success: true,
      data: publicItems,
    });
  } catch (error) {
    console.error('Error getting items needing consent renewal:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get items needing consent renewal',
      error: error.message,
    });
  }
});

// Get items with expired TAN
router.get('/items/tan/expired', authenticateToken, async (req, res) => {
  try {
    const tenantId = req.user.tenantId;

    const items = await Item.findItemsWithExpiredTan(tenantId);

    const publicItems = items.map(item => item.toPublicJSON());

    res.json({
      success: true,
      data: publicItems,
    });
  } catch (error) {
    console.error('Error getting items with expired TAN:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get items with expired TAN',
      error: error.message,
    });
  }
});

// Layer Integration Routes

// Create Layer session token
router.post('/layer/session-token', authenticateToken, async (req, res) => {
  try {
    const { templateId, userId, clientName, webhook, linkCustomizationName } = req.body;

    if (!templateId || !userId) {
      return res.status(400).json({
        success: false,
        message: 'Template ID and user ID are required',
      });
    }

    const options = {};
    if (clientName) options.clientName = clientName;
    if (webhook) options.webhook = webhook;
    if (linkCustomizationName) options.linkCustomizationName = linkCustomizationName;

    const sessionTokenData = await plaidService.createSessionToken(templateId, userId, options);

    res.json({
      success: true,
      data: sessionTokenData,
    });
  } catch (error) {
    console.error('Error creating Layer session token:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create Layer session token',
      error: error.message,
    });
  }
});

// Get Layer user account session data
router.get('/layer/user-session/:sessionId', authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.params;

    const sessionData = await plaidService.getUserAccountSession(sessionId);

    res.json({
      success: true,
      data: sessionData,
    });
  } catch (error) {
    console.error('Error getting Layer user session:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get Layer user session',
      error: error.message,
    });
  }
});

export default router;
