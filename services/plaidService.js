import { Configuration, PlaidApi, PlaidEnvironments } from 'plaid';
import crypto from 'crypto';
import logger from '../config/logger.js';
import plaidSignalService from './plaidSignalService.js';

// Retry configuration
const RETRY_CONFIG = {
  maxRetries: 3,
  baseDelay: 1000, // 1 second
  maxDelay: 10000, // 10 seconds
  backoffMultiplier: 2,
};

// Metrics collection for monitoring
const plaidMetrics = {
  apiCalls: 0,
  successfulCalls: 0,
  failedCalls: 0,
  retryAttempts: 0,
  averageResponseTime: 0,
  errorsByType: {},
  lastErrorTime: null,
  totalResponseTime: 0,
};

// Utility function for retry with exponential backoff
async function retryWithBackoff(operation, operationName, config = RETRY_CONFIG) {
  let lastError;
  const startTime = Date.now();

  for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
    try {
      const result = await operation();
      const duration = Date.now() - startTime;

      // Update metrics
      plaidMetrics.apiCalls++;
      plaidMetrics.successfulCalls++;
      plaidMetrics.totalResponseTime += duration;
      plaidMetrics.averageResponseTime = plaidMetrics.totalResponseTime / plaidMetrics.apiCalls;

      return result;
    } catch (error) {
      lastError = error;
      const duration = Date.now() - startTime;

      // Update metrics
      plaidMetrics.apiCalls++;
      plaidMetrics.failedCalls++;
      plaidMetrics.totalResponseTime += duration;
      plaidMetrics.averageResponseTime = plaidMetrics.totalResponseTime / plaidMetrics.apiCalls;
      plaidMetrics.lastErrorTime = Date.now();

      // Track error types
      const errorType = error.response?.status || error.code || 'unknown';
      plaidMetrics.errorsByType[errorType] = (plaidMetrics.errorsByType[errorType] || 0) + 1;

      // Don't retry on authentication errors or client errors (4xx)
      if (error.response && error.response.status >= 400 && error.response.status < 500) {
        logger.warn(`${operationName} failed with client error (no retry):`, {
          status: error.response.status,
          message: error.message,
          attempt: attempt + 1,
          duration,
        });
        throw error;
      }

      // Don't retry on the last attempt
      if (attempt === config.maxRetries) {
        logger.error(`${operationName} failed after ${config.maxRetries + 1} attempts:`, {
          error: error.message,
          attempts: config.maxRetries + 1,
          totalDuration: duration,
        });
        throw error;
      }

      // Calculate delay with exponential backoff
      const delay = Math.min(
        config.baseDelay * Math.pow(config.backoffMultiplier, attempt),
        config.maxDelay
      );

      plaidMetrics.retryAttempts++;

      logger.warn(`${operationName} failed, retrying in ${delay}ms (attempt ${attempt + 1}/${config.maxRetries + 1}):`, {
        error: error.message,
        delay,
        duration,
      });

      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  throw lastError;
}

// Credential validation function
function validatePlaidCredentials() {
  const clientId = process.env.PLAID_CLIENT_ID;
  const secret = process.env.PLAID_SECRET;
  const env = process.env.PLAID_ENV;

  const errors = [];

  if (!clientId) {
    errors.push('PLAID_CLIENT_ID environment variable is required');
  } else if (typeof clientId !== 'string' || clientId.length < 20) {
    errors.push('PLAID_CLIENT_ID appears to be invalid (too short)');
  }

  if (!secret) {
    errors.push('PLAID_SECRET environment variable is required');
  } else if (typeof secret !== 'string' || secret.length < 20) {
    errors.push('PLAID_SECRET appears to be invalid (too short)');
  }

  if (!env) {
    errors.push('PLAID_ENV environment variable is required');
  } else if (!['sandbox', 'development', 'production'].includes(env)) {
    errors.push('PLAID_ENV must be one of: sandbox, development, production');
  }

  if (errors.length > 0) {
    const errorMessage = `Plaid credential validation failed: ${errors.join(', ')}`;
    logger.error(errorMessage);
    throw new Error(errorMessage);
  }

  logger.info('Plaid credentials validated successfully');
  return { clientId, secret, env };
}

// Plaid configuration
const baseOptions = {};
if (process.env.PLAID_CLIENT_ID && process.env.PLAID_SECRET) {
  baseOptions.headers = {
    'PLAID-CLIENT-ID': process.env.PLAID_CLIENT_ID,
    'PLAID-SECRET': process.env.PLAID_SECRET,
  };
}

const configuration = new Configuration({
  basePath: PlaidEnvironments[process.env.PLAID_ENV || 'sandbox'],
  baseOptions,
});

const plaidClient = new PlaidApi(configuration);

class PlaidService {
  // Create link token for account linking
  async createLinkToken(userId, products = ['auth', 'transactions', 'identity'], options = {}) {
    // Validate credentials on first call
    if (!this.credentialsValidated) {
      validatePlaidCredentials();
      this.credentialsValidated = true;
    }

    return retryWithBackoff(async () => {
      const request = {
        user: {
          client_user_id: userId.toString(),
          ...(options.user && { ...options.user }), // Spread user object if provided
        },
        client_name: 'Oscar Broome Revenue System',
        products: products,
        country_codes: options.countryCodes || ['US'],
        language: options.language || 'en',
      };

      // Add OAuth configuration if enabled
      if (options.oauth) {
        request.oauth = options.oauth;
      }

      // Add redirect URI for OAuth flows
      if (options.redirectUri) {
        request.redirect_uri = options.redirectUri;
      }

      // Add webhook - use provided webhook or default to BASE_URL
      if (options.webhook) {
        request.webhook = options.webhook;
      } else if (process.env.BASE_URL) {
        request.webhook = `${process.env.BASE_URL}/api/plaid/webhook`;
      }

      // Add link customization name
      if (options.linkCustomizationName) {
        request.link_customization_name = options.linkCustomizationName;
      }

      // Add institution ID for pre-selection
      if (options.institutionId) {
        request.institution_id = options.institutionId;
      }

      // Add account filters
      if (options.accountFilters) {
        request.account_filters = options.accountFilters;
      }

      // Add payment initiation
      if (options.paymentInitiation) {
        request.payment_initiation = options.paymentInitiation;
      }

      // Add mode
      if (options.mode) {
        request.mode = options.mode;
      }

      const response = await plaidClient.linkTokenCreate(request);
      return response.data;
    }, 'createLinkToken');
  }

  // Exchange public token for access token
  async exchangePublicToken(publicToken) {
    return retryWithBackoff(async () => {
      const response = await plaidClient.itemPublicTokenExchange({
        public_token: publicToken,
      });

      return {
        access_token: response.data.access_token,
        item_id: response.data.item_id,
      };
    }, 'exchangePublicToken');
  }

  // Get account information
  async getAccounts(accessToken) {
    return retryWithBackoff(async () => {
      const response = await plaidClient.accountsGet({
        access_token: accessToken,
      });

      return response.data.accounts;
    }, 'getAccounts');
  }

  // Get account balances
  async getBalances(accessToken) {
    return retryWithBackoff(async () => {
      const response = await plaidClient.accountsBalanceGet({
        access_token: accessToken,
      });

      return response.data.accounts;
    }, 'getBalances');
  }

  // Get transactions
  async getTransactions(accessToken, startDate, endDate, options = {}) {
    return retryWithBackoff(async () => {
      const request = {
        access_token: accessToken,
        start_date: startDate,
        end_date: endDate,
        options: options,
      };

      const response = await plaidClient.transactionsGet(request);
      return response.data.transactions;
    }, 'getTransactions');
  }

  // Sync transfer events
  async syncTransferEvents(afterId, count) {
    try {
      const request = {
        after_id: afterId,
        count: count,
      };

      const response = await plaidClient.transferEventSync(request);
      return response.data;
    } catch (error) {
      logger.error('Error syncing transfer events:', error);
      throw error;
    }
  }

  // Get transfer sweep
  async getTransferSweep(sweepId) {
    try {
      const request = {
        sweep_id: sweepId,
      };

      const response = await plaidClient.transferSweepGet(request);
      return response.data;
    } catch (error) {
      logger.error('Error getting transfer sweep:', error);
      throw error;
    }
  }

  // List transfer sweeps
  async listTransferSweeps(startDate, endDate, count = 14, offset = 0) {
    try {
      const request = {
        start_date: startDate,
        end_date: endDate,
        count: count,
        offset: offset,
      };

      const response = await plaidClient.transferSweepList(request);
      return response.data;
    } catch (error) {
      logger.error('Error listing transfer sweeps:', error);
      throw error;
    }
  }

  // Create a transfer with real-time balance check via Signal
  async createTransfer(accessToken, transferData) {
    try {
      // First, evaluate the transaction using Plaid Signal (default ruleset includes real-time balance check)
      const signalEvaluation = await plaidSignalService.evaluateTransaction(accessToken, {
        client_transaction_id: transferData.idempotencyKey || crypto.randomUUID(),
        amount: transferData.amount,
        merchant_name: transferData.description || 'Transfer',
        iso_currency_code: 'USD',
        transaction_type: 'debit',
        transaction_initiation_date: new Date().toISOString(),
        user: transferData.user || {},
      });

      // Check if any rules were triggered that would block the transfer
      const triggeredRules = signalEvaluation.signals?.filter(signal => signal.triggered) || [];
      const blockingRules = triggeredRules.filter(signal => signal.rule?.outcome === 'block' || signal.rule?.outcome === 'review');

      if (blockingRules.length > 0) {
        logger.warn('Transfer blocked by Plaid Signal rules:', {
          transferData,
          triggeredRules: blockingRules,
        });
        throw new Error(`Transfer blocked by fraud detection rules: ${blockingRules.map(r => r.rule?.name).join(', ')}`);
      }

      // Log successful signal evaluation
      logger.info('Signal evaluation passed for transfer:', {
        amount: transferData.amount,
        triggeredRulesCount: triggeredRules.length,
        scores: signalEvaluation.scores,
      });

      const request = {
        access_token: accessToken,
        account_id: transferData.accountId,
        amount: transferData.amount,
        description: transferData.description,
        ach_class: transferData.achClass || 'ppd', // ppd, ccd, tel
        type: transferData.type || 'debit', // debit or credit
        network: transferData.network || 'ach',
        idempotency_key: transferData.idempotencyKey || crypto.randomUUID(),
        metadata: transferData.metadata || {},
      };

      // Add optional fields
      if (transferData.originatorClientId) {
        request.originator_client_id = transferData.originatorClientId;
      }

      if (transferData.user) {
        request.user = transferData.user;
      }

      const response = await plaidClient.transferCreate(request);
      return response.data;
    } catch (error) {
      logger.error('Error creating transfer:', error);
      throw error;
    }
  }

  // List transfers
  async listTransfers(accessToken, options = {}) {
    try {
      const request = {
        access_token: accessToken,
        start_date: options.startDate,
        end_date: options.endDate,
        count: options.count || 25,
        offset: options.offset || 0,
      };

      // Remove undefined values
      Object.keys(request).forEach(key => {
        if (request[key] === undefined) {
          delete request[key];
        }
      });

      const response = await plaidClient.transferList(request);
      return response.data;
    } catch (error) {
      logger.error('Error listing transfers:', error);
      throw error;
    }
  }

  // Get transfer details
  async getTransfer(transferId) {
    try {
      const response = await plaidClient.transferGet({
        transfer_id: transferId,
      });

      return response.data;
    } catch (error) {
      logger.error('Error getting transfer:', error);
      throw error;
    }
  }

  // Cancel a transfer
  async cancelTransfer(transferId) {
    try {
      const response = await plaidClient.transferCancel({
        transfer_id: transferId,
      });

      return response.data;
    } catch (error) {
      logger.error('Error canceling transfer:', error);
      throw error;
    }
  }

  // Create transfer intent (for authorization)
  async createTransferIntent(accessToken, intentData) {
    try {
      const request = {
        access_token: accessToken,
        account_id: intentData.accountId,
        amount: intentData.amount,
        description: intentData.description,
        ach_class: intentData.achClass || 'ppd',
        mode: intentData.mode || 'payment', // payment or disbursement
        network: intentData.network || 'ach',
        idempotency_key: intentData.idempotencyKey || crypto.randomUUID(),
        metadata: intentData.metadata || {},
      };

      // Add optional fields
      if (intentData.user) {
        request.user = intentData.user;
      }

      const response = await plaidClient.transferIntentCreate(request);
      return response.data;
    } catch (error) {
      logger.error('Error creating transfer intent:', error);
      throw error;
    }
  }

  // Get transfer intent
  async getTransferIntent(intentId) {
    try {
      const response = await plaidClient.transferIntentGet({
        transfer_intent_id: intentId,
      });

      return response.data;
    } catch (error) {
      logger.error('Error getting transfer intent:', error);
      throw error;
    }
  }

  // List transfer intents
  async listTransferIntents(accessToken, options = {}) {
    try {
      const request = {
        access_token: accessToken,
        transfer_id: options.transferId,
        account_id: options.accountId,
        count: options.count || 25,
        offset: options.offset || 0,
      };

      // Remove undefined values
      Object.keys(request).forEach(key => {
        if (request[key] === undefined) {
          delete request[key];
        }
      });

      const response = await plaidClient.transferIntentList(request);
      return response.data;
    } catch (error) {
      logger.error('Error listing transfer intents:', error);
      throw error;
    }
  }

  // Get service metrics for monitoring
  getMetrics() {
    return {
      ...plaidMetrics,
      successRate: plaidMetrics.apiCalls > 0 ? (plaidMetrics.successfulCalls / plaidMetrics.apiCalls) * 100 : 0,
      errorRate: plaidMetrics.apiCalls > 0 ? (plaidMetrics.failedCalls / plaidMetrics.apiCalls) * 100 : 0,
      uptime: plaidMetrics.lastErrorTime ? Date.now() - plaidMetrics.lastErrorTime : null,
    };
  }

  // Enhanced error handling with user-friendly messages
  createUserFriendlyError(error, operation) {
    const errorMappings = {
      'INVALID_ACCESS_TOKEN': 'Your bank connection has expired. Please reconnect your account.',
      'ITEM_LOGIN_REQUIRED': 'Your bank requires re-authentication. Please reconnect your account.',
      'INSUFFICIENT_FUNDS': 'Insufficient funds for this transaction.',
      'ACCOUNT_LOCKED': 'Your bank account is temporarily locked. Please contact your bank.',
      'RATE_LIMIT_EXCEEDED': 'Too many requests. Please try again in a moment.',
      'PRODUCT_NOT_READY': 'Bank data is still being processed. Please try again later.',
      'PRODUCTS_NOT_SUPPORTED': 'This feature is not supported by your bank.',
    };

    const plaidErrorCode = error.response?.data?.error_code;
    const userMessage = errorMappings[plaidErrorCode] || 'An error occurred while processing your request. Please try again.';

    logger.error(`Plaid ${operation} error:`, {
      error: error.message,
      plaidErrorCode,
      userMessage,
      operation,
    });

    return new Error(userMessage);
  }
}

const plaidService = new PlaidService();
export default plaidService;
