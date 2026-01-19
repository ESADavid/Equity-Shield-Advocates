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

      // Add investments_auth configuration for Investments Move
      if (products.includes('investments_auth')) {
        request.investments_auth = {};

        // Add fallback flow options
        if (options.maskedNumberMatchEnabled !== undefined) {
          request.investments_auth.masked_number_match_enabled = options.maskedNumberMatchEnabled;
        }
        if (options.statedAccountNumberEnabled !== undefined) {
          request.investments_auth.stated_account_number_enabled = options.statedAccountNumberEnabled;
        }
        if (options.manualEntryEnabled !== undefined) {
          request.investments_auth.manual_entry_enabled = options.manualEntryEnabled;
        }
      }

      // Add mode
      if (options.mode) {
        request.mode = options.mode;
      }

      // Add update mode specific fields
      if (options.mode === 'update') {
        if (options.itemId) {
          request.access_token = await this.getAccessTokenByItemId(options.itemId);
        }
        if (options.updateModeTrigger) {
          request.update = {
            account_selection_enabled: true,
          };
        }
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

  // Get income information
  async getIncome(accessToken) {
    return retryWithBackoff(async () => {
      const response = await plaidClient.incomeGet({
        access_token: accessToken,
      });

      return response.data.income;
    }, 'getIncome');
  }

  // Get auth information (account and routing numbers)
  async getAuth(accessToken) {
    return retryWithBackoff(async () => {
      const response = await plaidClient.authGet({
        access_token: accessToken,
      });

      // Enhance accounts with Auth-specific metadata
      const enhancedAccounts = response.data.accounts.map(account => {
        const numbers = response.data.numbers || {};

        // Check if account uses tokenized account numbers (TANs)
        const achNumbers = numbers.ach || [];
        const accountNumberData = achNumbers.find(num => num.account_id === account.account_id);

        // Determine if this is a tokenized account number
        const isTokenized = this.isTokenizedAccountNumber(accountNumberData?.account);

        return {
          ...account,
          // Include tokenized account number flag
          is_tokenized_account_number: isTokenized,
          // Include persistent account ID for TAN-enabled accounts
          persistent_account_id: isTokenized ? this.generatePersistentAccountId(account.account_id) : null,
          // Include consent expiration time if available
          consent_expiration_time: response.data.consent_expiration_time || null,
          // Include all number types
          numbers: {
            ach: achNumbers.filter(num => num.account_id === account.account_id),
            eft: (numbers.eft || []).filter(num => num.account_id === account.account_id),
            international: (numbers.international || []).filter(num => num.account_id === account.account_id),
            bacs: (numbers.bacs || []).filter(num => num.account_id === account.account_id),
          },
        };
      });

      return {
        accounts: enhancedAccounts,
        consent_expiration_time: response.data.consent_expiration_time,
        item: response.data.item,
      };
    }, 'getAuth');
  }

  // Get investments auth information (for ACATS transfers)
  async getInvestmentsAuth(accessToken) {
    return retryWithBackoff(async () => {
      const response = await plaidClient.investmentsAuthGet({
        access_token: accessToken,
      });

      return response.data;
    }, 'getInvestmentsAuth');
  }

  // Get investments holdings and transactions
  async getInvestments(accessToken, options = {}) {
    return retryWithBackoff(async () => {
      const request = {
        access_token: accessToken,
      };

      // Add optional parameters
      if (options.count) request.count = options.count;
      if (options.offset) request.offset = options.offset;

      const response = await plaidClient.investmentsGet(request);
      return response.data;
    }, 'getInvestments');
  }

  // Get liabilities information (debt details)
  async getLiabilities(accessToken) {
    return retryWithBackoff(async () => {
      const response = await plaidClient.liabilitiesGet({
        access_token: accessToken,
      });

      return response.data;
    }, 'getLiabilities');
  }

  // Enrich transactions data
  async enrichTransactions(transactions, options = {}) {
    return retryWithBackoff(async () => {
      const request = {
        transactions: transactions,
      };

      // Add optional parameters
      if (options.account_type) request.account_type = options.account_type;
      if (options.country_code) request.country_code = options.country_code;

      const response = await plaidClient.transactionsEnrich(request);
      return response.data;
    }, 'enrichTransactions');
  }

  // Verify account ownership (proof of funds)
  async verifyAccountOwnership(accessToken, accountId, amounts) {
    return retryWithBackoff(async () => {
      const response = await plaidClient.identityVerificationCreate({
        access_token: accessToken,
        account_id: accountId,
        amounts: amounts,
      });

      return response.data;
    }, 'verifyAccountOwnership');
  }

  // Get identity information
  async getIdentity(accessToken) {
    return retryWithBackoff(async () => {
      const response = await plaidClient.identityGet({
        access_token: accessToken,
      });

      return response.data.accounts;
    }, 'getIdentity');
  }

  // Match user identity information against institution data
  async identityMatch(accessToken, userIdentity) {
    return retryWithBackoff(async () => {
      const request = {
        access_token: accessToken,
      };

      // Add user identity data for matching
      if (userIdentity.legal_name) {
        request.user = {
          ...request.user,
          legal_name: userIdentity.legal_name,
        };
      }

      if (userIdentity.phone_number) {
        request.user = {
          ...request.user,
          phone_number: userIdentity.phone_number,
        };
      }

      if (userIdentity.email_address) {
        request.user = {
          ...request.user,
          email_address: userIdentity.email_address,
        };
      }

      if (userIdentity.address) {
        request.user = {
          ...request.user,
          address: userIdentity.address,
        };
      }

      const response = await plaidClient.identityMatch({
        ...request,
      });

      return response.data;
    }, 'identityMatch');
  }

  // Remove item (disconnect account)
  async removeItem(accessToken) {
    return retryWithBackoff(async () => {
      const response = await plaidClient.itemRemove({
        access_token: accessToken,
      });

      return response.data;
    }, 'removeItem');
  }

  // Get institutions
  async getInstitutions(options = {}) {
    return retryWithBackoff(async () => {
      const request = {
        count: options.count || 50,
        offset: options.offset || 0,
      };

      if (options.country_codes) {
        request.country_codes = options.country_codes;
      }

      const response = await plaidClient.institutionsGet(request);
      return response.data.institutions;
    }, 'getInstitutions');
  }

  // Get webhook verification key
  async getWebhookVerificationKey() {
    return retryWithBackoff(async () => {
      const response = await plaidClient.webhookVerificationKeyGet({});
      return response.data.key;
    }, 'getWebhookVerificationKey');
  }

  // Handle webhook
  async handleWebhook(webhookEvent) {
    try {
      logger.info('Processing webhook event:', {
        type: webhookEvent.webhook_type,
        code: webhookEvent.webhook_code,
        item_id: webhookEvent.item_id,
      });

      // Handle different webhook types
      switch (webhookEvent.webhook_type) {
        case 'TRANSACTIONS':
          await this.handleTransactionWebhook(webhookEvent);
          break;
        case 'ITEM':
          await this.handleItemWebhook(webhookEvent);
          break;
        case 'AUTH':
          await this.handleAuthWebhook(webhookEvent);
          break;
        case 'INCOME':
          await this.handleIncomeWebhook(webhookEvent);
          break;
        case 'LAYER':
          await this.handleLayerWebhook(webhookEvent);
          break;
        default:
          logger.info('Unhandled webhook type:', webhookEvent.webhook_type);
      }

      return { success: true };
    } catch (error) {
      logger.error('Error handling webhook:', error);
      throw error;
    }
  }

  // Handle transaction webhooks
  async handleTransactionWebhook(webhookEvent) {
    try {
      const { webhook_code, item_id } = webhookEvent;

      switch (webhook_code) {
        case 'INITIAL_UPDATE':
          logger.info('Initial transactions update received for item:', item_id);
          // Could trigger a sync or notification
          break;
        case 'HISTORICAL_UPDATE':
          logger.info('Historical transactions update received for item:', item_id);
          break;
        case 'DEFAULT_UPDATE':
          logger.info('Default transactions update received for item:', item_id);
          break;
        case 'TRANSACTIONS_REMOVED':
          logger.info('Transactions removed for item:', item_id);
          break;
        default:
          logger.info('Unknown transaction webhook code:', webhook_code);
      }
    } catch (error) {
      logger.error('Error handling transaction webhook:', error);
      throw error;
    }
  }

  // Handle item webhooks
  async handleItemWebhook(webhookEvent) {
    try {
      const { webhook_code, item_id } = webhookEvent;

      switch (webhook_code) {
        case 'ERROR':
          logger.error('Item error occurred:', { item_id, error: webhookEvent.error });
          // Could trigger update mode or notification
          break;
        case 'PENDING_DISCONNECT':
          logger.warn('Item pending disconnect:', item_id);
          // Should launch update mode
          break;
        case 'PENDING_EXPIRATION':
          logger.warn('Item pending expiration:', item_id);
          // Should launch update mode
          break;
        case 'USER_PERMISSION_REVOKED':
          logger.warn('User permission revoked for item:', item_id);
          // Should create new Item
          break;
        case 'NEW_ACCOUNTS_AVAILABLE':
          logger.info('New accounts available for item:', item_id);
          // Could launch update mode to access new accounts
          break;
        default:
          logger.info('Unknown item webhook code:', webhook_code);
      }
    } catch (error) {
      logger.error('Error handling item webhook:', error);
      throw error;
    }
  }

  // Handle auth webhooks
  async handleAuthWebhook(webhookEvent) {
    try {
      const { webhook_code, item_id, account_id } = webhookEvent;

      switch (webhook_code) {
        case 'AUTOMATICALLY_VERIFIED':
          logger.info('Auth automatically verified for item:', { item_id, account_id });
          // Account numbers are now available and verified
          break;

        case 'VERIFICATION_EXPIRED':
          logger.warn('Auth verification expired for item:', { item_id, account_id });
          // Consent has expired, need to send user through update mode
          // TODO: Trigger update mode flow
          break;

        case 'DEFAULT_UPDATE':
          logger.info('Auth default update for item:', { item_id, account_id });
          // Account/routing numbers have changed, need to refresh data
          // TODO: Call /auth/get to get updated account numbers
          break;

        case 'LOGIN_REPAIRED':
          logger.info('Auth login repaired for item:', { item_id, account_id });
          // User successfully repaired their login
          break;

        case 'NUMBER_VERIFIED':
          logger.info('Auth number verified for item:', { item_id, account_id });
          // Account number has been verified via micro-deposits
          break;

        case 'NUMBER_VERIFICATION_FAILED':
          logger.warn('Auth number verification failed for item:', { item_id, account_id });
          // Micro-deposit verification failed
          break;

        default:
          logger.info('Unknown auth webhook code:', { webhook_code, item_id, account_id });
      }

      // Handle PNC-specific TAN expiration logic
      if (webhook_code === 'VERIFICATION_EXPIRED' || webhook_code === 'DEFAULT_UPDATE') {
        // Check if this is a PNC item and handle TAN regeneration
        await this.handlePncTanExpiration(item_id, account_id);
      }
    } catch (error) {
      logger.error('Error handling auth webhook:', error);
      throw error;
    }
  }

  // Handle income webhooks
  async handleIncomeWebhook(webhookEvent) {
    try {
      const { webhook_code, item_id } = webhookEvent;

      switch (webhook_code) {
        case 'INCOME_VERIFICATION':
          logger.info('Income verification completed for item:', item_id);
          break;
        default:
          logger.info('Unknown income webhook code:', webhook_code);
      }
    } catch (error) {
      logger.error('Error handling income webhook:', error);
      throw error;
    }
  }

  // Verify webhook signature
  async verifyWebhookSignature(rawBody, signature, verificationKey) {
    try {
      // Plaid uses HMAC-SHA256 for webhook signature verification
      const expectedSignature = crypto
        .createHmac('sha256', verificationKey)
        .update(rawBody, 'utf8')
        .digest('hex');

      // Plaid sends signature in format: "v2-sha256,<signature>"
      const providedSignature = signature.replace('v2-sha256,', '');

      const isValid = crypto.timingSafeEqual(
        Buffer.from(expectedSignature, 'hex'),
        Buffer.from(providedSignature, 'hex')
      );

      return isValid;
    } catch (error) {
      logger.error('Error verifying webhook signature:', error);
      return false;
    }
  }

  // Initiate SMS microdeposits for account verification
  async initiateMicrodeposits(accessToken, accountId) {
    return retryWithBackoff(async () => {
      const response = await plaidClient.authMicrodepositsInitiate({
        access_token: accessToken,
        account_id: accountId,
      });

      return response.data;
    }, 'initiateMicrodeposits');
  }

  // Verify SMS microdeposits with deposit amounts
  async verifyMicrodeposits(accessToken, accountId, amounts) {
    return retryWithBackoff(async () => {
      const response = await plaidClient.authMicrodepositsVerify({
        access_token: accessToken,
        account_id: accountId,
        amounts: amounts,
      });

      return response.data;
    }, 'verifyMicrodeposits');
  }

  // Get microdeposits verification status
  async getMicrodepositsStatus(accessToken, accountId) {
    return retryWithBackoff(async () => {
      const response = await plaidClient.authMicrodepositsGet({
        access_token: accessToken,
        account_id: accountId,
      });

      return response.data;
    }, 'getMicrodepositsStatus');
  }

  // Get bank transfer events
  async getBankTransferEvents(accessToken, options = {}) {
    return retryWithBackoff(async () => {
      const request = {
        access_token: accessToken,
        count: options.count || 25,
        offset: options.offset || 0,
      };

      if (options.eventTypes) request.event_types = options.eventTypes;
      if (options.transferId) request.transfer_id = options.transferId;
      if (options.accountId) request.account_id = options.accountId;
      if (options.transferType) request.transfer_type = options.transferType;
      if (options.originationAccountId) request.origination_account_id = options.originationAccountId;
      if (options.startDate) request.start_date = options.startDate;
      if (options.endDate) request.end_date = options.endDate;

      const response = await plaidClient.transferEventList(request);
      return response.data.transfer_events;
    }, 'getBankTransferEvents');
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

  // Get access token by item ID (for update mode)
  async getAccessTokenByItemId(itemId) {
    try {
      // This method needs to be implemented based on your data storage
      // It should retrieve the access token associated with the given item ID
      // For now, this is a placeholder that throws an error

      // Example implementation (adjust based on your database schema):
      // const item = await Item.findOne({ item_id: itemId });
      // if (!item) {
      //   throw new Error(`Item ${itemId} not found`);
      // }
      // return item.access_token;

      throw new Error(`getAccessTokenByItemId method needs to be implemented for item ID: ${itemId}`);
    } catch (error) {
      logger.error('Error getting access token by item ID:', error);
      throw error;
    }
  }

  // Check if account number is tokenized (TAN)
  isTokenizedAccountNumber(accountNumber) {
    if (!accountNumber || typeof accountNumber !== 'string') {
      return false;
    }

    // Tokenized account numbers typically have specific patterns:
    // - Chase: Usually start with specific prefixes or have certain lengths
    // - PNC: TANs are different from real account numbers
    // - US Bank: TANs follow different patterns
    // For sandbox, we can detect based on known test patterns

    // In production, this would be determined by the Plaid API response
    // For now, we'll use heuristics based on account number patterns
    const tanPatterns = [
      // Chase TANs often have specific formats
      /^9\d{10,}$/, // Chase TANs may start with 9
      // PNC TANs are typically different from real numbers
      /^\d{8,12}$/, // PNC TANs have specific lengths
      // US Bank TANs
      /^\d{10,12}$/, // US Bank TANs have specific ranges
    ];

    // Check if the account number matches known TAN patterns
    return tanPatterns.some(pattern => pattern.test(accountNumber));
  }

  // Generate persistent account ID for TAN-enabled accounts
  generatePersistentAccountId(accountId) {
    // Create a persistent identifier for TAN-enabled accounts
    // This should be consistent across different Item instances for the same account
    const hash = crypto.createHash('sha256');
    hash.update(accountId + 'persistent_salt'); // Add salt for uniqueness
    return hash.digest('hex').substring(0, 32); // Return first 32 chars
  }

  // Handle PNC TAN expiration and regeneration
  async handlePncTanExpiration(itemId, accountId) {
    try {
      logger.info('Handling PNC TAN expiration for item:', { itemId, accountId });

      // For PNC Items, we need to:
      // 1. Send the Item through update mode
      // 2. Call /auth/get to get new TAN after update mode completes
      // 3. Update stored account information

      // This is a placeholder for the actual implementation
      // In production, this would:
      // - Check if the item is at PNC
      // - Trigger update mode flow
      // - Refresh account data after update mode
      // - Update database with new TAN

      logger.warn('PNC TAN expiration handling needs to be implemented with proper update mode flow');

      // TODO: Implement proper PNC TAN regeneration logic
      // This should integrate with your Item management system

    } catch (error) {
      logger.error('Error handling PNC TAN expiration:', error);
      throw error;
    }
  }

  // Layer Integration Methods

  // Create a Layer session token
  async createSessionToken(templateId, userId, options = {}) {
    return retryWithBackoff(async () => {
      const request = {
        template_id: templateId,
        user: {
          client_user_id: userId.toString(),
          ...(options.user && { ...options.user }),
        },
        client_name: options.clientName || 'Oscar Broome Revenue System',
      };

      // Add optional parameters
      if (options.webhook) {
        request.webhook = options.webhook;
      } else if (process.env.BASE_URL) {
        request.webhook = `${process.env.BASE_URL}/api/plaid/webhook`;
      }

      if (options.linkCustomizationName) {
        request.link_customization_name = options.linkCustomizationName;
      }

      const response = await plaidClient.sessionTokenCreate(request);
      return response.data;
    }, 'createSessionToken');
  }

  // Get user account session data after Layer completion
  async getUserAccountSession(sessionId) {
    return retryWithBackoff(async () => {
      const response = await plaidClient.userAccountSessionGet({
        session_id: sessionId,
      });

      return response.data;
    }, 'getUserAccountSession');
  }

  // Handle Layer-specific webhooks
  async handleLayerWebhook(webhookEvent) {
    try {
      const { webhook_code, session_id, item_id } = webhookEvent;

      switch (webhook_code) {
        case 'LAYER_AUTHENTICATION_PASSED':
          logger.info('Layer authentication passed for session:', {
            session_id,
            item_id,
          });
          // User has been authenticated via Layer
          // Can now proceed with account linking
          break;

        case 'SESSION_FINISHED':
          logger.info('Layer session finished:', {
            session_id,
            item_id,
          });
          // Layer session completed successfully
          // Retrieve user account data using session_id
          try {
            const sessionData = await this.getUserAccountSession(session_id);
            logger.info('Retrieved Layer session data:', {
              session_id,
              has_accounts: !!sessionData.accounts,
              has_identity: !!sessionData.identity,
            });
            // Process the session data (store in database, etc.)
          } catch (error) {
            logger.error('Error retrieving Layer session data:', error);
          }
          break;

        default:
          logger.info('Unknown Layer webhook code:', webhook_code);
      }
    } catch (error) {
      logger.error('Error handling Layer webhook:', error);
      throw error;
    }
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
