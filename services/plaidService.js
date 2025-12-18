import { Configuration, PlaidApi, PlaidEnvironments } from 'plaid';
import logger from '../utils/loggerWrapper.js';

// Plaid API configuration
const PLAID_CLIENT_ID = process.env.PLAID_CLIENT_ID;
const PLAID_SECRET = process.env.PLAID_SECRET;
const PLAID_ENV = process.env.PLAID_ENV || 'sandbox'; // sandbox, development, production

// Initialize Plaid client
let plaidClient = null;
if (PLAID_CLIENT_ID && PLAID_SECRET) {
  const configuration = new Configuration({
    basePath: PlaidEnvironments[PLAID_ENV],
    baseOptions: {
      headers: {
        'PLAID-CLIENT-ID': PLAID_CLIENT_ID,
        'PLAID-SECRET': PLAID_SECRET,
      },
    },
  });

  plaidClient = new PlaidApi(configuration);
} else {
  logger.warn('⚠️  PLAID_CLIENT_ID and/or PLAID_SECRET not found. Plaid functionality will be disabled for testing.');
}

// Plaid service functions
export const plaidService = {
  // Create a link token for account linking
  async createLinkToken(userId, products = ['transactions']) {
    if (!plaidClient) {
      throw new Error('Plaid client not configured');
    }

    try {
      const request = {
        user: {
          client_user_id: userId,
        },
        client_name: 'Oscar Broome Revenue System',
        products: products,
        country_codes: ['US'],
        language: 'en',
        webhook: `${process.env.BASE_URL}/api/plaid/webhook`,
      };

      const response = await plaidClient.linkTokenCreate(request);

      return {
        link_token: response.data.link_token,
        expiration: response.data.expiration,
      };
    } catch (error) {
      logger.error('Error creating Plaid link token:', error);
      throw new Error('Failed to create link token');
    }
  },

  // Exchange public token for access token
  async exchangePublicToken(publicToken) {
    if (!plaidClient) {
      throw new Error('Plaid client not configured');
    }

    try {
      const request = {
        public_token: publicToken,
      };

      const response = await plaidClient.itemPublicTokenExchange(request);

      return {
        access_token: response.data.access_token,
        item_id: response.data.item_id,
      };
    } catch (error) {
      logger.error('Error exchanging public token:', error);
      throw new Error('Failed to exchange public token');
    }
  },

  // Get account information
  async getAccounts(accessToken) {
    if (!plaidClient) {
      throw new Error('Plaid client not configured');
    }

    try {
      const request = {
        access_token: accessToken,
      };

      const response = await plaidClient.accountsGet(request);
      return response.data.accounts;
    } catch (error) {
      logger.error('Error getting accounts:', error);
      throw new Error('Failed to get accounts');
    }
  },

  // Get transactions
  async getTransactions(accessToken, startDate, endDate, options = {}) {
    if (!plaidClient) {
      throw new Error('Plaid client not configured');
    }

    try {
      const request = {
        access_token: accessToken,
        start_date: startDate,
        end_date: endDate,
        options: {
          count: options.count || 100,
          offset: options.offset || 0,
          ...options,
        },
      };

      const response = await plaidClient.transactionsGet(request);
      return response.data.transactions;
    } catch (error) {
      logger.error('Error getting transactions:', error);
      throw new Error('Failed to get transactions');
    }
  },

  // Get account balances
  async getBalances(accessToken) {
    if (!plaidClient) {
      throw new Error('Plaid client not configured');
    }

    try {
      const request = {
        access_token: accessToken,
      };

      const response = await plaidClient.accountsBalanceGet(request);
      return response.data.accounts;
    } catch (error) {
      logger.error('Error getting balances:', error);
      throw new Error('Failed to get balances');
    }
  },

  // Get income information
  async getIncome(accessToken) {
    if (!plaidClient) {
      throw new Error('Plaid client not configured');
    }

    try {
      const request = {
        access_token: accessToken,
      };

      const response = await plaidClient.incomeGet(request);
      return response.data.income;
    } catch (error) {
      logger.error('Error getting income:', error);
      throw new Error('Failed to get income');
    }
  },

  // Verify account ownership (for proof of funds)
  async verifyAccountOwnership(accessToken, accountId, amounts) {
    if (!plaidClient) {
      throw new Error('Plaid client not configured');
    }

    try {
      // Get account details
      const accounts = await this.getAccounts(accessToken);
      const account = accounts.find(acc => acc.account_id === accountId);

      if (!account) {
        throw new Error('Account not found');
      }

      // Check if account has sufficient balance for verification amounts
      const verificationResults = amounts.map(amount => ({
        amount,
        sufficient: account.balances.available >= amount,
        available_balance: account.balances.available,
        account_type: account.type,
        account_subtype: account.subtype,
      }));

      return {
        account_id: accountId,
        account_name: account.name,
        account_type: account.type,
        verification_results: verificationResults,
        verified_at: new Date().toISOString(),
      };
    } catch (error) {
      logger.error('Error verifying account ownership:', error);
      throw new Error('Failed to verify account ownership');
    }
  },

  // Get identity information
  async getIdentity(accessToken) {
    if (!plaidClient) {
      throw new Error('Plaid client not configured');
    }

    try {
      const request = {
        access_token: accessToken,
      };

      const response = await plaidClient.identityGet(request);
      return response.data.accounts;
    } catch (error) {
      logger.error('Error getting identity:', error);
      throw new Error('Failed to get identity');
    }
  },

  // Remove item (disconnect account)
  async removeItem(accessToken) {
    if (!plaidClient) {
      throw new Error('Plaid client not configured');
    }

    try {
      const request = {
        access_token: accessToken,
      };

      const response = await plaidClient.itemRemove(request);
      return response.data;
    } catch (error) {
      logger.error('Error removing item:', error);
      throw new Error('Failed to remove item');
    }
  },

  // Webhook handling
  async handleWebhook(event) {
    logger.info('Received Plaid webhook:', event);

    switch (event.webhook_type) {
      case 'TRANSACTIONS':
        if (event.webhook_code === 'INITIAL_UPDATE' || event.webhook_code === 'HISTORICAL_UPDATE') {
          // Handle transaction updates
          await this.processTransactionUpdate(event);
        }
        break;

      case 'ITEM':
        if (event.webhook_code === 'ERROR') {
          // Handle item errors
          await this.handleItemError(event);
        }
        break;

      default:
        logger.info('Unhandled webhook type:', event.webhook_type);
    }

    return { received: true };
  },

  // Process transaction updates
  async processTransactionUpdate(event) {
    try {
      // Get updated transactions
      const accessToken = await this.getAccessTokenForItem(event.item_id);
      if (!accessToken) return;

      const startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
      const endDate = new Date().toISOString().split('T')[0];

      const transactions = await this.getTransactions(accessToken, startDate, endDate);

      // Process and store transactions
      for (const transaction of transactions) {
        await this.storeTransaction(transaction);
      }

      logger.info(`Processed ${transactions.length} transactions for item ${event.item_id}`);
    } catch (error) {
      logger.error('Error processing transaction update:', error);
    }
  },

  // Handle item errors
  async handleItemError(event) {
    logger.error('Plaid item error:', event.error);
    // Handle item errors (e.g., invalid credentials, item locked)
  },

  // Helper methods
  async getAccessTokenForItem(itemId) {
    // This would typically come from your database
    // For now, return null (implement based on your storage)
    return null;
  },

  async storeTransaction(transaction) {
    // Store transaction in your database
    logger.info('Storing transaction:', transaction.transaction_id);
  },
};

export default plaidService;
