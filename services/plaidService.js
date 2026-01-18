import { Configuration, PlaidApi, PlaidEnvironments } from 'plaid';
import crypto from 'crypto';
import logger from '../config/logger.js';

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
  async createLinkToken(userId, products = ['auth', 'transactions', 'identity']) {
    if (!process.env.PLAID_CLIENT_ID || !process.env.PLAID_SECRET) {
      throw new Error('Plaid credentials not configured. Please set PLAID_CLIENT_ID and PLAID_SECRET environment variables.');
    }

    try {
      const request = {
        user: {
          client_user_id: userId.toString(),
        },
        client_name: 'Oscar Broome Revenue System',
        products: products,
        country_codes: ['US'],
        language: 'en',
      };

      // Only add webhook if BASE_URL is configured
      if (process.env.BASE_URL) {
        request.webhook = `${process.env.BASE_URL}/api/plaid/webhook`;
      }

      const response = await plaidClient.linkTokenCreate(request);
      return response.data;
    } catch (error) {
      logger.error('Error creating link token:', error);
      throw error;
    }
  }

  // Exchange public token for access token
  async exchangePublicToken(publicToken) {
    try {
      const response = await plaidClient.itemPublicTokenExchange({
        public_token: publicToken,
      });

      return {
        access_token: response.data.access_token,
        item_id: response.data.item_id,
      };
    } catch (error) {
      logger.error('Error exchanging public token:', error);
      throw error;
    }
  }

  // Get account information
  async getAccounts(accessToken) {
    try {
      const response = await plaidClient.accountsGet({
        access_token: accessToken,
      });

      return response.data.accounts;
    } catch (error) {
      logger.error('Error getting accounts:', error);
      throw error;
    }
  }

  // Get account balances
  async getBalances(accessToken) {
    try {
      const response = await plaidClient.accountsBalanceGet({
        access_token: accessToken,
      });

      return response.data.accounts;
    } catch (error) {
      logger.error('Error getting balances:', error);
      throw error;
    }
  }

  // Get transactions
  async getTransactions(accessToken, startDate, endDate, options = {}) {
    try {
      const request = {
        access_token: accessToken,
        start_date: startDate,
        end_date: endDate,
        options: options,
      };

      const response = await plaidClient.transactionsGet(request);
      return response.data.transactions;
    } catch (error) {
      logger.error('Error getting transactions:', error);
      throw error;
    }
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
}

const plaidService = new PlaidService();
export default plaidService;
