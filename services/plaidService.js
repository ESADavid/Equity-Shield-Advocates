import { Configuration, PlaidApi, PlaidEnvironments } from 'plaid';
import crypto from 'crypto';
import logger from '../config/logger.js';
import plaidSignalService from './plaidSignalService.js';

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
}

const plaidService = new PlaidService();
export default plaidService;
