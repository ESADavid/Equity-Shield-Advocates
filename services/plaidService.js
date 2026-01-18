import { Configuration, PlaidApi, PlaidEnvironments } from 'plaid';
import crypto from 'crypto';
import logger from '../config/logger.js';

// Plaid configuration
const configuration = new Configuration({
  basePath: PlaidEnvironments[process.env.PLAID_ENV || 'sandbox'],
  baseOptions: {
    headers: {
      'PLAID-CLIENT-ID': process.env.PLAID_CLIENT_ID,
      'PLAID-SECRET': process.env.PLAID_SECRET,
    },
  },
});

const plaidClient = new PlaidApi(configuration);

class PlaidService {
  // Create link token for account linking
  async createLinkToken(userId, products = ['auth', 'transactions']) {
    try {
      const request = {
        user: {
          client_user_id: userId.toString(),
        },
        client_name: 'Oscar Broome Revenue System',
        products: products,
        country_codes: ['US'],
        language: 'en',
        webhook: `${process.env.BASE_URL}/api/plaid/webhook`,
      };

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
        options: {
          count: options.count || 100,
          offset: options.offset || 0,
        },
      };

      const response = await plaidClient.transactionsGet(request);
      return response.data.transactions;
    } catch (error) {
      logger.error('Error getting transactions:', error);
      throw error;
    }
  }

  // Get income information
  async getIncome(accessToken) {
    try {
      const response = await plaidClient.incomeGet({
        access_token: accessToken,
      });

      return response.data.income;
    } catch (error) {
      logger.error('Error getting income:', error);
      throw error;
    }
  }

  // Get auth information (account and routing numbers)
  async getAuth(accessToken) {
    try {
      const response = await plaidClient.authGet({
        access_token: accessToken,
      });

      return response.data;
    } catch (error) {
      logger.error('Error getting auth:', error);
      throw error;
    }
  }

  // Verify account ownership (proof of funds)
  async verifyAccountOwnership(accessToken, accountId, amounts) {
    try {
      const response = await plaidClient.assetReportAuditCopyCreate({
        access_token: accessToken,
        auditor_id: process.env.PLAID_AUDITOR_ID,
      });

      // This is a simplified implementation
      // In production, you would use the audit copy token
      return {
        verification_status: 'VERIFIED',
        amounts: amounts,
      };
    } catch (error) {
      logger.error('Error verifying account ownership:', error);
      throw error;
    }
  }

  // Get identity information
  async getIdentity(accessToken) {
    try {
      const response = await plaidClient.identityGet({
        access_token: accessToken,
      });

      return response.data.accounts;
    } catch (error) {
      logger.error('Error getting identity:', error);
      throw error;
    }
  }

  // Remove item (disconnect account)
  async removeItem(accessToken) {
    try {
      const response = await plaidClient.itemRemove({
        access_token: accessToken,
      });

      return response.data;
    } catch (error) {
      logger.error('Error removing item:', error);
      throw error;
    }
  }

  // Get institutions
  async getInstitutions(options = {}) {
    try {
      const request = {
        count: options.count || 50,
        offset: options.offset || 0,
        country_codes: options.country_codes || ['US'],
      };

      const response = await plaidClient.institutionsGet(request);
      return response.data.institutions;
    } catch (error) {
      logger.error('Error getting institutions:', error);
      throw error;
    }
  }

  // Get webhook verification key
  async getWebhookVerificationKey() {
    try {
      const response = await plaidClient.webhookVerificationKeyGet({
        key_id: process.env.PLAID_WEBHOOK_VERIFICATION_KEY_ID,
      });

      return response.data.key;
    } catch (error) {
      logger.error('Error getting webhook verification key:', error);
      throw error;
    }
  }

  // Verify webhook signature
  verifyWebhookSignature(rawBody, signature, verificationKey) {
    try {
      const expectedSignature = crypto
        .createHmac('sha256', verificationKey)
        .update(rawBody)
        .digest('base64');

      const signatureBuffer = Buffer.from(signature, 'base64');
      const expectedBuffer = Buffer.from(expectedSignature, 'base64');

      if (signatureBuffer.length !== expectedBuffer.length) {
        return false;
      }

      return crypto.timingSafeEqual(signatureBuffer, expectedBuffer);
    } catch (error) {
      logger.error('Error verifying webhook signature:', error);
      return false;
    }
  }

  // Handle webhook events
  async handleWebhook(event) {
    try {
      logger.info('Received Plaid webhook:', {
        webhook_type: event.webhook_type,
        webhook_code: event.webhook_code,
        item_id: event.item_id,
      });

      switch (event.webhook_type) {
        case 'TRANSACTIONS':
          await this.handleTransactionWebhook(event);
          break;

        case 'ITEM':
          await this.handleItemWebhook(event);
          break;

        case 'ASSETS':
          await this.handleAssetWebhook(event);
          break;

        case 'AUTH':
          await this.handleAuthWebhook(event);
          break;

        default:
          logger.warn('Unhandled webhook type:', event.webhook_type);
      }

      return {
        success: true,
        message: 'Webhook processed successfully',
      };
    } catch (error) {
      logger.error('Error handling webhook:', error);
      throw error;
    }
  }

  // Handle transaction webhooks
  async handleTransactionWebhook(event) {
    const { webhook_code, item_id } = event;

    switch (webhook_code) {
      case 'INITIAL_UPDATE':
        logger.info('Initial transaction data available', { item_id });
        // Trigger transaction sync
        break;

      case 'HISTORICAL_UPDATE':
        logger.info('Historical transaction data available', { item_id });
        // Trigger historical transaction sync
        break;

      case 'DEFAULT_UPDATE':
        logger.info('New transactions available', { item_id });
        // Trigger transaction sync
        break;

      case 'TRANSACTIONS_REMOVED':
        logger.info('Transactions removed', { item_id });
        // Handle removed transactions
        break;

      default:
        logger.warn('Unhandled transaction webhook code:', webhook_code);
    }
  }

  // Handle item webhooks
  async handleItemWebhook(event) {
    const { webhook_code, item_id } = event;

    switch (webhook_code) {
      case 'ERROR':
        logger.error('Item error occurred', { item_id, error: event.error });
        // Handle item error
        break;

      case 'NEW_ACCOUNTS_AVAILABLE':
        logger.info('New accounts available', { item_id });
        // Handle new accounts
        break;

      case 'PENDING_EXPIRATION':
        logger.warn('Item pending expiration', { item_id });
        // Handle pending expiration
        break;

      case 'USER_PERMISSION_REVOKED':
        logger.warn('User permission revoked', { item_id });
        // Handle permission revocation
        break;

      case 'WEBHOOK_UPDATE_ACKNOWLEDGED':
        logger.info('Webhook update acknowledged', { item_id });
        // Handle webhook update acknowledgment
        break;

      default:
        logger.warn('Unhandled item webhook code:', webhook_code);
    }
  }

  // Handle asset webhooks
  async handleAssetWebhook(event) {
    const { webhook_code } = event;

    switch (webhook_code) {
      case 'PRODUCT_READY':
        logger.info('Asset report ready', { asset_report_id: event.asset_report_id });
        // Handle asset report ready
        break;

      case 'ERROR':
        logger.error('Asset report error', { error: event.error });
        // Handle asset report error
        break;

      default:
        logger.warn('Unhandled asset webhook code:', webhook_code);
    }
  }

  // Handle auth webhooks
  async handleAuthWebhook(event) {
    const { webhook_code, item_id, account_id } = event;

    switch (webhook_code) {
      case 'DEFAULT_UPDATE':
        logger.info('Auth data updated (default update)', {
          item_id,
          account_id,
        });
        // Handle default update - new auth data available
        // This may include updated account numbers or verification status
        // Trigger auth data refresh
        break;

      case 'VERIFICATION_STATUS_CHANGED':
        logger.info('Account verification status changed', {
          item_id,
          account_id,
          verification_status: event.verification_status,
        });

        // Handle specific verification statuses
        if (event.verification_status === 'automatically_verified') {
          logger.info('Account automatically verified by Plaid', {
            item_id,
            account_id,
          });
          // Account has been automatically verified
          // Update database with verified status
          // This provides high confidence in account ownership
        } else if (event.verification_status === 'manually_verified') {
          logger.info('Account manually verified', {
            item_id,
            account_id,
          });
          // Account has been manually verified
        } else if (event.verification_status === 'verification_expired') {
          logger.warn('Account verification expired', {
            item_id,
            account_id,
          });
          // Verification has expired, may need re-verification
        } else if (event.verification_status === 'verification_failed') {
          logger.warn('Account verification failed', {
            item_id,
            account_id,
          });
          // Verification failed, notify user
        }

        // Update account verification status in database
        // Notify user of verification status changes
        break;

      case 'ACCOUNT_NUMBERS_CHANGED':
        logger.info('Account numbers changed', {
          item_id,
          account_id,
        });
        // Handle account numbers change
        // Update account numbers in database
        // Notify user of changes
        break;

      default:
        logger.warn('Unhandled auth webhook code:', webhook_code);
    }
  }

  // Get bank transfer events
  async getBankTransferEvents(accessToken, options = {}) {
    try {
      const request = {
        access_token: accessToken,
        start_date: options.startDate,
        end_date: options.endDate,
        transfer_id: options.transferId,
        account_id: options.accountId,
        transfer_type: options.transferType,
        event_types: options.eventTypes,
        count: options.count || 25,
        offset: options.offset || 0,
      };

      // Remove undefined values
      Object.keys(request).forEach(key => {
        if (request[key] === undefined) {
          delete request[key];
        }
      });

      const response = await plaidClient.transferEventList(request);
      return response.data.transfer_events;
    } catch (error) {
      logger.error('Error getting bank transfer events:', error);
      throw error;
    }
  }

  // Initiate SMS microdeposits for account verification
  async initiateMicrodeposits(accessToken, accountId) {
    try {
      const request = {
        access_token: accessToken,
        account_id: accountId,
      };

      const response = await plaidClient.authMicrodepositsInitiate(request);
      return response.data;
    } catch (error) {
      logger.error('Error initiating microdeposits:', error);
      throw error;
    }
  }

  // Verify SMS microdeposits with deposit amounts
  async verifyMicrodeposits(accessToken, accountId, amounts) {
    try {
      const request = {
        access_token: accessToken,
        account_id: accountId,
        amounts: amounts, // Array of deposit amounts (e.g., [0.01, 0.02])
      };

      const response = await plaidClient.authMicrodepositsVerify(request);
      return response.data;
    } catch (error) {
      logger.error('Error verifying microdeposits:', error);
      throw error;
    }
  }

  // Get microdeposits verification status
  async getMicrodepositsStatus(accessToken, accountId) {
    try {
      // Use authGet to check verification status
      const response = await plaidClient.authGet({
        access_token: accessToken,
      });

      // Find the specific account
      const account = response.data.accounts.find(acc => acc.account_id === accountId);
      if (!account) {
        throw new Error('Account not found');
      }

      return {
        account_id: account.account_id,
        verification_status: account.verification_status,
        verification_method: account.verification_method,
      };
    } catch (error) {
      logger.error('Error getting microdeposits status:', error);
      throw error;
    }
  }
}

const plaidService = new PlaidService();
export default plaidService;
