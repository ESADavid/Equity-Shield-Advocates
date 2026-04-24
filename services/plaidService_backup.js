import { Configuration, PlaidApi, PlaidEnvironments } from 'plaid';
import logger from 'utils/loggerWrapper.js';

// Plaid API configuration
const PLAID_CLIENT_ID = process.env.PLAID_CLIENT_ID;
const PLAID_SECRET = process.env.PLAID_SECRET;
const PLAID_ENV = process.env.PLAID_ENV || 'sandbox'; // sandbox, development, production
const PLAID_API_VERSION = process.env.PLAID_API_VERSION || '2020-09-14'; // Default to stable version

// Initialize Plaid client
let plaidClient = null;
if (PLAID_CLIENT_ID && PLAID_SECRET) {
  const configuration = new Configuration({
    basePath: PlaidEnvironments[PLAID_ENV],
    baseOptions: {
      headers: {
        'PLAID-CLIENT-ID': PLAID_CLIENT_ID,
        'PLAID-SECRET': PLAID_SECRET,
        'Plaid-Version': PLAID_API_VERSION,
      },
    },
  });

  plaidClient = new PlaidApi(configuration);
  logger.info(`Plaid client initialized with API version: ${PLAID_API_VERSION}`);
} else {
  logger.warn(
    '⚠️  PLAID_CLIENT_ID and/or PLAID_SECRET not found. Plaid functionality will be disabled for testing.'
  );
}

// Plaid service functions
export const plaidService = {
  // Create a link token for account linking
  async createLinkToken(userId, products = ['auth', 'transactions']) {
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

  // Get auth information (account and routing numbers)
  async getAuth(accessToken, options = {}) {
    if (!plaidClient) {
      throw new Error('Plaid client not configured');
    }

    try {
      const request = {
        access_token: accessToken,
        options: options,
      };

      const response = await plaidClient.authGet(request);
      return response.data;
    } catch (error) {
      logger.error('Error getting auth:', error);
      throw new Error('Failed to get auth');
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
      const account = accounts.find((acc) => acc.account_id === accountId);

      if (!account) {
        throw new Error('Account not found');
      }

      // Check if account has sufficient balance for verification amounts
      const verificationResults = amounts.map((amount) => ({
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

  // Get institutions
  async getInstitutions(options = {}) {
    if (!plaidClient) {
      // Return mock data for testing
      const fs = await import('fs');
      const path = await import('path');
      const { fileURLToPath } = await import('url');
      const __filename = fileURLToPath(import.meta.url);
      const __dirname = path.dirname(__filename);
      const mockDataPath = path.join(__dirname, '../../../data/plaid_institutions.json');

      try {
        const mockData = fs.readFileSync(mockDataPath, 'utf8');
        return JSON.parse(mockData);
      } catch (error) {
        logger.error('Error reading mock institutions data:', error);
        throw new Error('Failed to get institutions data');
      }
    }

    try {
      const request = {
        count: options.count || 50,
        offset: options.offset || 0,
        country_codes: options.country_codes || ['US'],
        ...options,
      };

      const response = await plaidClient.institutionsGet(request);
      return response.data;
    } catch (error) {
      logger.error('Error getting institutions:', error);
      throw new Error('Failed to get institutions');
    }
  },

  // Get webhook verification key from Plaid API
  async getWebhookVerificationKey() {
    if (!plaidClient) {
      throw new Error('Plaid client not configured');
    }

    try {
      const response = await plaidClient.webhookVerificationKeyGet({});
      return response.data.key;
    } catch (error) {
      logger.error('Error getting webhook verification key:', error);
      throw new Error('Failed to get webhook verification key');
    }
  },

  // Verify webhook signature according to Plaid's specification
  async verifyWebhookSignature(payload, signature, secret) {
    try {
      if (!payload || !signature || !secret) {
        logger.warn('Missing required parameters for webhook signature verification');
        return false;
      }

      // Ensure payload is a buffer or string
      const payloadData = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');

      const crypto = await import('crypto');
      const expectedSignature = crypto
        .createHmac('sha256', secret)
        .update(payloadData)
        .digest('base64');

      // Use constant-time comparison to prevent timing attacks
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
  },

  // Store webhook event for tracking
  async storeWebhookEvent(event) {
    try {
      // This would store the webhook event in the database
      // For now, just log it
      logger.info('Storing webhook event:', {
        webhook_id: event.webhook_id,
        webhook_type: event.webhook_type,
        webhook_code: event.webhook_code,
        item_id: event.item_id,
      });
      return true;
    } catch (error) {
      logger.error('Error storing webhook event:', error);
      return false;
    }
  },

  // Check if webhook event was already processed
  async isWebhookProcessed(webhookId) {
    try {
      // This would check the database for duplicate processing
      // For now, return false (allow processing)
      return false;
    } catch (error) {
      logger.error('Error checking webhook processing status:', error);
      return false;
    }
  },

  // Webhook handling
  async handleWebhook(event) {
    try {
      logger.info('Received Plaid webhook:', {
        webhook_type: event.webhook_type,
        webhook_code: event.webhook_code,
        item_id: event.item_id,
        webhook_id: event.webhook_id,
      });

      // Check for duplicate processing
      if (event.webhook_id) {
        const alreadyProcessed = await this.isWebhookProcessed(event.webhook_id);
        if (alreadyProcessed) {
          logger.info('Webhook already processed, skipping:', event.webhook_id);
          return { received: true, status: 'already_processed' };
        }
      }

      // Store webhook event
      await this.storeWebhookEvent(event);

      // Process webhook based on type and code
      const result = await this.processWebhookByType(event);

      // Mark as processed if successful
      if (result.success) {
        await this.markWebhookProcessed(event.webhook_id);
      }

      return {
        received: true,
        processed: result.success,
        webhook_type: event.webhook_type,
        webhook_code: event.webhook_code,
      };
    } catch (error) {
      logger.error('Error handling webhook:', error);
      // Store error information
      await this.storeWebhookError(event, error);
      throw error;
    }
  },

  // Process webhook by type
  async processWebhookByType(event) {
    switch (event.webhook_type) {
      case 'TRANSACTIONS':
        return await this.handleTransactionWebhook(event);

      case 'ITEM':
        return await this.handleItemWebhook(event);

      case 'ASSETS':
        return await this.handleAssetWebhook(event);

      case 'HOLDINGS':
        return await this.handleHoldingsWebhook(event);

      case 'LIABILITIES':
        return await this.handleLiabilitiesWebhook(event);

      default:
        logger.info('Unhandled webhook type:', event.webhook_type);
        return { success: true, message: 'unhandled_type' };
    }
  },

  // Handle transaction webhooks
  async handleTransactionWebhook(event) {
    try {
      switch (event.webhook_code) {
        case 'INITIAL_UPDATE':
        case 'HISTORICAL_UPDATE':
        case 'DEFAULT_UPDATE':
          await this.processTransactionUpdate(event);
          return { success: true, message: 'transactions_processed' };

        case 'TRANSACTIONS_REMOVED':
          await this.processTransactionRemovals(event);
          return { success: true, message: 'transactions_removed' };

        default:
          logger.info('Unhandled transaction webhook code:', event.webhook_code);
          return { success: true, message: 'unhandled_code' };
      }
    } catch (error) {
      logger.error('Error handling transaction webhook:', error);
      return { success: false, error: error.message };
    }
  },

  // Handle item webhooks
  async handleItemWebhook(event) {
    try {
      switch (event.webhook_code) {
        case 'ERROR':
          await this.handleItemError(event);
          return { success: true, message: 'item_error_handled' };

        case 'NEW_ACCOUNTS_AVAILABLE':
          await this.handleNewAccountsAvailable(event);
          return { success: true, message: 'new_accounts_available' };

        case 'PENDING_EXPIRATION':
          await this.handlePendingExpiration(event);
          return { success: true, message: 'pending_expiration_handled' };

        case 'USER_PERMISSION_REVOKED':
          await this.handlePermissionRevoked(event);
          return { success: true, message: 'permission_revoked_handled' };

        case 'WEBHOOK_UPDATE_ACKNOWLEDGED':
          logger.info('Webhook update acknowledged for item:', event.item_id);
          return { success: true, message: 'webhook_acknowledged' };

        default:
          logger.info('Unhandled item webhook code:', event.webhook_code);
          return { success: true, message: 'unhandled_code' };
      }
    } catch (error) {
      logger.error('Error handling item webhook:', error);
      return { success: false, error: error.message };
    }
  },

  // Handle asset webhooks
  async handleAssetWebhook(event) {
    try {
      switch (event.webhook_code) {
        case 'PRODUCT_READY':
          await this.handleAssetReportReady(event);
          return { success: true, message: 'asset_report_ready' };

        case 'ERROR':
          await this.handleAssetReportError(event);
          return { success: true, message: 'asset_report_error_handled' };

        default:
          logger.info('Unhandled asset webhook code:', event.webhook_code);
          return { success: true, message: 'unhandled_code' };
      }
    } catch (error) {
      logger.error('Error handling asset webhook:', error);
      return { success: false, error: error.message };
    }
  },

  // Handle holdings webhooks
  async handleHoldingsWebhook(event) {
    try {
      // Handle holdings updates
      logger.info('Processing holdings update for item:', event.item_id);
      return { success: true, message: 'holdings_processed' };
    } catch (error) {
      logger.error('Error handling holdings webhook:', error);
      return { success: false, error: error.message };
    }
  },

  // Handle liabilities webhooks
  async handleLiabilitiesWebhook(event) {
    try {
      // Handle liabilities updates
      logger.info('Processing liabilities update for item:', event.item_id);
      return { success: true, message: 'liabilities_processed' };
    } catch (error) {
      logger.error('Error handling liabilities webhook:', error);
      return { success: false, error: error.message };
    }
  },

  // Process transaction updates
  async processTransactionUpdate(event) {
    try {
      // Get updated transactions
      const accessToken = await this.getAccessTokenForItem(event.item_id);
      if (!accessToken) return;

      const startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
        .toISOString()
        .split('T')[0];
      const endDate = new Date().toISOString().split('T')[0];

      const transactions = await this.getTransactions(
        accessToken,
        startDate,
        endDate
      );

      // Process and store transactions
      for (const transaction of transactions) {
        await this.storeTransaction(transaction);
      }

      logger.info(
        `Processed ${transactions.length} transactions for item ${event.item_id}`
      );
    } catch (error) {
      logger.error('Error processing transaction update:', error);
    }
  },

  // Handle item errors
  async handleItemError(event) {
    logger.error('Plaid item error:', event.error);
    // Handle item errors (e.g., invalid credentials, item locked)
  },

  // Additional webhook handlers
  async processTransactionRemovals(event) {
    try {
      logger.info('Processing transaction removals for item:', event.item_id);
      // Handle removed transactions
      if (event.removed_transactions) {
        for (const transactionId of event.removed_transactions) {
          await this.removeTransaction(transactionId);
        }
      }
    } catch (error) {
      logger.error('Error processing transaction removals:', error);
    }
  },

  async handleNewAccountsAvailable(event) {
    try {
      logger.info('New accounts available for item:', event.item_id);
      // Handle new accounts becoming available
      // Could trigger account sync or notifications
    } catch (error) {
      logger.error('Error handling new accounts available:', error);
    }
  },

  async handlePendingExpiration(event) {
    try {
      logger.warn('Item pending expiration:', event.item_id);
      // Handle pending item expiration
      // Could send notifications to user to re-authenticate
    } catch (error) {
      logger.error('Error handling pending expiration:', error);
    }
  },

  async handlePermissionRevoked(event) {
    try {
      logger.error('User permission revoked for item:', event.item_id);
      // Handle permission revocation
      // Could mark item as inactive or notify user
    } catch (error) {
      logger.error('Error handling permission revoked:', error);
    }
  },

  async handleAssetReportReady(event) {
    try {
      logger.info('Asset report ready:', event.asset_report_id);
      // Handle asset report being ready for retrieval
    } catch (error) {
      logger.error('Error handling asset report ready:', error);
    }
  },

  async handleAssetReportError(event) {
    try {
      logger.error('Asset report error:', event.error);
      // Handle asset report generation errors
    } catch (error) {
      logger.error('Error handling asset report error:', error);
    }
  },

  // Additional helper methods
  async markWebhookProcessed(webhookId) {
    try {
      // Mark webhook as processed in database
      logger.info('Marked webhook as processed:', webhookId);
    } catch (error) {
      logger.error('Error marking webhook as processed:', error);
    }
  },

  async storeWebhookError(event, error) {
    try {
      // Store webhook processing error
      logger.error('Stored webhook error:', {
        webhook_id: event.webhook_id,
        error: error.message,
      });
    } catch (storeError) {
      logger.error('Error storing webhook error:', storeError);
    }
  },

  async removeTransaction(transactionId) {
    try {
      // Remove transaction from database
      logger.info('Removing transaction:', transactionId);
    } catch (error) {
      logger.error('Error removing transaction:', error);
    }
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
/ /   G e t   b a n k   t r a n s f e r   e v e n t s  
     a s y n c   g e t B a n k T r a n s f e r E v e n t s ( a c c e s s T o k e n ,   o p t i o n s   =   { } )   {  
         i f   ( ! p l a i d C l i e n t )   {  
             t h r o w   n e w   E r r o r ( ' P l a i d   c l i e n t   n o t   c o n f i g u r e d ' ) ;  
         }  
  
         t r y   {  
             c o n s t   r e q u e s t   =   {  
                 a c c e s s _ t o k e n :   a c c e s s T o k e n ,  
                 s t a r t _ d a t e :   o p t i o n s . s t a r t D a t e ,  
                 e n d _ d a t e :   o p t i o n s . e n d D a t e ,  
                 t r a n s f e r _ i d :   o p t i o n s . t r a n s f e r I d ,  
                 a c c o u n t _ i d :   o p t i o n s . a c c o u n t I d ,  
                 t r a n s f e r _ t y p e :   o p t i o n s . t r a n s f e r T y p e ,  
                 e v e n t _ t y p e s :   o p t i o n s . e v e n t T y p e s ,  
                 c o u n t :   o p t i o n s . c o u n t   | |   2 5 ,  
                 o f f s e t :   o p t i o n s . o f f s e t   | |   0 ,  
                 . . . o p t i o n s ,  
             } ;  
  
             / /   R e m o v e   u n d e f i n e d   v a l u e s  
             O b j e c t . k e y s ( r e q u e s t ) . f o r E a c h ( k e y   = >   {  
                 i f   ( r e q u e s t [ k e y ]   = = =   u n d e f i n e d )   {  
                     d e l e t e   r e q u e s t [ k e y ] ;  
                 }  
             } ) ;  
  
             c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . t r a n s f e r E v e n t L i s t ( r e q u e s t ) ;  
             r e t u r n   r e s p o n s e . d a t a ;  
         }   c a t c h   ( e r r o r )   {  
             l o g g e r . e r r o r ( ' E r r o r   g e t t i n g   b a n k   t r a n s f e r   e v e n t s : ' ,   e r r o r ) ;  
             t h r o w   n e w   E r r o r ( ' F a i l e d   t o   g e t   b a n k   t r a n s f e r   e v e n t s ' ) ;  
         }  
     } ,  
 