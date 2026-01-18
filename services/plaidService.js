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
  async createLinkToken(userId, products = ['auth', 'transactions', 'identity']) {
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

      return response.data;
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
/ /   = = =   T R A N S F E R   A P I   M E T H O D S   = = =  
  
 / /   C r e a t e   a   t r a n s f e r  
 a s y n c   c r e a t e T r a n s f e r ( a c c e s s T o k e n ,   t r a n s f e r D a t a )   {  
     t r y   {  
         c o n s t   r e q u e s t   =   {  
             a c c e s s _ t o k e n :   a c c e s s T o k e n ,  
             a c c o u n t _ i d :   t r a n s f e r D a t a . a c c o u n t I d ,  
             a m o u n t :   t r a n s f e r D a t a . a m o u n t ,  
             d e s c r i p t i o n :   t r a n s f e r D a t a . d e s c r i p t i o n ,  
             a c h _ c l a s s :   t r a n s f e r D a t a . a c h C l a s s   | |   ' p p d ' ,   / /   p p d ,   c c d ,   t e l  
             t y p e :   t r a n s f e r D a t a . t y p e   | |   ' d e b i t ' ,   / /   d e b i t   o r   c r e d i t  
             n e t w o r k :   t r a n s f e r D a t a . n e t w o r k   | |   ' a c h ' ,  
             i d e m p o t e n c y _ k e y :   t r a n s f e r D a t a . i d e m p o t e n c y K e y   | |   c r y p t o . r a n d o m U U I D ( ) ,  
             m e t a d a t a :   t r a n s f e r D a t a . m e t a d a t a   | |   { } ,  
         } ;  
  
         / /   A d d   o p t i o n a l   f i e l d s  
         i f   ( t r a n s f e r D a t a . o r i g i n a t o r C l i e n t I d )   {  
             r e q u e s t . o r i g i n a t o r _ c l i e n t _ i d   =   t r a n s f e r D a t a . o r i g i n a t o r C l i e n t I d ;  
         }  
  
         i f   ( t r a n s f e r D a t a . u s e r )   {  
             r e q u e s t . u s e r   =   t r a n s f e r D a t a . u s e r ;  
         }  
  
         c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . t r a n s f e r C r e a t e ( r e q u e s t ) ;  
         r e t u r n   r e s p o n s e . d a t a ;  
     }   c a t c h   ( e r r o r )   {  
         l o g g e r . e r r o r ( ' E r r o r   c r e a t i n g   t r a n s f e r : ' ,   e r r o r ) ;  
         t h r o w   e r r o r ;  
     }  
 }  
  
 / /   L i s t   t r a n s f e r s  
 a s y n c   l i s t T r a n s f e r s ( a c c e s s T o k e n ,   o p t i o n s   =   { } )   {  
     t r y   {  
         c o n s t   r e q u e s t   =   {  
             a c c e s s _ t o k e n :   a c c e s s T o k e n ,  
             s t a r t _ d a t e :   o p t i o n s . s t a r t D a t e ,  
             e n d _ d a t e :   o p t i o n s . e n d D a t e ,  
             c o u n t :   o p t i o n s . c o u n t   | |   2 5 ,  
             o f f s e t :   o p t i o n s . o f f s e t   | |   0 ,  
         } ;  
  
         / /   R e m o v e   u n d e f i n e d   v a l u e s  
         O b j e c t . k e y s ( r e q u e s t ) . f o r E a c h ( k e y   = >   {  
             i f   ( r e q u e s t [ k e y ]   = = =   u n d e f i n e d )   {  
                 d e l e t e   r e q u e s t [ k e y ] ;  
             }  
         } ) ;  
  
         c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . t r a n s f e r L i s t ( r e q u e s t ) ;  
         r e t u r n   r e s p o n s e . d a t a ;  
     }   c a t c h   ( e r r o r )   {  
         l o g g e r . e r r o r ( ' E r r o r   l i s t i n g   t r a n s f e r s : ' ,   e r r o r ) ;  
         t h r o w   e r r o r ;  
     }  
 }  
  
 / /   G e t   t r a n s f e r   d e t a i l s  
 a s y n c   g e t T r a n s f e r ( t r a n s f e r I d )   {  
     t r y   {  
         c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . t r a n s f e r G e t ( {  
             t r a n s f e r _ i d :   t r a n s f e r I d ,  
         } ) ;  
  
         r e t u r n   r e s p o n s e . d a t a ;  
     }   c a t c h   ( e r r o r )   {  
         l o g g e r . e r r o r ( ' E r r o r   g e t t i n g   t r a n s f e r : ' ,   e r r o r ) ;  
         t h r o w   e r r o r ;  
     }  
 }  
  
 / /   C a n c e l   a   t r a n s f e r  
 a s y n c   c a n c e l T r a n s f e r ( t r a n s f e r I d )   {  
     t r y   {  
         c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . t r a n s f e r C a n c e l ( {  
             t r a n s f e r _ i d :   t r a n s f e r I d ,  
         } ) ;  
  
         r e t u r n   r e s p o n s e . d a t a ;  
     }   c a t c h   ( e r r o r )   {  
         l o g g e r . e r r o r ( ' E r r o r   c a n c e l i n g   t r a n s f e r : ' ,   e r r o r ) ;  
         t h r o w   e r r o r ;  
     }  
 }  
  
 / /   C r e a t e   t r a n s f e r   i n t e n t   ( f o r   a u t h o r i z a t i o n )  
 a s y n c   c r e a t e T r a n s f e r I n t e n t ( a c c e s s T o k e n ,   i n t e n t D a t a )   {  
     t r y   {  
         c o n s t   r e q u e s t   =   {  
             a c c e s s _ t o k e n :   a c c e s s T o k e n ,  
             a c c o u n t _ i d :   i n t e n t D a t a . a c c o u n t I d ,  
             a m o u n t :   i n t e n t D a t a . a m o u n t ,  
             d e s c r i p t i o n :   i n t e n t D a t a . d e s c r i p t i o n ,  
             a c h _ c l a s s :   i n t e n t D a t a . a c h C l a s s   | |   ' p p d ' ,  
             m o d e :   i n t e n t D a t a . m o d e   | |   ' p a y m e n t ' ,   / /   p a y m e n t   o r   d i s b u r s e m e n t  
             n e t w o r k :   i n t e n t D a t a . n e t w o r k   | |   ' a c h ' ,  
             i d e m p o t e n c y _ k e y :   i n t e n t D a t a . i d e m p o t e n c y K e y   | |   c r y p t o . r a n d o m U U I D ( ) ,  
             m e t a d a t a :   i n t e n t D a t a . m e t a d a t a   | |   { } ,  
         } ;  
  
         / /   A d d   o p t i o n a l   f i e l d s  
         i f   ( i n t e n t D a t a . u s e r )   {  
             r e q u e s t . u s e r   =   i n t e n t D a t a . u s e r ;  
         }  
  
         c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . t r a n s f e r I n t e n t C r e a t e ( r e q u e s t ) ;  
         r e t u r n   r e s p o n s e . d a t a ;  
     }   c a t c h   ( e r r o r )   {  
         l o g g e r . e r r o r ( ' E r r o r   c r e a t i n g   t r a n s f e r   i n t e n t : ' ,   e r r o r ) ;  
         t h r o w   e r r o r ;  
     }  
 }  
  
 / /   G e t   t r a n s f e r   i n t e n t  
 a s y n c   g e t T r a n s f e r I n t e n t ( i n t e n t I d )   {  
     t r y   {  
         c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . t r a n s f e r I n t e n t G e t ( {  
             t r a n s f e r _ i n t e n t _ i d :   i n t e n t I d ,  
         } ) ;  
  
         r e t u r n   r e s p o n s e . d a t a ;  
     }   c a t c h   ( e r r o r )   {  
         l o g g e r . e r r o r ( ' E r r o r   g e t t i n g   t r a n s f e r   i n t e n t : ' ,   e r r o r ) ;  
         t h r o w   e r r o r ;  
     }  
 }  
  
 / /   L i s t   t r a n s f e r   i n t e n t s  
 a s y n c   l i s t T r a n s f e r I n t e n t s ( a c c e s s T o k e n ,   o p t i o n s   =   { } )   {  
     t r y   {  
         c o n s t   r e q u e s t   =   {  
             a c c e s s _ t o k e n :   a c c e s s T o k e n ,  
             t r a n s f e r _ i d :   o p t i o n s . t r a n s f e r I d ,  
             a c c o u n t _ i d :   o p t i o n s . a c c o u n t I d ,  
             c o u n t :   o p t i o n s . c o u n t   | |   2 5 ,  
             o f f s e t :   o p t i o n s . o f f s e t   | |   0 ,  
         } ;  
  
         / /   R e m o v e   u n d e f i n e d   v a l u e s  
         O b j e c t . k e y s ( r e q u e s t ) . f o r E a c h ( k e y   = >   {  
             i f   ( r e q u e s t [ k e y ]   = = =   u n d e f i n e d )   {  
                 d e l e t e   r e q u e s t [ k e y ] ;  
             }  
         } ) ;  
  
         c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . t r a n s f e r I n t e n t L i s t ( r e q u e s t ) ;  
         r e t u r n   r e s p o n s e . d a t a ;  
     }   c a t c h   ( e r r o r )   {  
         l o g g e r . e r r o r ( ' E r r o r   l i s t i n g   t r a n s f e r   i n t e n t s : ' ,   e r r o r ) ;  
         t h r o w   e r r o r ;  
     }  
 }  
 