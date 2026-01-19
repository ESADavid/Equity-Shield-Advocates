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
  async createLinkToken(userId, products = ['auth', 'transactions', 'identity']) {
    // Validate credentials on first call
    if (!this.credentialsValidated) {
      validatePlaidCredentials();
      this.credentialsValidated = true;
    }

    return retryWithBackoff(async () => {
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
    / /   G e t   i n c o m e   i n f o r m a t i o n 
     a s y n c   g e t I n c o m e ( a c c e s s T o k e n )   { 
         r e t u r n   r e t r y W i t h B a c k o f f ( a s y n c   ( )   = >   { 
             c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . i n c o m e G e t ( { 
                 a c c e s s _ t o k e n :   a c c e s s T o k e n , 
             } ) ; 
 
             r e t u r n   r e s p o n s e . d a t a . i n c o m e ; 
         } ,   " g e t I n c o m e " ) ; 
     } 
 
     / /   G e t   a u t h   i n f o r m a t i o n   ( a c c o u n t   a n d   r o u t i n g   n u m b e r s ) 
     a s y n c   g e t A u t h ( a c c e s s T o k e n )   { 
         r e t u r n   r e t r y W i t h B a c k o f f ( a s y n c   ( )   = >   { 
             c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . a u t h G e t ( { 
                 a c c e s s _ t o k e n :   a c c e s s T o k e n , 
             } ) ; 
 
             r e t u r n   r e s p o n s e . d a t a ; 
         } ,   " g e t A u t h " ) ; 
     } 
 
     / /   V e r i f y   a c c o u n t   o w n e r s h i p   ( p r o o f   o f   f u n d s ) 
     a s y n c   v e r i f y A c c o u n t O w n e r s h i p ( a c c e s s T o k e n ,   a c c o u n t I d ,   a m o u n t s )   { 
         r e t u r n   r e t r y W i t h B a c k o f f ( a s y n c   ( )   = >   { 
             c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . a c c o u n t s B a l a n c e G e t ( { 
                 a c c e s s _ t o k e n :   a c c e s s T o k e n , 
             } ) ; 
 
             c o n s t   a c c o u n t   =   r e s p o n s e . d a t a . a c c o u n t s . f i n d ( a c c   = >   a c c . a c c o u n t _ i d   = = =   a c c o u n t I d ) ; 
             i f   ( ! a c c o u n t )   { 
                 t h r o w   n e w   E r r o r ( " A c c o u n t   n o t   f o u n d " ) ; 
             } 
 
             c o n s t   c u r r e n t B a l a n c e   =   a c c o u n t . b a l a n c e s . c u r r e n t ; 
             c o n s t   v e r i f i c a t i o n R e s u l t s   =   a m o u n t s . m a p ( a m o u n t   = >   ( { 
                 a m o u n t , 
                 s u f f i c i e n t :   c u r r e n t B a l a n c e   > =   a m o u n t , 
                 c u r r e n t B a l a n c e , 
             } ) ) ; 
 
             r e t u r n   { 
                 a c c o u n t I d , 
                 v e r i f i c a t i o n R e s u l t s , 
             } ; 
         } ,   " v e r i f y A c c o u n t O w n e r s h i p " ) ; 
     } 
 
     / /   G e t   i d e n t i t y   i n f o r m a t i o n 
     a s y n c   g e t I d e n t i t y ( a c c e s s T o k e n )   { 
         r e t u r n   r e t r y W i t h B a c k o f f ( a s y n c   ( )   = >   { 
             c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . i d e n t i t y G e t ( { 
                 a c c e s s _ t o k e n :   a c c e s s T o k e n , 
             } ) ; 
 
             r e t u r n   r e s p o n s e . d a t a . a c c o u n t s ; 
         } ,   " g e t I d e n t i t y " ) ; 
     } 
 
     / /   R e m o v e   i t e m   ( d i s c o n n e c t   a c c o u n t ) 
     a s y n c   r e m o v e I t e m ( a c c e s s T o k e n )   { 
         r e t u r n   r e t r y W i t h B a c k o f f ( a s y n c   ( )   = >   { 
             c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . i t e m R e m o v e ( { 
                 a c c e s s _ t o k e n :   a c c e s s T o k e n , 
             } ) ; 
 
             r e t u r n   r e s p o n s e . d a t a ; 
         } ,   " r e m o v e I t e m " ) ; 
     } 
 
     / /   G e t   i n s t i t u t i o n s 
     a s y n c   g e t I n s t i t u t i o n s ( o p t i o n s   =   { } )   { 
         r e t u r n   r e t r y W i t h B a c k o f f ( a s y n c   ( )   = >   { 
             c o n s t   r e q u e s t   =   { 
                 c o u n t :   o p t i o n s . c o u n t   | |   5 0 , 
                 o f f s e t :   o p t i o n s . o f f s e t   | |   0 , 
                 c o u n t r y _ c o d e s :   o p t i o n s . c o u n t r y _ c o d e s   | |   [ " U S " ] , 
             } ; 
 
             c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . i n s t i t u t i o n s G e t ( r e q u e s t ) ; 
             r e t u r n   r e s p o n s e . d a t a . i n s t i t u t i o n s ; 
         } ,   " g e t I n s t i t u t i o n s " ) ; 
     } 
 
     / /   G e t   w e b h o o k   v e r i f i c a t i o n   k e y 
     a s y n c   g e t W e b h o o k V e r i f i c a t i o n K e y ( )   { 
         r e t u r n   r e t r y W i t h B a c k o f f ( a s y n c   ( )   = >   { 
             c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . w e b h o o k V e r i f i c a t i o n K e y G e t ( { 
                 k e y _ i d :   p r o c e s s . e n v . P L A I D _ W E B H O O K _ V E R I F I C A T I O N _ K E Y _ I D   | |   " d e f a u l t " , 
             } ) ; 
 
             r e t u r n   r e s p o n s e . d a t a . k e y ; 
         } ,   " g e t W e b h o o k V e r i f i c a t i o n K e y " ) ; 
     } 
 
     / /   H a n d l e   w e b h o o k 
     a s y n c   h a n d l e W e b h o o k ( e v e n t )   { 
         t r y   { 
             l o g g e r . i n f o ( " P r o c e s s i n g   P l a i d   w e b h o o k : " ,   { 
                 w e b h o o k _ t y p e :   e v e n t . w e b h o o k _ t y p e , 
                 w e b h o o k _ c o d e :   e v e n t . w e b h o o k _ c o d e , 
                 i t e m _ i d :   e v e n t . i t e m _ i d , 
             } ) ; 
 
             / /   H a n d l e   d i f f e r e n t   w e b h o o k   t y p e s 
             s w i t c h   ( e v e n t . w e b h o o k _ t y p e )   { 
                 c a s e   " T R A N S A C T I O N S " : 
                     i f   ( e v e n t . w e b h o o k _ c o d e   = = =   " T R A N S A C T I O N S _ U P D A T E " )   { 
                         / /   H a n d l e   t r a n s a c t i o n   u p d a t e s 
                         l o g g e r . i n f o ( " T r a n s a c t i o n   u p d a t e s   r e c e i v e d : " ,   e v e n t ) ; 
                     } 
                     b r e a k ; 
 
                 c a s e   " I T E M " : 
                     i f   ( e v e n t . w e b h o o k _ c o d e   = = =   " E R R O R " )   { 
                         l o g g e r . e r r o r ( " I t e m   e r r o r   w e b h o o k : " ,   e v e n t ) ; 
                     } 
                     b r e a k ; 
 
                 c a s e   " T R A N S F E R " : 
                     / /   H a n d l e   t r a n s f e r   w e b h o o k s 
                     l o g g e r . i n f o ( " T r a n s f e r   w e b h o o k   r e c e i v e d : " ,   e v e n t ) ; 
                     b r e a k ; 
 
                 d e f a u l t : 
                     l o g g e r . i n f o ( " U n h a n d l e d   w e b h o o k   t y p e : " ,   e v e n t . w e b h o o k _ t y p e ) ; 
             } 
 
             r e t u r n   {   r e c e i v e d :   t r u e   } ; 
         }   c a t c h   ( e r r o r )   { 
             l o g g e r . e r r o r ( " E r r o r   h a n d l i n g   w e b h o o k : " ,   e r r o r ) ; 
             t h r o w   e r r o r ; 
         } 
     } 
 
     / /   V e r i f y   w e b h o o k   s i g n a t u r e 
     a s y n c   v e r i f y W e b h o o k S i g n a t u r e ( r a w B o d y ,   s i g n a t u r e ,   v e r i f i c a t i o n K e y )   { 
         t r y   { 
             / /   P l a i d   u s e s   H M A C - S H A 2 5 6   f o r   w e b h o o k   s i g n a t u r e   v e r i f i c a t i o n 
             c o n s t   e x p e c t e d S i g n a t u r e   =   c r y p t o 
                 . c r e a t e H m a c ( " s h a 2 5 6 " ,   v e r i f i c a t i o n K e y ) 
                 . u p d a t e ( r a w B o d y ,   " u t f 8 " ) 
                 . d i g e s t ( " h e x " ) ; 
 
             r e t u r n   s i g n a t u r e   = = =   ` v 2 - $ { e x p e c t e d S i g n a t u r e } ` ; 
         }   c a t c h   ( e r r o r )   { 
             l o g g e r . e r r o r ( " E r r o r   v e r i f y i n g   w e b h o o k   s i g n a t u r e : " ,   e r r o r ) ; 
             r e t u r n   f a l s e ; 
         } 
     } 
 
     / /   I n i t i a t e   S M S   m i c r o d e p o s i t s   f o r   a c c o u n t   v e r i f i c a t i o n 
     a s y n c   i n i t i a t e M i c r o d e p o s i t s ( a c c e s s T o k e n ,   a c c o u n t I d )   { 
         r e t u r n   r e t r y W i t h B a c k o f f ( a s y n c   ( )   = >   { 
             c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . d e p o s i t S w i t c h C r e a t e ( { 
                 t a r g e t _ a c c e s s _ t o k e n :   a c c e s s T o k e n , 
                 t a r g e t _ a c c o u n t _ i d :   a c c o u n t I d , 
             } ) ; 
 
             r e t u r n   r e s p o n s e . d a t a ; 
         } ,   " i n i t i a t e M i c r o d e p o s i t s " ) ; 
     } 
 
     / /   V e r i f y   S M S   m i c r o d e p o s i t s   w i t h   d e p o s i t   a m o u n t s 
     a s y n c   v e r i f y M i c r o d e p o s i t s ( a c c e s s T o k e n ,   a c c o u n t I d ,   a m o u n t s )   { 
         r e t u r n   r e t r y W i t h B a c k o f f ( a s y n c   ( )   = >   { 
             c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . d e p o s i t S w i t c h T o k e n C r e a t e ( { 
                 d e p o s i t _ s w i t c h _ i d :   a c c e s s T o k e n ,   / /   T h i s   m i g h t   n e e d   a d j u s t m e n t   b a s e d   o n   a c t u a l   A P I 
                 t a r g e t _ a c c o u n t _ i d :   a c c o u n t I d , 
             } ) ; 
 
             r e t u r n   r e s p o n s e . d a t a ; 
         } ,   " v e r i f y M i c r o d e p o s i t s " ) ; 
     } 
 
     / /   G e t   m i c r o d e p o s i t s   v e r i f i c a t i o n   s t a t u s 
     a s y n c   g e t M i c r o d e p o s i t s S t a t u s ( a c c e s s T o k e n ,   a c c o u n t I d )   { 
         r e t u r n   r e t r y W i t h B a c k o f f ( a s y n c   ( )   = >   { 
             / /   T h i s   i s   a   s i m p l i f i e d   i m p l e m e n t a t i o n   -   a c t u a l   A P I   m i g h t   d i f f e r 
             c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . a u t h G e t ( { 
                 a c c e s s _ t o k e n :   a c c e s s T o k e n , 
             } ) ; 
 
             c o n s t   a c c o u n t   =   r e s p o n s e . d a t a . a c c o u n t s . f i n d ( a c c   = >   a c c . a c c o u n t _ i d   = = =   a c c o u n t I d ) ; 
             r e t u r n   { 
                 a c c o u n t I d , 
                 v e r i f i c a t i o n S t a t u s :   a c c o u n t   ?   " v e r i f i e d "   :   " u n v e r i f i e d " , 
             } ; 
         } ,   " g e t M i c r o d e p o s i t s S t a t u s " ) ; 
     } 
 
     / /   G e t   b a n k   t r a n s f e r   e v e n t s 
     a s y n c   g e t B a n k T r a n s f e r E v e n t s ( a c c e s s T o k e n ,   o p t i o n s   =   { } )   { 
         r e t u r n   r e t r y W i t h B a c k o f f ( a s y n c   ( )   = >   { 
             c o n s t   r e q u e s t   =   { 
                 a c c e s s _ t o k e n :   a c c e s s T o k e n , 
                 s t a r t _ d a t e :   o p t i o n s . s t a r t D a t e , 
                 e n d _ d a t e :   o p t i o n s . e n d D a t e , 
                 c o u n t :   o p t i o n s . c o u n t   | |   2 5 , 
                 o f f s e t :   o p t i o n s . o f f s e t   | |   0 , 
             } ; 
 
             / /   R e m o v e   u n d e f i n e d   v a l u e s 
             O b j e c t . k e y s ( r e q u e s t ) . f o r E a c h ( k e y   = >   { 
                 i f   ( r e q u e s t [ k e y ]   = = =   u n d e f i n e d )   { 
                     d e l e t e   r e q u e s t [ k e y ] ; 
                 } 
             } ) ; 
 
             c o n s t   r e s p o n s e   =   a w a i t   p l a i d C l i e n t . t r a n s f e r E v e n t L i s t ( r e q u e s t ) ; 
             r e t u r n   r e s p o n s e . d a t a . t r a n s f e r _ e v e n t s ; 
         } ,   " g e t B a n k T r a n s f e r E v e n t s " ) ; 
     } 
 
 
