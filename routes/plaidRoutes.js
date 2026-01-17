import express from 'express';
import plaidService from '../services/plaidService.js';
import { authenticateToken } from '../../config/security.js';

const router = express.Router();

// Create link token for account linking
router.post('/create-link-token', authenticateToken, async (req, res) => {
  try {
    const { userId, products } = req.body;

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: 'User ID is required',
      });
    }

    const linkTokenData = await plaidService.createLinkToken(userId, products);

    res.json({
      success: true,
      data: linkTokenData,
    });
  } catch (error) {
    logger.error('Error creating link token:', error);
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
    logger.error('Error exchanging public token:', error);
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
    logger.error('Error getting accounts:', error);
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
    logger.error('Error getting balances:', error);
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
    logger.error('Error getting transactions:', error);
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
    logger.error('Error getting income:', error);
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
    logger.error('Error getting auth:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get auth',
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
    logger.error('Error verifying account ownership:', error);
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
    logger.error('Error getting identity:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get identity',
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
    logger.error('Error removing item:', error);
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
    logger.error('Error getting institutions:', error);
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
    logger.error('Error getting webhook verification key:', error);
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
          logger.error('Failed to retrieve webhook verification key:', error);
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
          logger.warn('Invalid webhook signature received');
          return res.status(401).json({
            success: false,
            message: 'Invalid webhook signature',
          });
        }
      }

      const event = JSON.parse(rawBody);

      // Validate webhook event structure
      if (!event.webhook_type || !event.webhook_code) {
        logger.warn('Invalid webhook event structure:', event);
        return res.status(400).json({
          success: false,
          message: 'Invalid webhook event structure',
        });
      }

      const result = await plaidService.handleWebhook(event);

      res.json(result);
    } catch (error) {
      logger.error('Error handling webhook:', error);
      res.status(500).json({
        success: false,
        message: 'Webhook processing failed',
        error: error.message,
      });
    }
  }
);

export default router;
/ /   G e t   b a n k   t r a n s f e r   e v e n t s  
 r o u t e r . g e t ( ' / t r a n s f e r - e v e n t s / : a c c e s s T o k e n ' ,   a u t h e n t i c a t e T o k e n ,   a s y n c   ( r e q ,   r e s )   = >   {  
     t r y   {  
         c o n s t   {   a c c e s s T o k e n   }   =   r e q . p a r a m s ;  
         c o n s t   {   s t a r t D a t e ,   e n d D a t e ,   t r a n s f e r I d ,   a c c o u n t I d ,   t r a n s f e r T y p e ,   e v e n t T y p e s ,   c o u n t ,   o f f s e t   }   =   r e q . q u e r y ;  
  
         c o n s t   o p t i o n s   =   {  
             s t a r t D a t e ,  
             e n d D a t e ,  
             t r a n s f e r I d ,  
             a c c o u n t I d ,  
             t r a n s f e r T y p e ,  
             e v e n t T y p e s :   e v e n t T y p e s   ?   e v e n t T y p e s . s p l i t ( ' , ' )   :   u n d e f i n e d ,  
             c o u n t :   c o u n t   ?   p a r s e I n t ( c o u n t )   :   u n d e f i n e d ,  
             o f f s e t :   o f f s e t   ?   p a r s e I n t ( o f f s e t )   :   u n d e f i n e d ,  
         } ;  
  
         c o n s t   t r a n s f e r E v e n t s   =   a w a i t   p l a i d S e r v i c e . g e t B a n k T r a n s f e r E v e n t s ( a c c e s s T o k e n ,   o p t i o n s ) ;  
  
         r e s . j s o n ( {  
             s u c c e s s :   t r u e ,  
             d a t a :   t r a n s f e r E v e n t s ,  
         } ) ;  
     }   c a t c h   ( e r r o r )   {  
         l o g g e r . e r r o r ( ' E r r o r   g e t t i n g   b a n k   t r a n s f e r   e v e n t s : ' ,   e r r o r ) ;  
         r e s . s t a t u s ( 5 0 0 ) . j s o n ( {  
             s u c c e s s :   f a l s e ,  
             m e s s a g e :   ' F a i l e d   t o   g e t   b a n k   t r a n s f e r   e v e n t s ' ,  
             e r r o r :   e r r o r . m e s s a g e ,  
         } ) ;  
     }  
 } ) ;  
 