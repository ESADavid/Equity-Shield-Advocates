import { Router } from 'express';
import { fetchOAuthToken } from '../services/jpmOAuthService.js';

const router = Router();

/**
 * POST /api/oauth/token
 * Triggers client-credentials token request to JPM OAuth
 * Returns sanitized response (no secrets)
 */
router.post('/token', async (req, res, next) => {
  try {
    const data = await fetchOAuthToken();
    
    // Return sanitized response - never echo secrets
    res.json({
      ok: true,
      token_type: data.token_type,
      expires_in: data.expires_in,
      scope: data.scope
    });
  } catch (err) {
    next(err);
  }
});

export default router;
