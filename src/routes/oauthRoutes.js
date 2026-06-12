import { Router } from 'express';
import { fetchOAuthToken } from '../services/jpmOAuthService.js';

const router = Router();

router.post('/token', async (req, res, next) => {
  try {
    const data = await fetchOAuthToken(req.requestId);

    res.json({
      ok: true,
      token_type: data.token_type,
      expires_in: data.expires_in,
      access_token: data.access_token,
      requestId: req.requestId
    });
  } catch (err) {
    next(err);
  }
});

export default router;
