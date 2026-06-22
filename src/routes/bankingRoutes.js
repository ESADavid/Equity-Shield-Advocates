import { Router } from 'express';
import { validateBankingSetupPayload, generateBankingSetupPlan } from '../services/bankingSetupService.js';
import { authGuard } from '../middleware/authGuard.js';

const router = Router();

/**
 * POST /api/banking/setup
 * Accepts entity payload and returns setup plan
 * Requires authentication
 */
router.post('/setup', authGuard, async (req, res, next) => {
  try {
    const payload = req.body;
    
    // Validate payload
    const validation = validateBankingSetupPayload(payload);
    
    if (!validation.valid) {
      return res.status(400).json({
        error: 'Validation Failed',
        messages: validation.errors
      });
    }
    
    // Generate setup plan
    const plan = generateBankingSetupPlan(payload);
    
    res.json({
      ok: true,
      plan
    });
  } catch (err) {
    next(err);
  }
});

export default router;
