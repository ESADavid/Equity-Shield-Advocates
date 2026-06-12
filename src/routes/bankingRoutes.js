import { Router } from 'express';
import { buildBankingSetupPlan, buildFamilyTrustIntegrationPlan } from '../services/bankingSetupService.js';
import { pingJpmSandbox } from '../services/jpmApiClient.js';
import { authGuard } from '../middleware/authGuard.js';
import { listTransactions } from '../services/transactionsService.js';

const router = Router();

router.post('/setup', (req, res, next) => {
  try {
    const plan = buildBankingSetupPlan(req.body);
    return res.json({
      ok: true,
      plan,
      requestId: req.requestId
    });
  } catch (err) {
    if (err.validationErrors) {
      return res.status(400).json({
        ok: false,
        error: err.publicMessage || 'Validation failed',
        details: err.validationErrors,
        requestId: req.requestId
      });
    }
    return next(err);
  }
});

router.post('/setup/family-trust', (req, res, next) => {
  try {
    const plan = buildFamilyTrustIntegrationPlan(req.body);
    return res.json({
      ok: true,
      plan,
      requestId: req.requestId
    });
  } catch (err) {
    if (err.validationErrors) {
      return res.status(400).json({
        ok: false,
        error: err.publicMessage || 'Validation failed',
        details: err.validationErrors,
        requestId: req.requestId
      });
    }
    return next(err);
  }
});

router.get('/ping', authGuard, async (req, res, next) => {
  try {
    const result = await pingJpmSandbox(req.requestId);
    return res.json({
      ok: true,
      result,
      requestId: req.requestId
    });
  } catch (err) {
    return next(err);
  }
});

router.get('/transactions', authGuard, (req, res, next) => {
  try {
    const result = listTransactions(req.query);
    return res.json({
      ok: true,
      ...result,
      requestId: req.requestId
    });
  } catch (err) {
    if (err.validationErrors) {
      return res.status(400).json({
        ok: false,
        error: err.publicMessage || 'Validation failed',
        details: err.validationErrors,
        requestId: req.requestId
      });
    }
    return next(err);
  }
});

export default router;
