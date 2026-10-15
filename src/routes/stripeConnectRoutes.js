import { Router } from 'express';
import { authGuard } from '../middleware/authGuard.js';
import {
  createConnectedAccount,
  createOnboardingSession,
  refreshConnectedAccountStatus
} from '../services/stripeConnectService.js';

const router = Router();

router.use(authGuard);

router.post('/accounts', async (req, res, next) => {
  try {
    const { providerId, contactEmail, displayName } = req.body ?? {};
    if (
      typeof providerId !== 'string' ||
      providerId.trim().length === 0 ||
      providerId.length > 128 ||
      typeof contactEmail !== 'string' ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactEmail) ||
      typeof displayName !== 'string' ||
      displayName.trim().length === 0 ||
      displayName.length > 200
    ) {
      return res.status(400).json({
        error: 'Validation Failed',
        message: 'providerId, a valid contactEmail, and displayName are required'
      });
    }

    const account = await createConnectedAccount({
      providerId: providerId.trim(),
      contactEmail: contactEmail.trim(),
      displayName: displayName.trim()
    });

    res.status(201).json({
      ok: true,
      providerId: account.provider_id,
      stripeAccountId: account.stripe_account_id,
      cardPaymentsStatus: account.card_payments_status
    });
  } catch (error) {
    next(error);
  }
});

router.post('/accounts/:providerId/onboarding-session', async (req, res, next) => {
  try {
    const session = await createOnboardingSession(req.params.providerId);
    res.json({
      ok: true,
      ...session
    });
  } catch (error) {
    next(error);
  }
});

router.get('/accounts/:providerId/status', async (req, res, next) => {
  try {
    const status = await refreshConnectedAccountStatus(req.params.providerId);
    res.json({
      ok: true,
      ...status
    });
  } catch (error) {
    next(error);
  }
});

export default router;
