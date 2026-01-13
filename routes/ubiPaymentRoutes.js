// UBI Payment Routes
import express from 'express';
import ubiPaymentService from '../services/ubiPaymentService.js';
import { info } from '../utils/loggerWrapper.js';

const router = express.Router();

router.post('/process/:citizenId', async (req, res, next) => {
  try {
    const payment = await ubiPaymentService.processPayment(req.params.citizenId);
    res.json({ success: true, payment });
  } catch (err) {
    next(err);
  }
});

router.get('/history/:citizenId', async (req, res, next) => {
  try {
    const history = await ubiPaymentService.getPaymentHistory(req.params.citizenId);
    res.json({ success: true, history });
  } catch (err) {
    next(err);
  }
});

export default router;
