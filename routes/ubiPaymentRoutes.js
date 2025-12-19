/**
 * UBI Payment Routes
 * API endpoints for Universal Basic Income payments
 */

import express from 'express';
import ubiPaymentService from '../services/ubiPaymentService.js';
import { info } from '../utils/loggerWrapper.js';

const router = express.Router();

/**
 * POST /api/ubi-payments/process/:citizenId
 * Process UBI payment for a citizen
 */
router.post('/process/:citizenId', async (req, res, next) => {
  try {
    info(`Processing UBI payment for citizen: ${req.params.citizenId}`);
    const payment = await ubiPaymentService.processPayment(req.params.citizenId);
    res.json({ 
      success: true, 
      payment,
      message: 'UBI payment initiated successfully'
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/ubi-payments/history/:citizenId
 * Get payment history for a citizen
 */
router.get('/history/:citizenId', async (req, res, next) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const history = await ubiPaymentService.getPaymentHistory(req.params.citizenId, limit);
    res.json({ 
      success: true, 
      history, 
      count: history.length 
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/ubi-payments/status/:paymentId
 * Get status of a specific payment
 */
router.get('/status/:paymentId', async (req, res, next) => {
  try {
    const payment = await ubiPaymentService.getPaymentStatus(req.params.paymentId);
    res.json({ 
      success: true, 
      payment 
    });
  } catch (err) {
    if (err.message === 'Payment not found') {
      return res.status(404).json({ 
        success: false, 
        message: 'Payment not found' 
      });
    }
    next(err);
  }
});

/**
 * GET /api/ubi-payments/pending
 * Get all pending payments
 */
router.get('/pending', async (req, res, next) => {
  try {
    const payments = await ubiPaymentService.getPendingPayments();
    res.json({ 
      success: true, 
      payments, 
      count: payments.length 
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/ubi-payments/retry/:paymentId
 * Retry a failed payment
 */
router.post('/retry/:paymentId', async (req, res, next) => {
  try {
    const payment = await ubiPaymentService.retryPayment(req.params.paymentId);
    res.json({ 
      success: true, 
      payment,
      message: 'Payment retry initiated'
    });
  } catch (err) {
    next(err);
  }
});

export default router;
