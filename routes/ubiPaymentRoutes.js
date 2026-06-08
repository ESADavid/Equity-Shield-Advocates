// UBI Payment Routes - Integrated with Payroll & JPMorgan
import express from 'express';
import ubiPaymentService from '../services/ubiPaymentService.js';
import UBIPayment from '../models/UBIPayment.js';
import { info, error } from '../utils/loggerWrapper.js';

const router = express.Router();

// Process UBI payment for a single citizen
router.post('/process/:citizenId', async (req, res, next) => {
  try {
    info(`Processing UBI payment request for citizen: ${req.params.citizenId}`);
    const payment = await ubiPaymentService.processPayment(
      req.params.citizenId
    );
    res.json({
      success: true,
      payment: {
        id: payment._id,
        citizenId: payment.citizenId,
        amount: payment.amount,
        status: payment.status,
        paymentDate: payment.paymentDate,
        transactionId: payment.transactionId,
        paymentMethod: payment.paymentMethod,
      },
    });
  } catch (err) {
    error('UBI payment processing error:', err.message);
    next(err);
  }
});

// Get payment history for a citizen
router.get('/history/:citizenId', async (req, res, next) => {
  try {
    /** @type {string} */
    const limitStr = req.query.limit;
    const limit = parseInt(limitStr) || 50;
    const history = await ubiPaymentService.getPaymentHistory(
      req.params.citizenId,
      limit
    );
    res.json({
      success: true,
      history: history.map((payment) => ({
        id: payment._id,
        citizenId: payment.citizenId,
        amount: payment.amount,
        status: payment.status,
        paymentDate: payment.paymentDate,
        transactionId: payment.transactionId,
        paymentMethod: payment.paymentMethod,
        citizen: payment.citizenId, // populated data
      })),
    });
  } catch (err) {
    error('UBI payment history retrieval error:', err.message);
    next(err);
  }
});

// Get payment status by payment ID
router.get('/status/:paymentId', async (req, res, next) => {
  try {
    const payment = await ubiPaymentService.getPaymentStatus(
      req.params.paymentId
    );
    res.json({
      success: true,
      payment: {
        id: payment._id,
        citizenId: payment.citizenId,
        amount: payment.amount,
        status: payment.status,
        paymentDate: payment.paymentDate,
        transactionId: payment.transactionId,
        paymentMethod: payment.paymentMethod,
        metadata: payment.metadata,
      },
    });
  } catch (err) {
    error('UBI payment status retrieval error:', err.message);
    next(err);
  }
});

// Calculate UBI amount for a citizen (preview)
router.get('/calculate/:citizenId', async (req, res, next) => {
  try {
    const amount = await ubiPaymentService.calculateUBIAmount(
      req.params.citizenId
    );
    res.json({
      success: true,
      citizenId: req.params.citizenId,
      calculatedAmount: amount,
      calculatedAt: new Date(),
    });
  } catch (err) {
    error('UBI amount calculation error:', err.message);
    next(err);
  }
});

// Process bulk UBI payments
router.post('/bulk-process', async (req, res, next) => {
  try {
    const { citizenIds } = req.body;

    if (!Array.isArray(citizenIds) || citizenIds.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'citizenIds must be a non-empty array',
      });
    }

    if (citizenIds.length > 1000) {
      return res.status(400).json({
        success: false,
        error: 'Maximum 1000 citizens allowed per bulk request',
      });
    }

    info(`Processing bulk UBI payments for ${citizenIds.length} citizens`);
    const results = await ubiPaymentService.processBulkPayments(citizenIds);

    res.json({
      success: true,
      results: {
        total: results.total,
        successful: results.successful.length,
        failed: results.failed.length,
        successfulPayments: results.successful,
        failedPayments: results.failed,
      },
    });
  } catch (err) {
    error('Bulk UBI payment processing error:', err.message);
    next(err);
  }
});

// Get UBI payment statistics
router.get('/stats', async (req, res, next) => {
  try {
    /** @type {string|undefined} */
    const startDate = req.query.startDate;
    /** @type {string|undefined} */
    const endDate = req.query.endDate;

    // Build date filter
    /** @type {Object} */
    const dateFilter = {};
    if (startDate) dateFilter.$gte = new Date(startDate);
    if (endDate) dateFilter.$lte = new Date(endDate);

    const matchFilter = { status: 'completed' };
    if (Object.keys(dateFilter).length > 0) {
      matchFilter.paymentDate = dateFilter;
    }

    // This would typically use MongoDB aggregation
    // For now, return basic stats
    const totalPayments = await UBIPayment.countDocuments(matchFilter);
    const totalAmount = await UBIPayment.aggregate([
      { $match: matchFilter },
      { $group: { _id: null, total: { $sum: '$amount' } } },
    ]);

    res.json({
      success: true,
      stats: {
        totalPayments,
        totalAmount: totalAmount[0]?.total || 0,
        averagePayment:
          totalPayments > 0 ? (totalAmount[0]?.total || 0) / totalPayments : 0,
        period: { startDate, endDate },
      },
    });
  } catch (err) {
    error('UBI payment stats retrieval error:', err.message);
    next(err);
  }
});

export default router;
