/**
 * UBI Routes - Heaven on Earth Phase 1
 * API endpoints for Universal Basic Income
 */

const express = require('express');
const router = express.Router();
const UBI = require('../services/universalBasicIncomeService');
const authMiddleware = require('../utils/authMiddleware');
const logger = require('../utils/logger');

// POST /api/ubi/eligibility/:citizenId
router.post('/eligibility/:citizenId', authMiddleware, async (req, res) => {
  try {
    const { citizenId } = req.params;
    const eligibility = await UBI.calculateEligibility(citizenId);
    res.json(eligibility);
  } catch (error) {
    logger.error(`UBI eligibility check failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

// POST /api/ubi/payment
router.post('/payment', authMiddleware, async (req, res) => {
  try {
    const { citizenId, month, amount } = req.body;
    const result = await UBI.processPayment(citizenId, month, amount);
    res.json(result);
  } catch (error) {
    logger.error(`UBI payment failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

// GET /api/ubi/history/:citizenId
router.get('/history/:citizenId', authMiddleware, async (req, res) => {
  try {
    const { citizenId } = req.params;
    const history = await UBI.getPaymentHistory(citizenId);
    res.json(history);
  } catch (error) {
    logger.error(`UBI history fetch failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

// POST /api/ubi/suspend/:citizenId
router.post('/suspend/:citizenId', authMiddleware, async (req, res) => {
  try {
    const { citizenId } = req.params;
    const { reason } = req.body;
    await UBI.suspendUBI(citizenId, reason);
    res.json({ status: 'suspended', reason });
  } catch (error) {
    logger.error(`UBI suspension failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

module.exports = router;
