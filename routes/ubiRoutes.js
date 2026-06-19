/**
 * UBI Routes - Heaven on Earth Phase 1
 * API endpoints for Universal Basic Income
 */

import express from 'express';
import { info, error } from '../utils/loggerWrapper.js';
import { authenticateToken } from '../utils/authMiddleware.js';
import UniversalBasicIncomeService from '../services/universalBasicIncomeService.js';

const router = express.Router();

// Welcome endpoint
router.get('/welcome', (req, res) => {
  res.json({
    message: 'Universal Basic Income System - Heaven on Earth',
    mission: '$33,000/year per citizen - BIRTH RIGHT',
    rate: '$2,750/month',
    eligibleAge: 0, // BIRTH RIGHT - UBI starts at birth, not age 18
  });
});

// POST /api/ubi/eligibility/:citizenId
router.post('/eligibility/:citizenId', authenticateToken, async (req, res) => {
  try {
    const { citizenId } = req.params;
    const eligibility = await UniversalBasicIncomeService.calculateEligibility(citizenId);
    res.json(eligibility);
  } catch (error) {
    error(`UBI eligibility check failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

// POST /api/ubi/payment
router.post('/payment', authenticateToken, async (req, res) => {
  try {
    const { citizenId, month, amount } = req.body;
    const result = await UniversalBasicIncomeService.processPayment(citizenId, month, amount);
    res.json(result);
  } catch (error) {
    error(`UBI payment failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

// GET /api/ubi/history/:citizenId
router.get('/history/:citizenId', authenticateToken, async (req, res) => {
  try {
    const { citizenId } = req.params;
    const history = await UniversalBasicIncomeService.getPaymentHistory(citizenId);
    res.json(history);
  } catch (error) {
    error(`UBI history fetch failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

// POST /api/ubi/suspend/:citizenId
router.post('/suspend/:citizenId', authenticateToken, async (req, res) => {
  try {
    const { citizenId } = req.params;
    const { reason } = req.body;
    await UniversalBasicIncomeService.suspendUBI(citizenId, reason);
    res.json({ status: 'suspended', reason });
  } catch (error) {
    error(`UBI suspension failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

export default router;
