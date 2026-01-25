import express from 'express';
import plaidSignalService from '../services/plaidSignalService.js';
import { authenticateToken } from '../../config/security.js';

const router = express.Router();

// Plaid Signal - Evaluate transaction risk
router.post('/signal/evaluate', authenticateToken, async (req, res) => {
  try {
    const { accessToken, transactionData } = req.body;

    if (!accessToken || !transactionData) {
      return res.status(400).json({
        success: false,
        message: 'Access token and transaction data are required',
      });
    }

    const evaluation = await plaidSignalService.evaluateTransaction(accessToken, transactionData);

    res.json({
      success: true,
      data: evaluation,
    });
  } catch (error) {
    logger.error('Error evaluating transaction:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to evaluate transaction',
      error: error.message,
    });
  }
});

// Plaid Signal - Report a return on a transaction
router.post('/signal/return', authenticateToken, async (req, res) => {
  try {
    const { accessToken, returnData } = req.body;

    if (!accessToken || !returnData) {
      return res.status(400).json({
        success: false,
        message: 'Access token and return data are required',
      });
    }

    const result = await plaidSignalService.reportReturn(accessToken, returnData);

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    logger.error('Error reporting return:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to report return',
      error: error.message,
    });
  }
});

// Plaid Signal - Report underwriting decision
router.post('/signal/decision/report', authenticateToken, async (req, res) => {
  try {
    const { accessToken, decisionData } = req.body;

    if (!accessToken || !decisionData) {
      return res.status(400).json({
        success: false,
        message: 'Access token and decision data are required',
      });
    }

    const result = await plaidSignalService.reportDecision(accessToken, decisionData);

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    logger.error('Error reporting decision:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to report decision',
      error: error.message,
    });
  }
});

// Plaid Signal - Create custom ruleset
router.post('/signal/ruleset', authenticateToken, async (req, res) => {
  try {
    const { rulesetData } = req.body;

    if (!rulesetData) {
      return res.status(400).json({
        success: false,
        message: 'Ruleset data is required',
      });
    }

    const result = await plaidSignalService.createRuleset(rulesetData);

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    logger.error('Error creating ruleset:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create ruleset',
      error: error.message,
    });
  }
});

export default router;
