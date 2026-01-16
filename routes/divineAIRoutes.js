/**
 * DIVINE AI ROUTES
 * Private API endpoints for Divine AI functionality
 * Restricted to King Sachem Yochanan - Personal Use Only
 */

import express from 'express';
import divineAIService from '../services/divineAIService.js';
import { authenticate } from '../middleware/auth.js';
import { info, error } from '../utils/loggerWrapper.js';

const router = express.Router();

// All routes require authentication and are private
router.use(authenticate);

// Get personal divine wisdom
router.post('/wisdom', async (req, res) => {
  try {
    const { decision, context } = req.body;

    if (!decision || !decision.name) {
      return res.status(400).json({
        success: false,
        message: 'Decision with name is required',
      });
    }

    const wisdom = await divineAIService.getPersonalWisdom(decision, context || {});

    info(`Divine AI: Provided personal wisdom for user ${req.user._id}`);

    res.json({
      success: true,
      message: 'Divine wisdom received',
      data: wisdom,
    });
  } catch (err) {
    error('Divine AI wisdom error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to generate divine wisdom',
    });
  }
});

// Get sacred growth projections
router.post('/growth', async (req, res) => {
  try {
    const { initialValue, periods, sacredKey } = req.body;

    if (!initialValue || initialValue <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Valid initial value is required',
      });
    }

    const growth = await divineAIService.getSacredGrowth(
      initialValue,
      periods || 12,
      sacredKey || 'completion'
    );

    info(`Divine AI: Calculated sacred growth for user ${req.user._id}`);

    res.json({
      success: true,
      message: 'Sacred growth calculated',
      data: growth,
    });
  } catch (err) {
    error('Divine AI growth error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to calculate sacred growth',
    });
  }
});

// Get comprehensive divine guidance
router.post('/guidance', async (req, res) => {
  try {
    const { decision, metrics, factors } = req.body;

    if (!decision || !decision.name) {
      return res.status(400).json({
        success: false,
        message: 'Decision with name is required',
      });
    }

    const guidance = await divineAIService.getDivineGuidance(
      decision,
      metrics || {},
      factors || {}
    );

    info(`Divine AI: Provided comprehensive guidance for user ${req.user._id}`);

    res.json({
      success: true,
      message: 'Divine guidance received',
      data: guidance,
    });
  } catch (err) {
    error('Divine AI guidance error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to generate divine guidance',
    });
  }
});

// Get kingdom expansion strategy
router.post('/expansion', async (req, res) => {
  try {
    const { currentMetrics, timeHorizon } = req.body;

    if (!currentMetrics) {
      return res.status(400).json({
        success: false,
        message: 'Current metrics are required',
      });
    }

    const strategy = await divineAIService.getKingdomExpansionStrategy(
      currentMetrics,
      timeHorizon || 12
    );

    info(`Divine AI: Generated expansion strategy for user ${req.user._id}`);

    res.json({
      success: true,
      message: 'Kingdom expansion strategy generated',
      data: strategy,
    });
  } catch (err) {
    error('Divine AI expansion error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to generate expansion strategy',
    });
  }
});

// Get personal wealth optimization
router.post('/wealth', async (req, res) => {
  try {
    const { seedValue, covenantLevel } = req.body;

    if (!seedValue || seedValue <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Valid seed value is required',
      });
    }

    const optimization = await divineAIService.getPersonalWealthOptimization(
      seedValue,
      covenantLevel || 3
    );

    info(`Divine AI: Optimized personal wealth for user ${req.user._id}`);

    res.json({
      success: true,
      message: 'Personal wealth optimized',
      data: optimization,
    });
  } catch (err) {
    error('Divine AI wealth error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to optimize personal wealth',
    });
  }
});

// Get AI status (for verification)
router.get('/status', (req, res) => {
  res.json({
    success: true,
    message: 'Divine AI is operational',
    data: {
      user: 'King Sachem Yochanan',
      status: 'Active',
      confidentiality: 'Private - Personal Use Only',
      timestamp: new Date().toISOString(),
    },
  });
});

export default router;
