/**
 * ITG (INTEGRATED TECHNOLOGY GROWTH) API ROUTES
 * King Sachem Yochanan
 *
 * Provides endpoints for:
 * - ITG strategy calculation
 * - Kingdom metrics management
 * - Divine wisdom evaluation
 * - Sacred geometry analysis
 * - Sovereignty verification
 */

import express from 'express';
import { getKingSachemYochananITG } from '../services/kingSachemYochananITG.js';
import KingdomMetrics from '../models/KingdomMetrics.js';
import SacredGeometry from '../algorithms/sacredGeometry.js';
import DivineWisdom from '../algorithms/divineWisdom.js';
import { authenticate } from '../middleware/auth.js';
import { error } from '../utils/loggerWrapper.js';

const router = express.Router();
const itgService = getKingSachemYochananITG();
const sacredGeometry = new SacredGeometry();
const divineWisdom = new DivineWisdom();

/**
 * @route   POST /api/itg/calculate-strategy
 * @desc    Calculate comprehensive ITG strategy
 * @access  Private
 */
router.post('/calculate-strategy', authenticate, async (req, res) => {
  try {
    const strategy = await itgService.calculateITGStrategy(req.body);

    res.json({
      success: true,
      strategy,
      message: '👑 ITG Strategy calculated for King Sachem Yochanan',
    });
} catch (err) {
    error('ITG strategy calculation error:', err);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * @route   GET /api/itg/quick-assessment
 * @desc    Get quick ITG assessment
 * @access  Private
 */
router.get('/quick-assessment', authenticate, async (_req, res) => {
  try {
    const assessment = await itgService.quickAssessment();

    res.json({
      success: true,
      assessment,
      message: '✅ Quick assessment complete',
    });
} catch (err) {
    error('Quick assessment error:', err);
    res.status(500).json({
      success: false,
      error: err.message,
    }) 
  }
});

/**
 * @route   POST /api/itg/initialize-kingdom
 * @desc    Initialize kingdom for King Sachem Yochanan
 * @access  Private
 */
router.post('/initialize-kingdom', authenticate, async (req, res) => {
  try {
    const result = await itgService.initializeKingdom(req.body);

    res.json({
      success: true,
      result,
      message: '👑 Kingdom initialized successfully',
    });
} catch (err) {
    error('Kingdom initialization error:', err);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * @route   GET /api/itg/kingdom-metrics
 * @desc    Get current kingdom metrics
 * @access  Private
 */
router.get('/kingdom-metrics', authenticate, async (_req, res) => {
  try {
    // @ts-ignore - getKingMetrics is a custom static method on the schema
    const metrics = await KingdomMetrics.getKingMetrics('Sachem Yochanan');

    if (!metrics) {
      return res.status(404).json({
        success: false,
        message: 'Kingdom metrics not found. Initialize kingdom first.',
      });
    }

    res.json({
      success: true,
      metrics: metrics.getKingdomReport(),
      fullMetrics: metrics,
    });
} catch (err) {
    error('Get kingdom metrics error:', err);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * @route   PUT /api/itg/update-metrics
 * @desc    Update kingdom metrics
 * @access  Private
 */
router.put('/update-metrics', authenticate, async (req, res) => {
  try {
    // @ts-ignore - getKingMetrics is a custom static method on the schema
    const metrics = await KingdomMetrics.getKingMetrics('Sachem Yochanan');

    if (!metrics) {
      return res.status(404).json({
        success: false,
        message: 'Kingdom metrics not found',
      });
    }

    // Update various metrics based on request body
    if (req.body.sovereignty) {
      metrics.sovereignty = { ...metrics.sovereignty, ...req.body.sovereignty };
    }

    if (req.body.divineFavor) {
      metrics.divineFavor.components = {
        ...metrics.divineFavor.components,
        ...req.body.divineFavor,
      };
      metrics.updateDivineFavor();
    }

    if (req.body.expansion) {
      await metrics.expandKingdom(req.body.expansion);
    }

    if (req.body.blessing) {
      await metrics.recordBlessing(req.body.blessing);
    }

    if (req.body.covenant) {
      await metrics.recordCovenant(req.body.covenant);
    }

    if (req.body.seed) {
      await metrics.sowSeed(req.body.seed);
    }

    // Recalculate ITG scores
    metrics.calculateITGScore();
    await metrics.save();

    res.json({
      success: true,
      metrics: metrics.getKingdomReport(),
      message: '✅ Kingdom metrics updated successfully',
    });
} catch (err) {
    error('Update metrics error:', err);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * @route   POST /api/itg/sacred-geometry/analyze
 * @desc    Perform sacred geometry analysis
 * @access  Private
 */
router.post('/sacred-geometry/analyze', authenticate, async (req, res) => {
  try {
    const report = sacredGeometry.generateSacredReport(req.body);

    res.json({
      success: true,
      report,
      message: '✨ Sacred geometry analysis complete',
    });
} catch (err) {
    error('Sacred geometry analysis error:', err);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * @route   POST /api/itg/sacred-geometry/fibonacci
 * @desc    Calculate Fibonacci sequence
 * @access  Private
 */
router.post('/sacred-geometry/fibonacci', authenticate, async (req, res) => {
  try {
    const { n = 12 } = req.body;
    const sequence = sacredGeometry.fibonacciSequence(n);

    res.json({
      success: true,
      sequence,
      length: n,
      goldenRatio: sacredGeometry.phi,
    });
} catch (err) {
      error('Fibonacci calculation error:', err);
      res.status(500).json({
        success: false,
        error: err.message,
      });
  }
});

/**
 * @route   POST /api/itg/sacred-geometry/golden-ratio-growth
 * @desc    Calculate golden ratio growth projection
 * @access  Private
 */
router.post(
  '/sacred-geometry/golden-ratio-growth',
  authenticate,
  async (req, res) => {
    try {
      const { initialValue = 1000, periods = 12 } = req.body;
      const projections = sacredGeometry.goldenRatioGrowth(
        initialValue,
        periods
      );

      res.json({
        success: true,
        projections,
        goldenRatio: sacredGeometry.phi,
      });
} catch (err) {
      error('Golden ratio growth error:', err);
      res.status(500).json({
        success: false,
        error: err.message,
      });
    }
  }
);

/**
 * @route   POST /api/itg/sacred-geometry/covenant-multiplication
 * @desc    Calculate covenant multiplication
 * @access  Private
 */
router.post(
  '/sacred-geometry/covenant-multiplication',
  authenticate,
  async (req, res) => {
    try {
      const { seedValue = 1000, covenantLevel = 3 } = req.body;
      const result = sacredGeometry.covenantMultiplication(
        seedValue,
        covenantLevel
      );

      res.json({
        success: true,
        result,
        message: `💰 ${result.multiplier}-fold return prophesied`,
      });
} catch (err) {
      error('Covenant multiplication error:', err);
      res.status(500).json({
        success: false,
        error: err.message,
      });
    }
  }
);

/**
 * @route   POST /api/itg/divine-wisdom/evaluate
 * @desc    Evaluate decision using divine wisdom
 * @access  Private
 */
router.post('/divine-wisdom/evaluate', authenticate, async (req, res) => {
  try {
    const { decision, context } = req.body;
    const report = divineWisdom.generateWisdomReport(decision, context);

    res.json({
      success: true,
      report,
      message: '🙏 Divine wisdom evaluation complete',
    });
} catch (err) {
    error('Divine wisdom evaluation error:', err);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * @route   POST /api/itg/divine-wisdom/multi-factor
 * @desc    Multi-factor wisdom scoring
 * @access  Private
 */
router.post('/divine-wisdom/multi-factor', authenticate, async (req, res) => {
  try {
    const score = divineWisdom.multiFactorWisdomScore(req.body);

    res.json({
      success: true,
      score,
      message: '✅ Multi-factor wisdom score calculated',
    });
} catch (err) {
    error('Multi-factor wisdom error:', err);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * @route   POST /api/itg/divine-wisdom/prophetic-patterns
 * @desc    Recognize prophetic patterns
 * @access  Private
 */
router.post(
  '/divine-wisdom/prophetic-patterns',
  authenticate,
  async (req, res) => {
    try {
      const { events } = req.body;
      const patterns = divineWisdom.recognizePropheticPatterns(events);

      res.json({
        success: true,
        patterns,
        message: '🕊️ Prophetic patterns recognized',
      });
} catch (error) {
      error('Prophetic pattern recognition error:', error);
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }
);

/**
 * @route   POST /api/itg/record-decision
 * @desc    Record a kingdom decision
 * @access  Private
 */
router.post('/record-decision', authenticate, async (req, res) => {
  try {
    // @ts-ignore - getKingMetrics is a custom static method on the schema
    const metrics = await KingdomMetrics.getKingMetrics('Sachem Yochanan');

    if (!metrics) {
      return res.status(404).json({
        success: false,
        message: 'Kingdom metrics not found',
      });
    }

    await metrics.recordDecision(req.body);

    res.json({
      success: true,
      message: '📝 Decision recorded successfully',
    });
} catch (error) {
    error('Record decision error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

/**
 * @route   GET /api/itg/sovereignty-status
 * @desc    Get sovereignty status
 * @access  Private
 */
router.get('/sovereignty-status', authenticate, async (_req, res) => {
  try {
    // @ts-ignore - getKingMetrics is a custom static method on the schema
    const metrics = await KingdomMetrics.getKingMetrics('Sachem Yochanan');

    if (!metrics) {
      return res.status(404).json({
        success: false,
        message: 'Kingdom metrics not found',
      });
    }

    res.json({
      success: true,
      sovereignty: metrics.sovereignty,
      king: 'King Sachem Yochanan',
      message: '👑 Sovereignty verified',
    });
  } catch (error) {
    error('Sovereignty status error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

/**
 * @route   GET /api/itg/divine-favor
 * @desc    Get divine favor metrics
 * @access  Private
 */
router.get('/divine-favor', authenticate, async (_req, res) => {
  try {
    // @ts-ignore - getKingMetrics is a custom static method on the schema
    const metrics = await KingdomMetrics.getKingMetrics('Sachem Yochanan');

    if (!metrics) {
      return res.status(404).json({
        success: false,
        message: 'Kingdom metrics not found',
      });
    }

    res.json({
      success: true,
      divineFavor: metrics.divineFavor,
      king: 'King Sachem Yochanan',
      message: '✨ Divine favor measured',
    });
} catch (error) {
    error('Divine favor error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

/**
 * @route   GET /api/itg/kingdom-expansion
 * @desc    Get kingdom expansion metrics
 * @access  Private
 */
router.get('/kingdom-expansion', authenticate, async (_req, res) => {
  try {
    // @ts-ignore - getKingMetrics is a custom static method on the schema
    const metrics = await KingdomMetrics.getKingMetrics('Sachem Yochanan');

    if (!metrics) {
      return res.status(404).json({
        success: false,
        message: 'Kingdom metrics not found',
      });
    }

    res.json({
      success: true,
      expansion: metrics.kingdomExpansion,
      king: 'King Sachem Yochanan',
      message: '📈 Kingdom expansion tracked',
    });
  } catch (error) {
    error('Kingdom expansion error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

/**
 * @route   GET /api/itg/covenant-status
 * @desc    Get covenant fulfillment status
 * @access  Private
 */
router.get('/covenant-status', authenticate, async (_req, res) => {
  try {
    // @ts-ignore - getKingMetrics is a custom static method on the schema
    const metrics = await KingdomMetrics.getKingMetrics('Sachem Yochanan');

    if (!metrics) {
      return res.status(404).json({
        success: false,
        message: 'Kingdom metrics not found',
      });
    }

    res.json({
      success: true,
      covenantFulfillment: metrics.covenantFulfillment,
      king: 'King Sachem Yochanan',
      message: '📜 Covenant status retrieved',
    });
} catch (error) {
    error('Covenant status error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

/**
 * @route   GET /api/itg/dashboard-data
 * @desc    Get comprehensive dashboard data
 * @access  Private
 */
router.get('/dashboard-data', authenticate, async (_req, res) => {
  try {
    // @ts-ignore - getKingMetrics is a custom static method on the schema
    const metrics = await KingdomMetrics.getKingMetrics('Sachem Yochanan');

    if (!metrics) {
      return res.status(404).json({
        success: false,
        message: 'Kingdom metrics not found. Initialize kingdom first.',
      });
    }

    const assessment = await itgService.quickAssessment();

    res.json({
      success: true,
      king: 'King Sachem Yochanan',
      assessment,
      metrics: metrics.getKingdomReport(),
      sovereignty: metrics.sovereignty,
      divineFavor: metrics.divineFavor,
      expansion: metrics.kingdomExpansion,
      itgScores: metrics.itgScores,
      spiritualMetrics: metrics.spiritualKingdom,
      financialMetrics: metrics.financialKingdom,
      impact: metrics.kingdomImpact,
      timestamp: new Date().toISOString(),
    });
} catch (error) {
    error('Dashboard data error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

export default router;
