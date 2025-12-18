import express from 'express';
import { getAnalytics } from './ai_analytics.js';
import { getTranscendenceAnalytics, initializeTranscendence, optimizeRevenueAutonomously } from './ai_transcendence.js';

const router = express.Router();

// GET /api/analytics - Get AI-powered analytics
router.get('/', (req, res) => {
  try {
    const analytics = getAnalytics();
    // Transform to match test expectations
    const response = {
      predictions: analytics.predictions,
      anomalies: analytics.anomalies,
      riskAssessment: analytics.riskAssessment
    };
    res.json(response);
  } catch (error) {
    logger.error('Analytics error:', error);
    res.status(500).json({ error: 'Failed to retrieve analytics' });
  }
});

// GET /api/analytics/transcendence - Get AI transcendence analytics
router.get('/transcendence', async (req, res) => {
  try {
    const analytics = getTranscendenceAnalytics();
    // Transform to match test expectations
    const response = {
      deepLearning: analytics.deepLearning,
      quantumOptimization: analytics.quantumOptimization,
      autonomousDecisions: analytics.autonomousDecisions
    };
    res.json(response);
  } catch (error) {
    logger.error('Transcendence analytics error:', error);
    res.status(500).json({ error: 'Failed to retrieve transcendence analytics' });
  }
});

// POST /api/analytics/optimize - Optimize revenue autonomously
router.post('/optimize', async (req, res) => {
  try {
    const { currentRevenue, marketConditions } = req.body;
    if (typeof currentRevenue !== 'number' || !marketConditions) {
      return res.status(400).json({ error: 'Invalid input data' });
    }
    const result = await optimizeRevenueAutonomously(currentRevenue, marketConditions);
    // Transform to match test expectations
    const response = {
      optimized: {
        projectedRevenue: result.optimized.projectedRevenue
      },
      decisions: {
        actions: result.decisions.actions
      }
    };
    res.json(response);
  } catch (error) {
    logger.error('Optimization error:', error);
    res.status(500).json({ error: 'Failed to optimize revenue' });
  }
});

// Initialize transcendence engine on router load
initializeTranscendence().catch(err => {
  logger.error('Failed to initialize AI transcendence engine:', err);
});

export default router;
