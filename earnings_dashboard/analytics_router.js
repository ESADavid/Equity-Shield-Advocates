import express from 'express';
import { getAnalytics } from './ai_analytics.js';

const router = express.Router();

// GET /api/analytics - Get AI-powered analytics
router.get('/', (req, res) => {
  try {
    const analytics = getAnalytics();
    res.json(analytics);
  } catch (error) {
    console.error('Analytics error:', error);
    res.status(500).json({ error: 'Failed to retrieve analytics' });
  }
});

export default router;
