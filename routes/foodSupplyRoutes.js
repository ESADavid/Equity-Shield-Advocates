/**
 * Food Supply Chain Acquisition API Routes
 */

import express from 'express';
const router = express.Router();
import FoodSupplyChain from '../models/FoodSupplyChain.js';
import { authenticate, authorize } from '../middleware/auth.js';

router.get('/', authenticate, async (req, res) => {
  try {
    const chains = await FoodSupplyChain.getByTenant(req.tenantId);
    res.json({ success: true, data: chains });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/analytics', authenticate, async (req, res) => {
  try {
    const analytics = await FoodSupplyChain.getPortfolioAnalytics(req.tenantId);
    res.json({ success: true, data: analytics });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const chain = new FoodSupplyChain({
      ...req.body,
      tenantId: req.tenantId,
      audit: { acquiredBy: req.userId },
    });
    await chain.save();
    res.status(201).json({ success: true, data: chain });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

export default router;
