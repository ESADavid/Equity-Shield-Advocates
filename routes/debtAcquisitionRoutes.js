/**
 * DEBT ACQUISITION API ROUTES
 * RESTful endpoints for debt acquisition and management operations
 */

import express from 'express';
const router = express.Router();
import Debt from '../models/Debt.js';
import { authenticate, authorize } from '../middleware/auth.js';

// GET /api/debt - Get debt portfolio
router.get('/', authenticate, authorize(['admin', 'portfolio_manager', 'analyst']), async (req, res) => {
  try {
    const { page = 1, limit = 50, status, entityType, riskRating, country } = req.query;
    const skip = (Number.parseInt(page) - 1) * Number.parseInt(limit);

    // Build query
    const query = { tenantId: req.tenantId };
    if (status) query.status = status;
    if (entityType) query.entityType = entityType;
    if (riskRating) query.riskRating = riskRating;
    if (country) query.country = country;

    const debts = await Debt.find(query)
      .sort({ acquisitionDate: -1 })
      .limit(limit)
      .skip(skip)
      .populate('audit.acquiredBy', 'username firstName lastName')
      .populate('audit.approvedBy', 'username firstName lastName');

    const total = await Debt.countDocuments(query);

    res.json({
      success: true,
      data: debts.map(debt => debt.toPublicJSON()),
      pagination: {
        page: Number.parseInt(page),
        limit: Number.parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve debt portfolio',
      message: error.message
    });
  }
});

// GET /api/debt/analytics - Get debt portfolio analytics
router.get('/analytics', authenticate, authorize(['admin', 'portfolio_manager', 'analyst']), async (req, res) => {
  try {
    const analytics = await Debt.getPortfolioAnalytics(req.tenantId);

    res.json({
      success: true,
      data: analytics
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve debt analytics',
      message: error.message
    });
  }
});

// GET /api/debt/:id - Get specific debt
router.get('/:id', authenticate, authorize(['admin', 'portfolio_manager', 'analyst']), async (req, res) => {
  try {
    const debt = await Debt.findOne({
      debtId: req.params.id,
      tenantId: req.tenantId
    })
    .populate('audit.acquiredBy', 'username firstName lastName')
    .populate('audit.approvedBy', 'username firstName lastName')
    .populate('audit.lastValuationBy', 'username firstName lastName');

    if (!debt) {
      return res.status(404).json({
        success: false,
        error: 'Debt not found'
      });
    }

    res.json({
      success: true,
      data: debt.toPublicJSON()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve debt',
      message: error.message
    });
  }
});

// POST /api/debt - Acquire new debt
router.post('/', authenticate, authorize(['admin', 'portfolio_manager']), async (req, res) => {
  try {
    const {
      entity,
      entityType,
      country,
      debtType,
      faceValue,
      acquiredValue,
      currency = 'USD',
      maturityDate,
      interestRate,
      riskRating,
      strategicValue,
      collateral,
      covenants = []
    } = req.body;

    // Validate required fields
    if (!entity || !faceValue || !acquiredValue || !maturityDate || !interestRate) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields',
        required: ['entity', 'faceValue', 'acquiredValue', 'maturityDate', 'interestRate']
      });
    }

    // Generate debt ID
    const debtId = `debt-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const acquisitionId = `ACQ-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    // Calculate expected yield (simplified)
    const discount = ((faceValue - acquiredValue) / faceValue) * 100;
    const expectedYield = interestRate + (discount / 100);

    const debt = new Debt({
      tenantId: req.tenantId,
      debtId,
      entity,
      entityType: entityType || 'sovereign',
      country: country || 'Global',
      debtType: debtType || 'sovereign_bonds',
      faceValue,
      acquiredValue,
      currentValue: acquiredValue, // Initial current value = acquired value
      currency,
      maturityDate,
      acquisitionDate: new Date(),
      interestRate,
      expectedYield,
      status: 'active',
      riskRating: riskRating || 'AA',
      strategicValue,
      collateral,
      covenants,
      discount: discount.toFixed(2) + '%',
      acquisitionId,
      audit: {
        acquiredBy: req.userId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      }
    });

    await debt.save();

    // Record initial valuation
    debt.valuations.push({
      value: acquiredValue,
      change: 0,
      changePercent: 0,
      marketPrice: acquiredValue,
      interestRate,
      riskRating: riskRating || 'AA',
      assessedBy: req.userId
    });

    await debt.save();

    res.status(201).json({
      success: true,
      data: debt.toPublicJSON(),
      message: `Successfully acquired ${debt.currency} ${debt.acquiredValue.toString()} of ${entity} debt`
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to acquire debt',
      message: error.message
    });
  }
});

// PUT /api/debt/:id/valuation - Update debt valuation
router.put('/:id/valuation', authenticate, authorize(['admin', 'portfolio_manager', 'analyst']), async (req, res) => {
  try {
    const { newValue, marketPrice, interestRate, riskRating } = req.body;

    if (!newValue) {
      return res.status(400).json({
        success: false,
        error: 'New value is required'
      });
    }

    const debt = await Debt.findOne({
      debtId: req.params.id,
      tenantId: req.tenantId
    });

    if (!debt) {
      return res.status(404).json({
        success: false,
        error: 'Debt not found'
      });
    }

    const marketData = {};
    if (marketPrice) marketData.marketPrice = marketPrice;
    if (interestRate) marketData.interestRate = interestRate;
    if (riskRating) marketData.riskRating = riskRating;

    await debt.updateValuation(newValue, req.userId, marketData);

    res.json({
      success: true,
      data: debt.toPublicJSON(),
      message: 'Debt valuation updated successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to update debt valuation',
      message: error.message
    });
  }
});

// PUT /api/debt/:id/status - Update debt status
router.put('/:id/status', authenticate, authorize(['admin', 'portfolio_manager']), async (req, res) => {
  try {
    const { status, reason } = req.body;

    const validStatuses = ['active', 'matured', 'defaulted', 'called', 'exchanged'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid status',
        validStatuses
      });
    }

    const debt = await Debt.findOne({
      debtId: req.params.id,
      tenantId: req.tenantId
    });

    if (!debt) {
      return res.status(404).json({
        success: false,
        error: 'Debt not found'
      });
    }

    debt.status = status;

    if (status === 'defaulted' && reason) {
      debt.metadata.defaultReason = reason;
      debt.metadata.defaultDate = new Date();
    } else if (status === 'matured') {
      debt.metadata.maturityDate = new Date();
    }

    await debt.save();

    res.json({
      success: true,
      data: debt.toPublicJSON(),
      message: `Debt status updated to ${status}`
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to update debt status',
      message: error.message
    });
  }
});

// POST /api/debt/:id/cashflow - Add cashflow to debt
router.post('/:id/cashflow', authenticate, authorize(['admin', 'portfolio_manager']), async (req, res) => {
  try {
    const { date, amount, type } = req.body;

    if (!date || !amount || !type) {
      return res.status(400).json({
        success: false,
        error: 'Date, amount, and type are required'
      });
    }

    const debt = await Debt.findOne({
      debtId: req.params.id,
      tenantId: req.tenantId
    });

    if (!debt) {
      return res.status(404).json({
        success: false,
        error: 'Debt not found'
      });
    }

    await debt.addCashflow(new Date(date), amount, type);

    res.json({
      success: true,
      message: 'Cashflow added successfully',
      data: debt.cashflows[debt.cashflows.length - 1]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to add cashflow',
      message: error.message
    });
  }
});

// PUT /api/debt/:id/cashflow/:cashflowId - Mark cashflow as paid
router.put('/:id/cashflow/:cashflowId', authenticate, authorize(['admin', 'portfolio_manager']), async (req, res) => {
  try {
    const debt = await Debt.findOne({
      debtId: req.params.id,
      tenantId: req.tenantId
    });

    if (!debt) {
      return res.status(404).json({
        success: false,
        error: 'Debt not found'
      });
    }

    await debt.markCashflowPaid(req.params.cashflowId);

    res.json({
      success: true,
      message: 'Cashflow marked as paid'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to update cashflow',
      message: error.message
    });
  }
});

// GET /api/debt/:id/history - Get debt valuation history
router.get('/:id/history', authenticate, authorize(['admin', 'portfolio_manager', 'analyst']), async (req, res) => {
  try {
    const { days = 365 } = req.query;

    const debt = await Debt.findOne({
      debtId: req.params.id,
      tenantId: req.tenantId
    });

    if (!debt) {
      return res.status(404).json({
        success: false,
        error: 'Debt not found'
      });
    }

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);

    const history = debt.valuations
      .filter(valuation => valuation.date >= cutoffDate)
      .sort((a, b) => b.date - a.date);

    res.json({
      success: true,
      data: history,
      count: history.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve valuation history',
      message: error.message
    });
  }
});

// GET /api/debt/maturing - Get debts maturing soon
router.get('/maturing/soon', authenticate, authorize(['admin', 'portfolio_manager', 'analyst']), async (req, res) => {
  try {
    const { days = 90 } = req.query;

    const debts = await Debt.getMaturingSoon(days, req.tenantId);

    res.json({
      success: true,
      data: debts.map(debt => debt.toPublicJSON()),
      count: debts.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve maturing debts',
      message: error.message
    });
  }
});

// GET /api/debt/high-risk - Get high-risk debts
router.get('/risk/high', authenticate, authorize(['admin', 'portfolio_manager', 'analyst']), async (req, res) => {
  try {
    const { threshold = 70 } = req.query;

    const debts = await Debt.getHighRisk(threshold, req.tenantId);

    res.json({
      success: true,
      data: debts.map(debt => debt.toPublicJSON()),
      count: debts.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve high-risk debts',
      message: error.message
    });
  }
});

// POST /api/debt/:id/notification - Add notification to debt
router.post('/:id/notification', authenticate, authorize(['admin', 'portfolio_manager']), async (req, res) => {
  try {
    const { type, message, priority = 'medium' } = req.body;

    const debt = await Debt.findOne({
      debtId: req.params.id,
      tenantId: req.tenantId
    });

    if (!debt) {
      return res.status(404).json({
        success: false,
        error: 'Debt not found'
      });
    }

    await debt.addNotification(type, message, priority);

    res.json({
      success: true,
      message: 'Notification added successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to add notification',
      message: error.message
    });
  }
});

export default router;
