/**
 * HAITI STRATEGIC ACQUISITION API ROUTES
 * RESTful endpoints for Haiti debt acquisition, infrastructure, AI centers, and military operations
 */

import express from 'express';
const router = express.Router();
import HaitiStrategicService from '../services/haitiStrategicService.js';
import { authenticate, authorize } from '../middleware/auth.js';

// Initialize Haiti Strategic Service
const haitiService = new HaitiStrategicService();

// GET /api/haiti/portfolio - Get complete Haiti strategic portfolio
router.get('/portfolio', authenticate, authorize(['admin', 'portfolio_manager', 'analyst']), async (req, res) => {
  try {
    const portfolio = haitiService.getHaitiPortfolio();

    res.json({
      success: true,
      data: portfolio,
      message: 'Haiti strategic portfolio retrieved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve Haiti portfolio',
      message: error.message
    });
  }
});

// GET /api/haiti/summary - Get portfolio financial summary
router.get('/summary', authenticate, authorize(['admin', 'portfolio_manager', 'analyst']), async (req, res) => {
  try {
    const summary = haitiService.getPortfolioSummary();

    res.json({
      success: true,
      data: summary,
      message: 'Portfolio summary retrieved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve portfolio summary',
      message: error.message
    });
  }
});

// POST /api/haiti/debt/acquire - Acquire Haiti sovereign debt
router.post('/debt/acquire', authenticate, authorize(['admin', 'portfolio_manager']), async (req, res) => {
  try {
    const { acquisitionPrice } = req.body;

    const result = await haitiService.acquireHaitiDebt(
      { acquisitionPrice },
      req.userId,
      req.tenantId
    );

    res.status(201).json({
      success: true,
      data: result,
      message: 'Haiti sovereign debt acquired successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to acquire Haiti debt',
      message: error.message
    });
  }
});

// GET /api/haiti/infrastructure - Get infrastructure projects
router.get('/infrastructure', authenticate, authorize(['admin', 'portfolio_manager', 'analyst']), async (req, res) => {
  try {
    const portfolio = haitiService.getHaitiPortfolio();

    res.json({
      success: true,
      data: portfolio.infrastructure,
      count: portfolio.infrastructure.length,
      message: 'Infrastructure projects retrieved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve infrastructure projects',
      message: error.message
    });
  }
});

// GET /api/haiti/ai-centers - Get AI center deployments
router.get('/ai-centers', authenticate, authorize(['admin', 'portfolio_manager', 'analyst']), async (req, res) => {
  try {
    const portfolio = haitiService.getHaitiPortfolio();

    res.json({
      success: true,
      data: portfolio.aiCenters,
      count: portfolio.aiCenters.length,
      message: 'AI centers retrieved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve AI centers',
      message: error.message
    });
  }
});

// GET /api/haiti/ai-resources - Get AI resource requirements
router.get('/ai-resources', authenticate, authorize(['admin', 'portfolio_manager', 'analyst']), async (req, res) => {
  try {
    const resources = haitiService.getAIResourceRequirements();

    res.json({
      success: true,
      data: resources,
      message: 'AI resource requirements retrieved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve AI resources',
      message: error.message
    });
  }
});

// GET /api/haiti/military - Get military assets
router.get('/military', authenticate, authorize(['admin', 'portfolio_manager', 'analyst']), async (req, res) => {
  try {
    const portfolio = haitiService.getHaitiPortfolio();

    res.json({
      success: true,
      data: portfolio.military,
      count: portfolio.military.length,
      message: 'Military assets retrieved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve military assets',
      message: error.message
    });
  }
});

// GET /api/haiti/minerals - Get mineral resources
router.get('/minerals', authenticate, authorize(['admin', 'portfolio_manager', 'analyst']), async (req, res) => {
  try {
    const portfolio = haitiService.getHaitiPortfolio();

    res.json({
      success: true,
      data: portfolio.minerals,
      count: portfolio.minerals.length,
      totalEstimatedValue: '$60B+',
      message: 'Mineral resources retrieved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve mineral resources',
      message: error.message
    });
  }
});

// GET /api/haiti/partners - Get strategic partners
router.get('/partners', authenticate, authorize(['admin', 'portfolio_manager', 'analyst']), async (req, res) => {
  try {
    const portfolio = haitiService.getHaitiPortfolio();

    res.json({
      success: true,
      data: portfolio.partners,
      count: portfolio.partners.length,
      message: 'Strategic partners retrieved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve strategic partners',
      message: error.message
    });
  }
});

// PUT /api/haiti/project/:projectId/status - Update project status
router.put('/project/:projectId/status', authenticate, authorize(['admin', 'portfolio_manager']), async (req, res) => {
  try {
    const { projectId } = req.params;
    const { status, progress, notes, completionDate } = req.body;

    if (!status) {
      return res.status(400).json({
        success: false,
        error: 'Status is required'
      });
    }

    const result = haitiService.updateProjectStatus(projectId, status, {
      progress,
      notes,
      completionDate
    });

    if (!result.success) {
      return res.status(404).json(result);
    }

    res.json({
      success: true,
      data: result.project,
      message: result.message
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to update project status',
      message: error.message
    });
  }
});

// GET /api/haiti/export - Export complete strategic data
router.get('/export', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const exportData = haitiService.exportStrategicData();

    res.json({
      success: true,
      data: exportData,
      message: 'Strategic data exported successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to export strategic data',
      message: error.message
    });
  }
});

// GET /api/haiti/health - Get service health status
router.get('/health', authenticate, async (req, res) => {
  try {
    const health = haitiService.getHealthStatus();

    res.json({
      success: true,
      data: health,
      message: 'Service health retrieved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve service health',
      message: error.message
    });
  }
});

export default router;
