/**
 * PARTNER ROUTES
 * API endpoints for partner management and coordination
 * Part of Phase 2: Heaven on Earth Implementation
 */

import express from 'express';
import PartnerCoordinationService from '../services/partnerCoordinationService.js';
import PMCIntegrationService from '../services/pmcIntegrationService.js';
import { error } from '../utils/loggerWrapper.js';

const router = express.Router();
const partnerService = new PartnerCoordinationService();
const pmcService = new PMCIntegrationService();

/**
 * @route   POST /api/partners/onboard
 * @desc    Onboard a new partner
 * @access  Private
 */
router.post('/onboard', async (req, res) => {
  try {
    const userId = req.user?.id || 'system';
    const result = await partnerService.onboardPartner(req.body, userId);

    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
} catch (err) {
    error('Error onboarding partner:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to onboard partner',
    });
  }
});

/**
 * @route   GET /api/partners
 * @desc    Get all partners with filters
 * @access  Private
 */
router.get('/', (req, res) => {
  try {
    const filters = {
      status: req.query.status,
      type: req.query.type,
      minRating: req.query.minRating ? parseFloat(String(req.query.minRating)) : undefined,
      sortBy: req.query.sortBy,
    };

    const result = partnerService.getPartners(filters);
    res.json(result);
  } catch (error) {
    error('Error getting partners:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get partners',
    });
  }
});

/**
 * @route   GET /api/partners/:partnerId
 * @desc    Get partner details
 * @access  Private
 */
router.get('/:partnerId', async (req, res) => {
  try {
    const { partnerId } = req.params;
    const result = await partnerService.getPartner(partnerId);

    if (result.success) {
      res.json(result);
    } else {
      res.status(404).json(result);
    }
  } catch (error) {
    error('Error getting partner:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get partner',
    });
  }
});

/**
 * @route   POST /api/partners/:partnerId/activate
 * @desc    Activate a partner
 * @access  Private
 */
router.post('/:partnerId/activate', async (req, res) => {
  try {
    const { partnerId } = req.params;
    const userId = req.user?.id || 'system';

    const result = await partnerService.activatePartner(partnerId, userId);

    if (result.success) {
      res.json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    error('Error activating partner:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to activate partner',
    });
  }
});

/**
 * @route   POST /api/partners/:partnerId/projects
 * @desc    Assign project to partner
 * @access  Private
 */
router.post('/:partnerId/projects', async (req, res) => {
  try {
    const { partnerId } = req.params;
    const userId = req.user?.id || 'system';

    const result = await partnerService.assignProject(partnerId, req.body, userId);

    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    error('Error assigning project:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to assign project',
    });
  }
});

/**
 * @route   PUT /api/partners/projects/:projectId
 * @desc    Update project status
 * @access  Private
 */
router.put('/projects/:projectId', async (req, res) => {
  try {
    const { projectId } = req.params;
    const { status, ...updateData } = req.body;
    const userId = req.user?.id || 'system';

    const result = await partnerService.updateProjectStatus(
      projectId,
      status,
      updateData,
      userId
    );

    if (result.success) {
      res.json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    error('Error updating project:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update project',
    });
  }
});

/**
 * @route   POST /api/partners/:partnerId/communication
 * @desc    Log communication with partner
 * @access  Private
 */
router.post('/:partnerId/communication', async (req, res) => {
  try {
    const { partnerId } = req.params;
    const userId = req.user?.id || 'system';

    const result = await partnerService.logCommunication(partnerId, req.body, userId);

    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    error('Error logging communication:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to log communication',
    });
  }
});

/**
 * @route   POST /api/partners/:partnerId/rating
 * @desc    Update partner performance rating
 * @access  Private
 */
router.post('/:partnerId/rating', async (req, res) => {
  try {
    const { partnerId } = req.params;
    const userId = req.user?.id || 'system';

    const result = await partnerService.updatePerformanceRating(
      partnerId,
      req.body,
      userId
    );

    if (result.success) {
      res.json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    error('Error updating rating:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update rating',
    });
  }
});

/**
 * @route   PUT /api/partners/workflows/:workflowId/steps/:stepId
 * @desc    Update workflow step status
 * @access  Private
 */
router.put('/workflows/:workflowId/steps/:stepId', async (_req, res) => {
  try {
    const { workflowId, stepId } = _req.params;
    const { status } = _req.body;
    const userId = _req.user?.id || 'system';

    const result = await partnerService.updateWorkflowStep(
      workflowId,
      stepId,
      status,
      userId
    );

    if (result.success) {
      res.json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    error('Error updating workflow step:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update workflow step',
    });
  }
});

/**
 * @route   GET /api/partners/statistics
 * @desc    Get partner service statistics
 * @access  Private
 */
router.get('/statistics', async (_req, res) => {
  try {
    // Extract query parameters for potential filtering (reserved for future use)
    const queryParams = _req.query;
    const result = await partnerService.getStatistics();
    res.json(result);
  } catch (err) {
    error('Error getting statistics:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get statistics',
    });
  }
});

/**
 * @route   GET /api/partners/health
 * @desc    Get partner service health status
 * @access  Public
 */
router.get('/health', async (_req, res) => {
  try {
    const result = await partnerService.getHealthStatus();
    res.json(result);
  } catch (err) {
    error('Error getting health status:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get health status',
    });
  }
});

// ===== PMC INTEGRATION ROUTES =====

/**
 * @route   POST /api/partners/pmc/operations
 * @desc    Create coordinated PMC operation
 * @access  Private
 */
router.post('/pmc/operations', async (req, res) => {
  try {
    const userId = req.user?.id || 'system';
    const result = await pmcService.createCoordinatedOperation(req.body, userId);

    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    error('Error creating PMC operation:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create PMC operation',
    });
  }
});

/**
 * @route   GET /api/partners/pmc/operations
 * @desc    Get PMC operations
 * @access  Private
 */
router.get('/pmc/operations', (req, res) => {
  try {
    const filters = {
      status: req.query.status,
      type: req.query.type,
      priority: req.query.priority,
    };

    const result = pmcService.getOperations(filters);
    res.json(result);
  } catch (error) {
    error('Error getting PMC operations:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get PMC operations',
    });
  }
});

/**
 * @route   GET /api/partners/pmc/operations/:operationId
 * @desc    Get PMC operation details
 * @access  Private
 */
router.get('/pmc/operations/:operationId', async (req, res) => {
  try {
    const { operationId } = req.params;
    const result = await pmcService.getOperation(operationId);

    if (result.success) {
      res.json(result);
    } else {
      res.status(404).json(result);
    }
  } catch (error) {
    error('Error getting PMC operation:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get PMC operation',
    });
  }
});

/**
 * @route   PUT /api/partners/pmc/operations/:operationId/status
 * @desc    Update PMC operation status
 * @access  Private
 */
router.put('/pmc/operations/:operationId/status', async (req, res) => {
  try {
    const { operationId } = req.params;
    const { status, ...updateData } = req.body;
    const userId = req.user?.id || 'system';

    const result = await pmcService.updateOperationStatus(
      operationId,
      status,
      updateData,
      userId
    );

    if (result.success) {
      res.json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    error('Error updating PMC operation status:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update PMC operation status',
    });
  }
});

/**
 * @route   POST /api/partners/pmc/operations/:operationId/resources
 * @desc    Allocate resources to PMC operation
 * @access  Private
 */
router.post('/pmc/operations/:operationId/resources', async (_req, res) => {
  try {
    const { operationId } = _req.params;
    const userId = _req.user?.id || 'system';

    const result = await pmcService.allocateResources(operationId, _req.body, userId);

    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    error('Error allocating resources:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to allocate resources',
    });
  }
});

/**
 * @route   POST /api/partners/pmc/operations/:operationId/report
 * @desc    Generate PMC operation report
 * @access  Private
 */
router.post('/pmc/operations/:operationId/report', async (_req, res) => {
  try {
    const { operationId } = _req.params;
    const { reportType } = _req.body;
    const userId = _req.user?.id || 'system';

    const result = await pmcService.generateOperationReport(
      operationId,
      reportType,
      userId
    );

    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    error('Error generating operation report:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate operation report',
    });
  }
});

/**
 * @route   POST /api/partners/pmc/training
 * @desc    Create PMC training program
 * @access  Private
 */
router.post('/pmc/training', async (_req, res) => {
  try {
    const userId = _req.user?.id || 'system';
    const result = await pmcService.createTrainingProgram(_req.body, userId);

    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    error('Error creating training program:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create training program',
    });
  }
});

/**
 * @route   GET /api/partners/pmc/integration-status
 * @desc    Get PMC integration status
 * @access  Private
 */
router.get('/pmc/integration-status', async (_req, res) => {
  try {
    const result = await pmcService.getIntegrationStatus();
    res.json(result);
  } catch (error) {
    error('Error getting PMC integration status:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get PMC integration status',
    });
  }
});

/**
 * @route   GET /api/partners/pmc/statistics
 * @desc    Get PMC service statistics
 * @access  Private
 */
router.get('/pmc/statistics', async (_req, res) => {
  try {
    const result = await pmcService.getStatistics();
    res.json(result);
  } catch (error) {
    error('Error getting PMC statistics:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get PMC statistics',
    });
  }
});

/**
 * @route   GET /api/partners/pmc/health
 * @desc    Get PMC service health status
 * @access  Public
 */
router.get('/pmc/health', async (_req, res) => {
  try {
    const result = await pmcService.getHealthStatus();
    res.json(result);
  } catch (error) {
    error('Error getting PMC health status:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get PMC health status',
    });
  }
});

export default router;
