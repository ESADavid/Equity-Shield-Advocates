/**
 * PARTNER ROUTES
 * API endpoints for partner management and coordination
 * Part of Phase 2: Heaven on Earth Implementation
 */

import express from 'express';
import PartnerCoordinationService from '../services/partnerCoordinationService.js';
import PMCIntegrationService from '../services/pmcIntegrationService.js';
import { createLogger } from '../config/logger.js';

const router = express.Router();
const logger = createLogger('Partner-Routes');
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
  } catch (error) {
    logger.error('Error onboarding partner:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to onboard partner'
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
      minRating: parseFloat(req.query.minRating),
      sortBy: req.query.sortBy
    };

    const result = partnerService.getPartners(filters);
    res.json(result);
  } catch (error) {
    logger.error('Error getting partners:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get partners'
    });
  }
});

/**
 * @route   GET /api/partners/:partnerId
 * @desc    Get partner details
 * @access  Private
 */
router.get('/:partnerId', (req, res) => {
  try {
    const { partnerId } = req.params;
    const result = partnerService.getPartner(partnerId);
    
    if (result.success) {
      res.json(result);
    } else {
      res.status(404).json(result);
    }
  } catch (error) {
    logger.error('Error getting partner:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get partner'
    });
  }
});

/**
 * @route   POST /api/partners/:partnerId/activate
 * @desc    Activate a partner
 * @access  Private
 */
router.post('/:partnerId/activate', (req, res) => {
  try {
    const { partnerId } = req.params;
    const userId = req.user?.id || 'system';
    
    const result = partnerService.activatePartner(partnerId, userId);
    
    if (result.success) {
      res.json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error activating partner:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to activate partner'
    });
  }
});

/**
 * @route   POST /api/partners/:partnerId/projects
 * @desc    Assign project to partner
 * @access  Private
 */
router.post('/:partnerId/projects', (req, res) => {
  try {
    const { partnerId } = req.params;
    const userId = req.user?.id || 'system';
    
    const result = partnerService.assignProject(partnerId, req.body, userId);
    
    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error assigning project:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to assign project'
    });
  }
});

/**
 * @route   PUT /api/partners/projects/:projectId
 * @desc    Update project status
 * @access  Private
 */
router.put('/projects/:projectId', (req, res) => {
  try {
    const { projectId } = req.params;
    const { status, ...updateData } = req.body;
    const userId = req.user?.id || 'system';
    
    const result = partnerService.updateProjectStatus(projectId, status, updateData, userId);
    
    if (result.success) {
      res.json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error updating project:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update project'
    });
  }
});

/**
 * @route   POST /api/partners/:partnerId/communication
 * @desc    Log communication with partner
 * @access  Private
 */
router.post('/:partnerId/communication', (req, res) => {
  try {
    const { partnerId } = req.params;
    const userId = req.user?.id || 'system';
    
    const result = partnerService.logCommunication(partnerId, req.body, userId);
    
    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error logging communication:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to log communication'
    });
  }
});

/**
 * @route   POST /api/partners/:partnerId/rating
 * @desc    Update partner performance rating
 * @access  Private
 */
router.post('/:partnerId/rating', (req, res) => {
  try {
    const { partnerId } = req.params;
    const userId = req.user?.id || 'system';
    
    const result = partnerService.updatePerformanceRating(partnerId, req.body, userId);
    
    if (result.success) {
      res.json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error updating rating:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update rating'
    });
  }
});

/**
 * @route   PUT /api/partners/workflows/:workflowId/steps/:stepId
 * @desc    Update workflow step status
 * @access  Private
 */
router.put('/workflows/:workflowId/steps/:stepId', (req, res) => {
  try {
    const { workflowId, stepId } = req.params;
    const { status } = req.body;
    const userId = req.user?.id || 'system';
    
    const result = partnerService.updateWorkflowStep(workflowId, stepId, status, userId);
    
    if (result.success) {
      res.json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error updating workflow step:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update workflow step'
    });
  }
});

/**
 * @route   GET /api/partners/statistics
 * @desc    Get partner service statistics
 * @access  Private
 */
router.get('/statistics', (req, res) => {
  try {
    const result = partnerService.getStatistics();
    res.json(result);
  } catch (error) {
    logger.error('Error getting statistics:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get statistics'
    });
  }
});

/**
 * @route   GET /api/partners/health
 * @desc    Get partner service health status
 * @access  Public
 */
router.get('/health', (req, res) => {
  try {
    const result = partnerService.getHealthStatus();
    res.json(result);
  } catch (error) {
    logger.error('Error getting health status:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get health status'
    });
  }
});

// ===== PMC INTEGRATION ROUTES =====

/**
 * @route   POST /api/partners/pmc/operations
 * @desc    Create coordinated PMC operation
 * @access  Private
 */
router.post('/pmc/operations', (req, res) => {
  try {
    const userId = req.user?.id || 'system';
    const result = pmcService.createCoordinatedOperation(req.body, userId);
    
    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error creating PMC operation:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create PMC operation'
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
      priority: req.query.priority
    };

    const result = pmcService.getOperations(filters);
    res.json(result);
  } catch (error) {
    logger.error('Error getting PMC operations:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get PMC operations'
    });
  }
});

/**
 * @route   GET /api/partners/pmc/operations/:operationId
 * @desc    Get PMC operation details
 * @access  Private
 */
router.get('/pmc/operations/:operationId', (req, res) => {
  try {
    const { operationId } = req.params;
    const result = pmcService.getOperation(operationId);
    
    if (result.success) {
      res.json(result);
    } else {
      res.status(404).json(result);
    }
  } catch (error) {
    logger.error('Error getting PMC operation:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get PMC operation'
    });
  }
});

/**
 * @route   PUT /api/partners/pmc/operations/:operationId/status
 * @desc    Update PMC operation status
 * @access  Private
 */
router.put('/pmc/operations/:operationId/status', (req, res) => {
  try {
    const { operationId } = req.params;
    const { status, ...updateData } = req.body;
    const userId = req.user?.id || 'system';
    
    const result = pmcService.updateOperationStatus(operationId, status, updateData, userId);
    
    if (result.success) {
      res.json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error updating PMC operation status:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update PMC operation status'
    });
  }
});

/**
 * @route   POST /api/partners/pmc/operations/:operationId/resources
 * @desc    Allocate resources to PMC operation
 * @access  Private
 */
router.post('/pmc/operations/:operationId/resources', (req, res) => {
  try {
    const { operationId } = req.params;
    const userId = req.user?.id || 'system';
    
    const result = pmcService.allocateResources(operationId, req.body, userId);
    
    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error allocating resources:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to allocate resources'
    });
  }
});

/**
 * @route   POST /api/partners/pmc/operations/:operationId/report
 * @desc    Generate PMC operation report
 * @access  Private
 */
router.post('/pmc/operations/:operationId/report', (req, res) => {
  try {
    const { operationId } = req.params;
    const { reportType } = req.body;
    const userId = req.user?.id || 'system';
    
    const result = pmcService.generateOperationReport(operationId, reportType, userId);
    
    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error generating operation report:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate operation report'
    });
  }
});

/**
 * @route   POST /api/partners/pmc/training
 * @desc    Create PMC training program
 * @access  Private
 */
router.post('/pmc/training', (req, res) => {
  try {
    const userId = req.user?.id || 'system';
    const result = pmcService.createTrainingProgram(req.body, userId);
    
    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error creating training program:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create training program'
    });
  }
});

/**
 * @route   GET /api/partners/pmc/integration-status
 * @desc    Get PMC integration status
 * @access  Private
 */
router.get('/pmc/integration-status', (req, res) => {
  try {
    const result = pmcService.getIntegrationStatus();
    res.json(result);
  } catch (error) {
    logger.error('Error getting PMC integration status:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get PMC integration status'
    });
  }
});

/**
 * @route   GET /api/partners/pmc/statistics
 * @desc    Get PMC service statistics
 * @access  Private
 */
router.get('/pmc/statistics', (req, res) => {
  try {
    const result = pmcService.getStatistics();
    res.json(result);
  } catch (error) {
    logger.error('Error getting PMC statistics:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get PMC statistics'
    });
  }
});

/**
 * @route   GET /api/partners/pmc/health
 * @desc    Get PMC service health status
 * @access  Public
 */
router.get('/pmc/health', (req, res) => {
  try {
    const result = pmcService.getHealthStatus();
    res.json(result);
  } catch (error) {
    logger.error('Error getting PMC health status:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get PMC health status'
    });
  }
});

export default router;
