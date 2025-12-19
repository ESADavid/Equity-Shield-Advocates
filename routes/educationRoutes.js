/**
 * EDUCATION ROUTES
 * API endpoints for education system management
 * Part of the OWLBAN GROUP Heaven on Earth Initiative
 */

import express from 'express';
import EducationService from '../services/educationService.js';
import { createLogger } from '../config/logger.js';

const router = express.Router();
const educationService = new EducationService();
const logger = createLogger('Education-Routes');

/**
 * @route   POST /api/education/create-program
 * @desc    Create a new education program
 * @access  Protected (Admin only)
 */
router.post('/create-program', async (req, res) => {
  try {
    const programData = req.body;
    const userId = req.user?.id || req.headers['x-user-id'] || 'system';

    logger.info(`Program creation request from user: ${userId}`);

    const result = await educationService.createProgram(programData, userId);

    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error in create-program route:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message,
    });
  }
});

/**
 * @route   POST /api/education/enroll-citizen
 * @desc    Enroll a citizen in an education program
 * @access  Protected
 */
router.post('/enroll-citizen', async (req, res) => {
  try {
    const { citizenId, programId } = req.body;
    const userId = req.user?.id || req.headers['x-user-id'] || 'system';

    if (!citizenId || !programId) {
      return res.status(400).json({
        success: false,
        error: 'citizenId and programId are required',
      });
    }

    logger.info(
      `Enrollment request: citizen ${citizenId} to program ${programId}`
    );

    const result = await educationService.enrollCitizen(
      citizenId,
      programId,
      userId
    );

    if (result.success) {
      res.status(200).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error in enroll-citizen route:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message,
    });
  }
});

/**
 * @route   POST /api/education/update-progress
 * @desc    Update citizen's progress in a program
 * @access  Protected (Instructor/Admin)
 */
router.post('/update-progress', async (req, res) => {
  try {
    const { citizenId, programId, progressData } = req.body;
    const userId = req.user?.id || req.headers['x-user-id'] || 'system';

    if (!citizenId || !programId || !progressData) {
      return res.status(400).json({
        success: false,
        error: 'citizenId, programId, and progressData are required',
      });
    }

    logger.info(
      `Progress update request for citizen ${citizenId} in program ${programId}`
    );

    const result = await educationService.updateProgress(
      citizenId,
      programId,
      progressData,
      userId
    );

    if (result.success) {
      res.status(200).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error in update-progress route:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message,
    });
  }
});

/**
 * @route   GET /api/education/programs
 * @desc    Get all education programs
 * @access  Public
 */
router.get('/programs', async (req, res) => {
  try {
    const filters = {
      programType: req.query.programType,
      status: req.query.status,
      limit: parseInt(req.query.limit) || 100,
    };

    logger.info('Programs list request');

    const result = await educationService.getPrograms(filters);

    if (result.success) {
      res.status(200).json(result);
    } else {
      res.status(500).json(result);
    }
  } catch (error) {
    logger.error('Error in programs route:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message,
    });
  }
});

/**
 * @route   GET /api/education/citizen/:citizenId/progress
 * @desc    Get citizen's education progress
 * @access  Protected
 */
router.get('/citizen/:citizenId/progress', async (req, res) => {
  try {
    const { citizenId } = req.params;

    logger.info(`Progress request for citizen: ${citizenId}`);

    const result = await educationService.getCitizenProgress(citizenId);

    if (result.success) {
      res.status(200).json(result);
    } else {
      res.status(404).json(result);
    }
  } catch (error) {
    logger.error('Error in citizen progress route:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message,
    });
  }
});

/**
 * @route   POST /api/education/issue-certification
 * @desc    Issue certification to a citizen
 * @access  Protected (Admin/Instructor)
 */
router.post('/issue-certification', async (req, res) => {
  try {
    const { citizenId, programId } = req.body;
    const userId = req.user?.id || req.headers['x-user-id'] || 'system';

    if (!citizenId || !programId) {
      return res.status(400).json({
        success: false,
        error: 'citizenId and programId are required',
      });
    }

    logger.info(
      `Certification request for citizen ${citizenId} in program ${programId}`
    );

    const result = await educationService.issueCertification(
      citizenId,
      programId,
      userId
    );

    if (result.success) {
      res.status(200).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error in issue-certification route:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message,
    });
  }
});

/**
 * @route   GET /api/education/statistics
 * @desc    Get education system statistics
 * @access  Protected (Admin)
 */
router.get('/statistics', async (req, res) => {
  try {
    logger.info('Education statistics request');

    const result = await educationService.getStatistics();

    if (result.success) {
      res.status(200).json(result);
    } else {
      res.status(500).json(result);
    }
  } catch (error) {
    logger.error('Error in statistics route:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message,
    });
  }
});

/**
 * @route   POST /api/education/initialize-defaults
 * @desc    Initialize default education programs
 * @access  Protected (Admin only)
 */
router.post('/initialize-defaults', async (req, res) => {
  try {
    const userId = req.user?.id || req.headers['x-user-id'] || 'system';

    logger.info(`Initialize default programs request from user: ${userId}`);

    const result = await educationService.initializeDefaultPrograms(userId);

    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(500).json(result);
    }
  } catch (error) {
    logger.error('Error in initialize-defaults route:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message,
    });
  }
});

/**
 * @route   GET /api/education/health
 * @desc    Get education service health status
 * @access  Public
 */
router.get('/health', (req, res) => {
  try {
    const health = educationService.getHealthStatus();
    res.status(200).json(health);
  } catch (error) {
    logger.error('Error in health route:', error);
    res.status(500).json({
      status: 'error',
      error: error.message,
    });
  }
});

/**
 * @route   GET /api/education/welcome
 * @desc    Welcome message for Education API
 * @access  Public
 */
router.get('/welcome', (req, res) => {
  res.status(200).json({
    message: 'Welcome to the Education System API',
    description: 'OWLBAN GROUP - Heaven on Earth Initiative',
    mission:
      'Mandatory education in Military, Law, Technology, and Agriculture',
    features: [
      'Program creation and management',
      'Citizen enrollment',
      'Progress tracking',
      'Certification issuance',
      'AI-powered personalized learning',
      'Compliance monitoring',
    ],
    mandatoryTracks: {
      military: '6 months - Basic combat, discipline, leadership',
      law: '4 months - Constitutional law, civil rights, legal procedures',
      tech: '6 months - Programming, AI, web development, cybersecurity',
      agriculture: '4 months - Sustainable farming, hydroponics, food security',
    },
    totalRequired: '20 months for UBI eligibility',
    endpoints: {
      createProgram: 'POST /api/education/create-program',
      enrollCitizen: 'POST /api/education/enroll-citizen',
      updateProgress: 'POST /api/education/update-progress',
      getPrograms: 'GET /api/education/programs',
      getCitizenProgress: 'GET /api/education/citizen/:citizenId/progress',
      issueCertification: 'POST /api/education/issue-certification',
      statistics: 'GET /api/education/statistics',
      initializeDefaults: 'POST /api/education/initialize-defaults',
      health: 'GET /api/education/health',
    },
    version: '1.0.0',
    timestamp: new Date().toISOString(),
  });
});

export default router;
