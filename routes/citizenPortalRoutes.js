/**
 * CITIZEN PORTAL ROUTES
 * API endpoints for citizen-facing portal
 * Part of Phase 2: Heaven on Earth Implementation
 */

import express from 'express';
import CitizenPortalService from '../services/citizenPortalService.js';
import { info, error, warn, debug } from 'utils/loggerWrapper.js';

const router = express.Router();
const portalService = new CitizenPortalService();

/**
 * @route   POST /api/citizen-portal/register
 * @desc    Register a new citizen
 * @access  Public
 */
router.post('/register', async (req, res) => {
  try {
    const result = await portalService.registerCitizen(req.body);

    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    error('Error registering citizen:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to register citizen',
    });
  }
});

/**
 * @route   GET /api/citizen-portal/profile/:citizenId
 * @desc    Get citizen profile
 * @access  Private
 */
router.get('/profile/:citizenId', (req, res) => {
  try {
    const { citizenId } = req.params;
    const result = portalService.getCitizenProfile(citizenId);

    if (result.success) {
      res.json(result);
    } else {
      res.status(404).json(result);
    }
  } catch (error) {
    error('Error getting citizen profile:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get citizen profile',
    });
  }
});

/**
 * @route   PUT /api/citizen-portal/profile/:citizenId
 * @desc    Update citizen profile
 * @access  Private
 */
router.put('/profile/:citizenId', (req, res) => {
  try {
    const { citizenId } = req.params;
    const result = portalService.updateCitizenProfile(citizenId, req.body);

    if (result.success) {
      res.json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    error('Error updating citizen profile:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update citizen profile',
    });
  }
});

/**
 * @route   POST /api/citizen-portal/:citizenId/ubi/enroll
 * @desc    Enroll citizen in UBI program
 * @access  Private
 */
router.post('/:citizenId/ubi/enroll', async (req, res) => {
  try {
    const { citizenId } = req.params;
    const result = await portalService.enrollInUBI(citizenId, req.body);

    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    error('Error enrolling in UBI:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to enroll in UBI',
    });
  }
});

/**
 * @route   POST /api/citizen-portal/:citizenId/education/enroll
 * @desc    Enroll citizen in education course
 * @access  Private
 */
router.post('/:citizenId/education/enroll', async (req, res) => {
  try {
    const { citizenId } = req.params;
    const { courseId } = req.body;

    const result = await portalService.enrollInCourse(citizenId, courseId);

    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    error('Error enrolling in course:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to enroll in course',
    });
  }
});

/**
 * @route   POST /api/citizen-portal/:citizenId/service-requests
 * @desc    Create service request
 * @access  Private
 */
router.post('/:citizenId/service-requests', async (req, res) => {
  try {
    const { citizenId } = req.params;
    const result = await portalService.createServiceRequest(
      citizenId,
      req.body
    );

    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    error('Error creating service request:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create service request',
    });
  }
});

/**
 * @route   GET /api/citizen-portal/service-requests/:requestId
 * @desc    Get service request details
 * @access  Private
 */
router.get('/service-requests/:requestId', (req, res) => {
  try {
    const { requestId } = req.params;
    const result = portalService.getServiceRequest(requestId);

    if (result.success) {
      res.json(result);
    } else {
      res.status(404).json(result);
    }
  } catch (error) {
    error('Error getting service request:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get service request',
    });
  }
});

/**
 * @route   POST /api/citizen-portal/:citizenId/documents
 * @desc    Upload document
 * @access  Private
 */
router.post('/:citizenId/documents', async (req, res) => {
  try {
    const { citizenId } = req.params;
    const result = await portalService.uploadDocument(citizenId, req.body);

    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    error('Error uploading document:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to upload document',
    });
  }
});

/**
 * @route   GET /api/citizen-portal/:citizenId/notifications
 * @desc    Get citizen notifications
 * @access  Private
 */
router.get('/:citizenId/notifications', (req, res) => {
  try {
    const { citizenId } = req.params;
    const filters = {
      unreadOnly: req.query.unreadOnly === 'true',
    };

    const result = portalService.getCitizenNotifications(citizenId, filters);
    res.json(result);
  } catch (error) {
    error('Error getting notifications:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get notifications',
    });
  }
});

/**
 * @route   GET /api/citizen-portal/statistics
 * @desc    Get citizen portal statistics
 * @access  Private
 */
router.get('/statistics', (req, res) => {
  try {
    const result = portalService.getStatistics();
    res.json(result);
  } catch (error) {
    error('Error getting statistics:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get statistics',
    });
  }
});

/**
 * @route   GET /api/citizen-portal/health
 * @desc    Get citizen portal health status
 * @access  Public
 */
router.get('/health', (req, res) => {
  try {
    const result = portalService.getHealthStatus();
    res.json(result);
  } catch (error) {
    error('Error getting health status:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get health status',
    });
  }
});

export default router;
