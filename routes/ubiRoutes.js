/**
 * UNIVERSAL BASIC INCOME ROUTES
 * API endpoints for UBI system management
 * Part of the OWLBAN GROUP Heaven on Earth Initiative
 */

import express from 'express';
import UniversalBasicIncomeService from '../services/universalBasicIncomeService.js';
import { createLogger } from '../config/logger.js';

const router = express.Router();
const ubiService = new UniversalBasicIncomeService();
const logger = createLogger('UBI-Routes');

/**
 * @route   POST /api/ubi/register-citizen
 * @desc    Register a new citizen for UBI
 * @access  Protected (Admin/Registrar)
 */
router.post('/register-citizen', async (req, res) => {
  try {
    const citizenData = req.body;
    const userId = req.user?.id || req.headers['x-user-id'] || 'system';

    logger.info(`Citizen registration request from user: ${userId}`);

    const result = await ubiService.registerCitizen(citizenData, userId);

    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error in register-citizen route:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route   POST /api/ubi/process-monthly-payments
 * @desc    Process monthly UBI payments for all eligible citizens
 * @access  Protected (Admin only)
 */
router.post('/process-monthly-payments', async (req, res) => {
  try {
    const userId = req.user?.id || req.headers['x-user-id'] || 'system';

    logger.info(`Monthly payment processing initiated by user: ${userId}`);

    const result = await ubiService.processMonthlyPayments(userId);

    if (result.success) {
      res.status(200).json(result);
    } else {
      res.status(500).json(result);
    }
  } catch (error) {
    logger.error('Error in process-monthly-payments route:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route   GET /api/ubi/citizen/:citizenId
 * @desc    Get UBI status for a specific citizen
 * @access  Protected
 */
router.get('/citizen/:citizenId', async (req, res) => {
  try {
    const { citizenId } = req.params;

    logger.info(`UBI status request for citizen: ${citizenId}`);

    const result = await ubiService.getCitizenUBIStatus(citizenId);

    if (result.success) {
      res.status(200).json(result);
    } else {
      res.status(404).json(result);
    }
  } catch (error) {
    logger.error('Error in get citizen route:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route   GET /api/ubi/payment-history/:citizenId
 * @desc    Get payment history for a citizen
 * @access  Protected
 */
router.get('/payment-history/:citizenId', async (req, res) => {
  try {
    const { citizenId } = req.params;
    const { limit = 12, offset = 0 } = req.query;

    logger.info(`Payment history request for citizen: ${citizenId}`);

    // This would query payment records from the database
    // For now, returning the citizen's UBI status which includes payment info
    const result = await ubiService.getCitizenUBIStatus(citizenId);

    if (result.success) {
      res.status(200).json({
        success: true,
        citizenId: citizenId,
        paymentHistory: {
          totalReceived: result.ubiStatus.totalReceived,
          paymentsCount: result.ubiStatus.paymentsCount,
          lastPaymentDate: result.ubiStatus.lastPaymentDate,
          nextPaymentDate: result.ubiStatus.nextPaymentDate,
          monthlyAmount: result.ubiStatus.monthlyAmount,
          annualAmount: result.ubiStatus.annualAmount
        }
      });
    } else {
      res.status(404).json(result);
    }
  } catch (error) {
    logger.error('Error in payment-history route:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route   POST /api/ubi/suspend/:citizenId
 * @desc    Suspend UBI payments for a citizen
 * @access  Protected (Admin only)
 */
router.post('/suspend/:citizenId', async (req, res) => {
  try {
    const { citizenId } = req.params;
    const { reason } = req.body;
    const userId = req.user?.id || req.headers['x-user-id'] || 'system';

    if (!reason) {
      return res.status(400).json({
        success: false,
        error: 'Suspension reason is required'
      });
    }

    logger.info(`UBI suspension request for citizen ${citizenId} by user: ${userId}`);

    const result = await ubiService.suspendUBI(citizenId, reason, userId);

    if (result.success) {
      res.status(200).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error in suspend route:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route   POST /api/ubi/reinstate/:citizenId
 * @desc    Reinstate UBI payments for a citizen
 * @access  Protected (Admin only)
 */
router.post('/reinstate/:citizenId', async (req, res) => {
  try {
    const { citizenId } = req.params;
    const userId = req.user?.id || req.headers['x-user-id'] || 'system';

    logger.info(`UBI reinstatement request for citizen ${citizenId} by user: ${userId}`);

    const result = await ubiService.reinstateUBI(citizenId, userId);

    if (result.success) {
      res.status(200).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error in reinstate route:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route   POST /api/ubi/verify-eligibility/:citizenId
 * @desc    Verify UBI eligibility for a citizen
 * @access  Protected
 */
router.post('/verify-eligibility/:citizenId', async (req, res) => {
  try {
    const { citizenId } = req.params;

    logger.info(`Eligibility verification request for citizen: ${citizenId}`);

    const result = await ubiService.getCitizenUBIStatus(citizenId);

    if (result.success) {
      res.status(200).json({
        success: true,
        citizenId: citizenId,
        eligibility: result.eligibility,
        ubiStatus: {
          eligible: result.ubiStatus.eligible,
          suspended: result.ubiStatus.suspended,
          suspensionReason: result.ubiStatus.suspensionReason
        },
        educationCompliance: {
          status: result.educationStatus.complianceStatus,
          progress: result.educationStatus.overallProgress,
          military: result.educationStatus.military,
          law: result.educationStatus.law,
          tech: result.educationStatus.tech,
          agriculture: result.educationStatus.agriculture
        },
        verification: result.verification
      });
    } else {
      res.status(404).json(result);
    }
  } catch (error) {
    logger.error('Error in verify-eligibility route:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route   GET /api/ubi/statistics
 * @desc    Get UBI system statistics
 * @access  Protected (Admin only)
 */
router.get('/statistics', async (req, res) => {
  try {
    logger.info('System statistics request');

    const result = await ubiService.getSystemStatistics();

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
      message: error.message
    });
  }
});

/**
 * @route   GET /api/ubi/health
 * @desc    Get UBI service health status
 * @access  Public
 */
router.get('/health', (req, res) => {
  try {
    const health = ubiService.getHealthStatus();
    res.status(200).json(health);
  } catch (error) {
    logger.error('Error in health route:', error);
    res.status(500).json({
      status: 'error',
      error: error.message
    });
  }
});

/**
 * @route   GET /api/ubi/welcome
 * @desc    Welcome message for UBI API
 * @access  Public
 */
router.get('/welcome', (req, res) => {
  res.status(200).json({
    message: 'Welcome to the Universal Basic Income API',
    description: 'OWLBAN GROUP - Heaven on Earth Initiative',
    mission: '$33,000 per year for every citizen',
    features: [
      'Citizen registration',
      'Monthly payment processing',
      'Education compliance tracking',
      'Blockchain transparency',
      'Real-time eligibility verification'
    ],
    endpoints: {
      registerCitizen: 'POST /api/ubi/register-citizen',
      processPayments: 'POST /api/ubi/process-monthly-payments',
      getCitizen: 'GET /api/ubi/citizen/:citizenId',
      paymentHistory: 'GET /api/ubi/payment-history/:citizenId',
      suspend: 'POST /api/ubi/suspend/:citizenId',
      reinstate: 'POST /api/ubi/reinstate/:citizenId',
      verifyEligibility: 'POST /api/ubi/verify-eligibility/:citizenId',
      statistics: 'GET /api/ubi/statistics',
      health: 'GET /api/ubi/health'
    },
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

export default router;
