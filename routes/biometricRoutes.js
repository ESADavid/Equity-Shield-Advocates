import express from 'express';
import biometricAuthService from '../services/biometricAuthService.js';
import { authenticate } from '../middleware/auth.js';
import winston from 'winston';

const router = express.Router();

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'biometric-routes' },
  transports: [
    new winston.transports.File({ filename: 'logs/biometric-routes.log' }),
    new winston.transports.File({
      filename: 'logs/biometric-routes-error.log',
      level: 'error',
    }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
    })
  );
}

/**
 * @route   POST /api/biometric/enroll/fingerprint
 * @desc    Enroll fingerprint biometric
 * @access  Private
 */
router.post('/enroll/fingerprint', authenticate, async (req, res) => {
  try {
    const { finger, hand, template, quality } = req.body;

    if (!finger || !hand || !template || quality === undefined) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields: finger, hand, template, quality',
      });
    }

    const result = await biometricAuthService.enrollFingerprint(
      req.user._id,
      req.tenantId,
      { finger, hand, template, quality }
    );

    logger.info('Fingerprint enrolled', {
      userId: req.user._id,
      tenantId: req.tenantId,
      finger,
      hand,
    });

    res.json(result);
  } catch (error) {
    logger.error('Fingerprint enrollment failed', {
      userId: req.user?._id,
      error: error.message,
    });

    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
});

/**
 * @route   POST /api/biometric/enroll/facial
 * @desc    Enroll facial recognition biometric
 * @access  Private
 */
router.post('/enroll/facial', authenticate, async (req, res) => {
  try {
    const { template, quality, metadata } = req.body;

    if (!template || quality === undefined) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields: template, quality',
      });
    }

    const result = await biometricAuthService.enrollFacial(
      req.user._id,
      req.tenantId,
      { template, quality, metadata: metadata || {} }
    );

    logger.info('Facial recognition enrolled', {
      userId: req.user._id,
      tenantId: req.tenantId,
    });

    res.json(result);
  } catch (error) {
    logger.error('Facial enrollment failed', {
      userId: req.user?._id,
      error: error.message,
    });

    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
});

/**
 * @route   POST /api/biometric/enroll/voice
 * @desc    Enroll voice print biometric
 * @access  Private
 */
router.post('/enroll/voice', authenticate, async (req, res) => {
  try {
    const { template, quality, metadata } = req.body;

    if (!template || quality === undefined) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields: template, quality',
      });
    }

    const result = await biometricAuthService.enrollVoice(
      req.user._id,
      req.tenantId,
      { template, quality, metadata: metadata || {} }
    );

    logger.info('Voice print enrolled', {
      userId: req.user._id,
      tenantId: req.tenantId,
    });

    res.json(result);
  } catch (error) {
    logger.error('Voice enrollment failed', {
      userId: req.user?._id,
      error: error.message,
    });

    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
});

/**
 * @route   POST /api/biometric/verify/fingerprint
 * @desc    Verify fingerprint biometric
 * @access  Private
 */
router.post('/verify/fingerprint', authenticate, async (req, res) => {
  try {
    const { template } = req.body;

    if (!template) {
      return res.status(400).json({
        success: false,
        message: 'Missing required field: template',
      });
    }

    const context = {
      ipAddress: req.ip,
      deviceId: req.headers['x-device-id'],
      userAgent: req.headers['user-agent'],
    };

    const result = await biometricAuthService.verifyFingerprint(
      req.user._id,
      req.tenantId,
      template,
      context
    );

    res.json(result);
  } catch (error) {
    logger.error('Fingerprint verification failed', {
      userId: req.user?._id,
      error: error.message,
    });

    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
});

/**
 * @route   POST /api/biometric/verify/facial
 * @desc    Verify facial recognition biometric
 * @access  Private
 */
router.post('/verify/facial', authenticate, async (req, res) => {
  try {
    const { template } = req.body;

    if (!template) {
      return res.status(400).json({
        success: false,
        message: 'Missing required field: template',
      });
    }

    const context = {
      ipAddress: req.ip,
      deviceId: req.headers['x-device-id'],
      userAgent: req.headers['user-agent'],
    };

    const result = await biometricAuthService.verifyFacial(
      req.user._id,
      req.tenantId,
      template,
      context
    );

    res.json(result);
  } catch (error) {
    logger.error('Facial verification failed', {
      userId: req.user?._id,
      error: error.message,
    });

    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
});

/**
 * @route   POST /api/biometric/verify/voice
 * @desc    Verify voice print biometric
 * @access  Private
 */
router.post('/verify/voice', authenticate, async (req, res) => {
  try {
    const { template } = req.body;

    if (!template) {
      return res.status(400).json({
        success: false,
        message: 'Missing required field: template',
      });
    }

    const context = {
      ipAddress: req.ip,
      deviceId: req.headers['x-device-id'],
      userAgent: req.headers['user-agent'],
    };

    const result = await biometricAuthService.verifyVoice(
      req.user._id,
      req.tenantId,
      template,
      context
    );

    res.json(result);
  } catch (error) {
    logger.error('Voice verification failed', {
      userId: req.user?._id,
      error: error.message,
    });

    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
});

/**
 * @route   POST /api/biometric/verify/multi
 * @desc    Verify multiple biometrics at once
 * @access  Private
 */
router.post('/verify/multi', authenticate, async (req, res) => {
  try {
    const { fingerprint, facial, voice } = req.body;

    if (!fingerprint && !facial && !voice) {
      return res.status(400).json({
        success: false,
        message: 'At least one biometric template required',
      });
    }

    const context = {
      ipAddress: req.ip,
      deviceId: req.headers['x-device-id'],
      userAgent: req.headers['user-agent'],
    };

    const result = await biometricAuthService.verifyMultipleBiometrics(
      req.user._id,
      req.tenantId,
      { fingerprint, facial, voice },
      context
    );

    res.json(result);
  } catch (error) {
    logger.error('Multi-factor biometric verification failed', {
      userId: req.user?._id,
      error: error.message,
    });

    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
});

/**
 * @route   GET /api/biometric/status
 * @desc    Get biometric enrollment status
 * @access  Private
 */
router.get('/status', authenticate, async (req, res) => {
  try {
    const status = await biometricAuthService.getBiometricStatus(
      req.user._id,
      req.tenantId
    );

    res.json({
      success: true,
      status,
    });
  } catch (error) {
    logger.error('Failed to get biometric status', {
      userId: req.user?._id,
      error: error.message,
    });

    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
});

/**
 * @route   POST /api/biometric/device/register
 * @desc    Register a device fingerprint
 * @access  Private
 */
router.post('/device/register', authenticate, async (req, res) => {
  try {
    const deviceInfo = {
      deviceType: req.body.deviceType || 'unknown',
      browser: req.headers['user-agent'],
      os: req.body.os,
      screenResolution: req.body.screenResolution,
      timezone: req.body.timezone,
      language: req.body.language,
    };

    const result = await biometricAuthService.registerDevice(
      req.user._id,
      req.tenantId,
      deviceInfo
    );

    logger.info('Device registered', {
      userId: req.user._id,
      tenantId: req.tenantId,
      deviceType: deviceInfo.deviceType,
    });

    res.json(result);
  } catch (error) {
    logger.error('Device registration failed', {
      userId: req.user?._id,
      error: error.message,
    });

    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
});

/**
 * @route   POST /api/biometric/device/verify
 * @desc    Verify a device fingerprint
 * @access  Private
 */
router.post('/device/verify', authenticate, async (req, res) => {
  try {
    const { deviceHash } = req.body;

    if (!deviceHash) {
      return res.status(400).json({
        success: false,
        message: 'Missing required field: deviceHash',
      });
    }

    const result = await biometricAuthService.verifyDevice(
      req.user._id,
      req.tenantId,
      deviceHash
    );

    res.json({
      success: true,
      ...result,
    });
  } catch (error) {
    logger.error('Device verification failed', {
      userId: req.user?._id,
      error: error.message,
    });

    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
});

export default router;
