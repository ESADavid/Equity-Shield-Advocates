/**
 * NOTIFICATION ROUTES
 * API endpoints for multi-channel notification system
 * Part of Phase 2: Heaven on Earth Implementation
 */

import express from 'express';
import MultiChannelNotificationService from '../services/multiChannelNotificationService.js';
import logger from '../utils/loggerWrapper.js';

const router = express.Router();
const notificationService = new MultiChannelNotificationService();

/**
 * @route   POST /api/notifications/send
 * @desc    Send a notification
 * @access  Private
 */
router.post('/send', async (req, res) => {
  try {
    const result = await notificationService.sendNotification(req.body);

    if (result.success) {
      res.json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (err) {
    logger.error('Error sending notification:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to send notification',
    });
  }
});

/**
 * @route   POST /api/notifications/batch
 * @desc    Send batch notifications
 * @access  Private
 */
router.post('/batch', async (req, res) => {
  try {
    const { notifications } = req.body;

    if (!Array.isArray(notifications)) {
      return res.status(400).json({
        success: false,
        error: 'Notifications must be an array',
      });
    }

    const result =
      await notificationService.sendBatchNotifications(notifications);
    res.json(result);
  } catch (err) {
    logger.error('Error sending batch notifications:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to send batch notifications',
    });
  }
});

/**
 * @route   GET /api/notifications/history/:userId
 * @desc    Get notification history for a user
 * @access  Private
 */
router.get('/history/:userId', (req, res) => {
  try {
    const { userId } = req.params;
    const filters = {
      status: req.query.status,
      priority: req.query.priority,
      startDate: req.query.startDate,
      endDate: req.query.endDate,
      page: parseInt(req.query.page) || 1,
      limit: parseInt(req.query.limit) || 50,
    };

    const result = notificationService.getNotificationHistory(userId, filters);
    res.json(result);
  } catch (err) {
    logger.error('Error getting notification history:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get notification history',
    });
  }
});

/**
 * @route   GET /api/notifications/:notificationId
 * @desc    Get notification by ID
 * @access  Private
 */
router.get('/:notificationId', (req, res) => {
  try {
    const { notificationId } = req.params;
    const result = notificationService.getNotification(notificationId);

    if (result.success) {
      res.json(result);
    } else {
      res.status(404).json(result);
    }
  } catch (err) {
    logger.error('Error getting notification:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get notification',
    });
  }
});

/**
 * @route   GET /api/notifications/preferences/:userId
 * @desc    Get user notification preferences
 * @access  Private
 */
router.get('/preferences/:userId', (req, res) => {
  try {
    const { userId } = req.params;
    const result = notificationService.getPreferences(userId);
    res.json(result);
  } catch (err) {
    logger.error('Error getting preferences:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get preferences',
    });
  }
});

/**
 * @route   PUT /api/notifications/preferences/:userId
 * @desc    Update user notification preferences
 * @access  Private
 */
router.put('/preferences/:userId', (req, res) => {
  try {
    const { userId } = req.params;
    const result = notificationService.updatePreferences(userId, req.body);
    res.json(result);
  } catch (err) {
    logger.error('Error updating preferences:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to update preferences',
    });
  }
});

/**
 * @route   GET /api/notifications/templates
 * @desc    Get available notification templates
 * @access  Private
 */
router.get('/templates', (req, res) => {
  try {
    const result = notificationService.getTemplates();
    res.json(result);
  } catch (err) {
    logger.error('Error getting templates:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get templates',
    });
  }
});

/**
 * @route   GET /api/notifications/statistics
 * @desc    Get notification service statistics
 * @access  Private
 */
router.get('/statistics', (req, res) => {
  try {
    const result = notificationService.getStatistics();
    res.json(result);
  } catch (err) {
    logger.error('Error getting statistics:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get statistics',
    });
  }
});

/**
 * @route   GET /api/notifications/health
 * @desc    Get notification service health status
 * @access  Public
 */
router.get('/health', (req, res) => {
  try {
    const result = notificationService.getHealthStatus();
    res.json(result);
  } catch (err) {
    logger.error('Error getting health status:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get health status',
    });
  }
});

export default router;
