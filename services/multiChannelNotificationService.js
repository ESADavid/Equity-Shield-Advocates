/**
 * MULTI-CHANNEL NOTIFICATION SERVICE
 * Enhanced notification system with preferences, history, and multi-channel delivery
 * Part of Phase 2: Heaven on Earth Implementation
 *
 * Features:
 * - Email, SMS, Push, In-App notifications
 * - User preferences management
 * - Notification history and tracking
 * - Template management
 * - Delivery status tracking
 * - Priority-based delivery
 * - Batch notifications
 */

import { info, error, warn, debug } from 'utils/loggerWrapper.js';
import nodemailer from 'nodemailer';

class MultiChannelNotificationService {
  constructor() {
    this.notifications = new Map();
    this.preferences = new Map();
    this.templates = new Map();
    this.deliveryLog = new Map();
    this.emailTransporter = null;

    this.initializeEmailService();
    this.initializeTemplates();

    info('Multi-Channel Notification Service initialized');
  }

  /**
   * Initialize email service
   */
  initializeEmailService() {
    try {
      if (
        process.env.SMTP_HOST &&
        process.env.SMTP_USER &&
        process.env.SMTP_PASS
      ) {
        this.emailTransporter = nodemailer.createTransporter({
          host: process.env.SMTP_HOST,
          port: process.env.SMTP_PORT || 587,
          secure: false,
          auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
          },
        });
        info('Email service initialized');
      } else {
        warn('Email service not configured - set SMTP environment variables');
      }
} catch (err) {
      error('Error initializing email service:', err);
    }
  }

  /**
   * Initialize notification templates
   */
  initializeTemplates() {
    const defaultTemplates = [
      {
        id: 'ubi-payment-success',
        name: 'UBI Payment Success',
        channels: ['email', 'sms', 'push', 'in-app'],
        subject: 'UBI Payment Processed Successfully',
        emailBody:
          '<h2>UBI Payment Confirmation</h2>' +
          '<p>Dear ' +
          '{{citizenName}}' +
          ',</p>' +
          '<p>Your Universal Basic Income payment has been processed successfully.</p>' +
          '<p><strong>Amount:</strong> $' +
          '{{paymentAmount}}' +
          '</p>' +
          '<p><strong>Payment Date:</strong> ' +
          '{{paymentDate}}' +
          '</p>' +
          '<p><strong>Reference:</strong> ' +
          '{{reference}}' +
          '</p>' +
          '<p>Thank you for being part of the Heaven on Earth initiative.</p>',
        smsBody:
          'UBI Payment: $' +
          '{{paymentAmount}}' +
          ' processed successfully. Ref: ' +
          '{{reference}}',
        pushBody:
          'Your UBI payment of $' + '{{paymentAmount}}' + ' has been processed',
        priority: 'high',
      },
      {
        id: 'education-enrollment',
        name: 'Education Course Enrollment',
        channels: ['email', 'push', 'in-app'],
        subject: 'Course Enrollment Confirmation',
        emailBody:
          '<h2>Course Enrollment Confirmed</h2>' +
          '<p>Dear ' +
          '{{studentName}}' +
          ',</p>' +
          '<p>You have been successfully enrolled in:</p>' +
          '<p><strong>Course:</strong> ' +
          '{{courseName}}' +
          '</p>' +
          '<p><strong>Start Date:</strong> ' +
          '{{startDate}}' +
          '</p>' +
          '<p><strong>Instructor:</strong> ' +
          '{{instructor}}' +
          '</p>' +
          '<p>Access your course materials in the education portal.</p>',
        pushBody:
          'Enrolled in ' +
          '{{courseName}}' +
          '. Start date: ' +
          '{{startDate}}',
        priority: 'medium',
      },
      {
        id: 'compliance-alert',
        name: 'Compliance Alert',
        channels: ['email', 'sms', 'push'],
        subject: 'Compliance Alert - Action Required',
        emailBody:
          '<h2>Compliance Alert</h2>' +
          '<p><strong>Alert Type:</strong> ' +
          '{{alertType}}' +
          '</p>' +
          '<p><strong>Severity:</strong> ' +
          '{{severity}}' +
          '</p>' +
          '<p><strong>Description:</strong> ' +
          '{{description}}' +
          '</p>' +
          '<p><strong>Action Required:</strong> ' +
          '{{action}}' +
          '</p>' +
          '<p>Please address this issue immediately.</p>',
        smsBody:
          'COMPLIANCE ALERT: ' +
          '{{alertType}}' +
          ' - ' +
          '{{severity}}' +
          '. Action required.',
        pushBody: 'Compliance Alert: ' + '{{alertType}}',
        priority: 'critical',
      },
      {
        id: 'partner-update',
        name: 'Partner Update',
        channels: ['email', 'in-app'],
        subject: 'Partner Update - ' + '{{updateType}}',
        emailBody:
          '<h2>Partner Update</h2>' +
          '<p>Dear ' +
          '{{partnerName}}' +
          ',</p>' +
          '<p><strong>Update Type:</strong> ' +
          '{{updateType}}' +
          '</p>' +
          '<p><strong>Details:</strong> ' +
          '{{details}}' +
          '</p>' +
          '<p><strong>Date:</strong> ' +
          '{{updateDate}}' +
          '</p>' +
          '<p>Please review this update in your partner portal.</p>',
        pushBody: 'Partner Update: ' + '{{updateType}}',
        priority: 'medium',
      },
      {
        id: 'citizen-welcome',
        name: 'Citizen Welcome',
        channels: ['email', 'sms', 'push'],
        subject: 'Welcome to Heaven on Earth Initiative',
        emailBody:
          '<h2>Welcome to Heaven on Earth!</h2>' +
          '<p>Dear ' +
          '{{citizenName}}' +
          ',</p>' +
          '<p>Welcome to the Heaven on Earth initiative. Your registration is complete.</p>' +
          '<p><strong>Citizen ID:</strong> ' +
          '{{citizenId}}' +
          '</p>' +
          '<p><strong>Registration Date:</strong> ' +
          '{{registrationDate}}' +
          '</p>' +
          '<p>You now have access to:</p>' +
          '<ul>' +
          '<li>Universal Basic Income (UBI) Program</li>' +
          '<li>AI-Powered Education System</li>' +
          '<li>Healthcare Services</li>' +
          '<li>Community Resources</li>' +
          '</ul>' +
          '<p>Access your citizen portal to get started.</p>',
        smsBody:
          'Welcome to Heaven on Earth! Your Citizen ID: ' + '{{citizenId}}',
        pushBody: 'Welcome! Your registration is complete.',
        priority: 'high',
      },
    ];

    for (const template of defaultTemplates) {
      this.templates.set(template.id, {
        ...template,
        createdAt: new Date().toISOString(),
      });
    }

    info(`Initialized ${defaultTemplates.length} notification templates`);
  }

  /**
   * Send notification through multiple channels
   * @param {Object} notificationData - Notification details
   * @returns {Object} Send result
   */
  async sendNotification(notificationData) {
    try {
      const {
        userId,
        templateId,
        channels = ['email', 'push', 'in-app'],
        data = {},
        priority = 'medium',
        scheduledFor = null,
      } = notificationData;

      // Get template
      const template = this.templates.get(templateId);
      if (!template) {
        return {
          success: false,
          error: 'Template not found',
        };
      }

      // Get user preferences
      const userPreferences = this.preferences.get(userId) || {
        email: true,
        sms: true,
        push: true,
        inApp: true,
      };

      // Create notification record
      const notificationId = `NOTIF-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

      const notification = {
        id: notificationId,
        userId: userId,
        templateId: templateId,
        templateName: template.name,
        priority: priority,
        channels: channels,
        data: data,
        status: scheduledFor ? 'scheduled' : 'pending',
        scheduledFor: scheduledFor,
        createdAt: new Date().toISOString(),
        deliveryStatus: {},
      };

      this.notifications.set(notificationId, notification);

      // If scheduled, don't send immediately
      if (scheduledFor) {
        info(`Notification ${notificationId} scheduled for ${scheduledFor}`);
        return {
          success: true,
          notificationId: notificationId,
          status: 'scheduled',
          scheduledFor: scheduledFor,
        };
      }

      // Send through enabled channels
      const deliveryResults = {};

      for (const channel of channels) {
        if (this.isChannelEnabled(channel, userPreferences)) {
          try {
            const result = await this.sendToChannel(
              channel,
              template,
              data,
              userId
            );
            deliveryResults[channel] = result;

            // Log delivery
            this.logDelivery(notificationId, channel, result);
          } catch (error) {
            error(`Error sending to ${channel}:`, error);
            deliveryResults[channel] = {
              success: false,
              error: error.message,
            };
          }
        } else {
          deliveryResults[channel] = {
            success: false,
            reason: 'Channel disabled by user preferences',
          };
        }
      }

      // Update notification status
      notification.status = 'sent';
      notification.sentAt = new Date().toISOString();
      notification.deliveryStatus = deliveryResults;

      info(
        `Notification ${notificationId} sent through ${Object.keys(deliveryResults).length} channels`
      );

      return {
        success: true,
        notificationId: notificationId,
        deliveryResults: deliveryResults,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      error('Error sending notification:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Send notification to specific channel
   * @param {string} channel - Channel type
   * @param {Object} template - Notification template
   * @param {Object} data - Template data
   * @param {string} userId - User ID
   * @returns {Object} Send result
   */
  async sendToChannel(channel, template, data, userId) {
    switch (channel) {
      case 'email':
        return await this.sendEmail(template, data, userId);
      case 'sms':
        return await this.sendSMS(template, data, userId);
      case 'push':
        return await this.sendPush(template, data, userId);
      case 'in-app':
        return await this.sendInApp(template, data, userId);
      default:
        return {
          success: false,
          error: 'Unknown channel',
        };
    }
  }

  /**
   * Send email notification
   */
  async sendEmail(template, data, userId) {
    try {
      if (!this.emailTransporter) {
        return {
          success: false,
          error: 'Email service not configured',
        };
      }

      const subject = this.replaceTemplateVariables(template.subject, data);
      const body = this.replaceTemplateVariables(template.emailBody, data);

      // In production, get user email from database
      const userEmail = data.email || `user-${userId}@example.com`;

      await this.emailTransporter.sendMail({
        from: process.env.SMTP_USER,
        to: userEmail,
        subject: subject,
        html: body,
      });

      return {
        success: true,
        channel: 'email',
        recipient: userEmail,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      error('Email send error:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Send SMS notification
   */
  async sendSMS(template, data, userId) {
    try {
      const message = this.replaceTemplateVariables(template.smsBody, data);

      // In production, integrate with Twilio or similar service
      const phoneNumber = data.phone || `+1234567890`;

      info(`SMS sent to ${phoneNumber}: ${message}`);

      return {
        success: true,
        channel: 'sms',
        recipient: phoneNumber,
        message: message,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      error('SMS send error:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Send push notification
   */
  async sendPush(template, data, userId) {
    try {
      const message = this.replaceTemplateVariables(template.pushBody, data);

      // In production, integrate with Firebase Cloud Messaging or similar
      info(`Push notification sent to user ${userId}: ${message}`);

      return {
        success: true,
        channel: 'push',
        recipient: userId,
        message: message,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      error('Push notification error:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Send in-app notification
   */
  async sendInApp(template, data, userId) {
    try {
      const message = this.replaceTemplateVariables(template.pushBody, data);

      // Store in-app notification
      const inAppNotification = {
        userId: userId,
        message: message,
        priority: template.priority,
        read: false,
        createdAt: new Date().toISOString(),
      };

      // In production, store in database and emit via WebSocket
      info(`In-app notification created for user ${userId}`);

      return {
        success: true,
        channel: 'in-app',
        recipient: userId,
        notification: inAppNotification,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      error('In-app notification error:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Replace template variables with actual data
   */
  replaceTemplateVariables(template, data) {
    let result = template;
    for (const [key, value] of Object.entries(data)) {
      // Use a simpler string replacement approach to avoid regex escaping issues
      const placeholder = `{{${key}}}`;
      result = result.split(placeholder).join(value);
    }
    return result;
  }

  /**
   * Check if channel is enabled for user
   */
  isChannelEnabled(channel, preferences) {
    const channelMap = {
      email: preferences.email,
      sms: preferences.sms,
      push: preferences.push,
      'in-app': preferences.inApp,
    };
    return channelMap[channel] !== false;
  }

  /**
   * Log notification delivery
   */
  logDelivery(notificationId, channel, result) {
    const logEntry = {
      notificationId: notificationId,
      channel: channel,
      success: result.success,
      timestamp: new Date().toISOString(),
      details: result,
    };

    const logKey = `${notificationId}-${channel}`;
    this.deliveryLog.set(logKey, logEntry);
  }

  /**
   * Update user notification preferences
   * @param {string} userId - User ID
   * @param {Object} preferences - Notification preferences
   * @returns {Object} Update result
   */
  updatePreferences(userId, preferences) {
    try {
      const currentPreferences = this.preferences.get(userId) || {};

      const updatedPreferences = {
        ...currentPreferences,
        ...preferences,
        updatedAt: new Date().toISOString(),
      };

      this.preferences.set(userId, updatedPreferences);

      info(`Updated notification preferences for user ${userId}`);

      return {
        success: true,
        preferences: updatedPreferences,
      };
    } catch (error) {
      error('Error updating preferences:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get user notification preferences
   * @param {string} userId - User ID
   * @returns {Object} User preferences
   */
  getPreferences(userId) {
    try {
      const preferences = this.preferences.get(userId) || {
        email: true,
        sms: true,
        push: true,
        inApp: true,
      };

      return {
        success: true,
        preferences: preferences,
      };
    } catch (error) {
      error('Error getting preferences:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get notification history for user
   * @param {string} userId - User ID
   * @param {Object} filters - Filter options
   * @returns {Object} Notification history
   */
  getNotificationHistory(userId, filters = {}) {
    try {
      let notifications = Array.from(this.notifications.values()).filter(
        (n) => n.userId === userId
      );

      // Apply filters
      if (filters.status) {
        notifications = notifications.filter(
          (n) => n.status === filters.status
        );
      }

      if (filters.priority) {
        notifications = notifications.filter(
          (n) => n.priority === filters.priority
        );
      }

      if (filters.startDate) {
        notifications = notifications.filter(
          (n) => new Date(n.createdAt) >= new Date(filters.startDate)
        );
      }

      if (filters.endDate) {
        notifications = notifications.filter(
          (n) => new Date(n.createdAt) <= new Date(filters.endDate)
        );
      }

      // Sort by date (newest first)
      notifications.sort(
        (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
      );

      // Apply pagination
      const page = filters.page || 1;
      const limit = filters.limit || 50;
      const startIndex = (page - 1) * limit;
      const endIndex = startIndex + limit;
      const paginatedNotifications = notifications.slice(startIndex, endIndex);

      return {
        success: true,
        notifications: paginatedNotifications,
        pagination: {
          page: page,
          limit: limit,
          total: notifications.length,
          pages: Math.ceil(notifications.length / limit),
        },
      };
    } catch (error) {
      error('Error getting notification history:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get notification by ID
   * @param {string} notificationId - Notification ID
   * @returns {Object} Notification details
   */
  getNotification(notificationId) {
    try {
      const notification = this.notifications.get(notificationId);

      if (!notification) {
        return {
          success: false,
          error: 'Notification not found',
        };
      }

      return {
        success: true,
        notification: notification,
      };
    } catch (error) {
      error('Error getting notification:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Send batch notifications
   * @param {Array} notifications - Array of notification data
   * @returns {Object} Batch send result
   */
  async sendBatchNotifications(notifications) {
    try {
      const results = [];

      for (const notificationData of notifications) {
        const result = await this.sendNotification(notificationData);
        results.push({
          userId: notificationData.userId,
          result: result,
        });
      }

      const successCount = results.filter((r) => r.result.success).length;
      const failureCount = results.length - successCount;

      info(
        `Batch notifications sent: ${successCount} success, ${failureCount} failed`
      );

      return {
        success: true,
        total: results.length,
        successful: successCount,
        failed: failureCount,
        results: results,
      };
    } catch (error) {
      error('Error sending batch notifications:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get available templates
   * @returns {Object} Templates list
   */
  getTemplates() {
    try {
      const templates = Array.from(this.templates.values());

      return {
        success: true,
        templates: templates.map((t) => ({
          id: t.id,
          name: t.name,
          channels: t.channels,
          priority: t.priority,
        })),
        count: templates.length,
      };
    } catch (error) {
      error('Error getting templates:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get service statistics
   * @returns {Object} Service statistics
   */
  getStatistics() {
    try {
      const notifications = Array.from(this.notifications.values());
      const deliveryLogs = Array.from(this.deliveryLog.values());

      const stats = {
        totalNotifications: notifications.length,
        byStatus: {
          pending: notifications.filter((n) => n.status === 'pending').length,
          sent: notifications.filter((n) => n.status === 'sent').length,
          scheduled: notifications.filter((n) => n.status === 'scheduled')
            .length,
          failed: notifications.filter((n) => n.status === 'failed').length,
        },
        byPriority: {
          critical: notifications.filter((n) => n.priority === 'critical')
            .length,
          high: notifications.filter((n) => n.priority === 'high').length,
          medium: notifications.filter((n) => n.priority === 'medium').length,
          low: notifications.filter((n) => n.priority === 'low').length,
        },
        deliveryStats: {
          totalDeliveries: deliveryLogs.length,
          successful: deliveryLogs.filter((l) => l.success).length,
          failed: deliveryLogs.filter((l) => !l.success).length,
          byChannel: {
            email: deliveryLogs.filter((l) => l.channel === 'email').length,
            sms: deliveryLogs.filter((l) => l.channel === 'sms').length,
            push: deliveryLogs.filter((l) => l.channel === 'push').length,
            inApp: deliveryLogs.filter((l) => l.channel === 'in-app').length,
          },
        },
        templates: this.templates.size,
        users: this.preferences.size,
      };

      return {
        success: true,
        statistics: stats,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      error('Error getting statistics:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get service health status
   * @returns {Object} Health status
   */
  getHealthStatus() {
    return {
      status: 'operational',
      service: 'Multi-Channel Notification Service',
      emailService: this.emailTransporter ? 'configured' : 'not configured',
      templates: this.templates.size,
      activeNotifications: this.notifications.size,
      lastCheck: new Date().toISOString(),
    };
  }
}

export default MultiChannelNotificationService;
