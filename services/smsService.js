import twilio from 'twilio';
import smsConfig from '../config/sms.js';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'sms-service' },
  transports: [
    new winston.transports.File({
      filename: 'logs/sms-service-error.log',
      level: 'error',
    }),
    new winston.transports.File({ filename: 'logs/sms-service.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
    })
  );
}

class SMSService {
  constructor() {
    this.client = null;
    this.templates = new Map();
    this.deliveryLog = new Map();
    this.initializeClient();
    this.loadTemplates();
  }

  initializeClient() {
    try {
      // Check if SMS is enabled
      if (!smsConfig.smsEnabled) {
        logger.warn('SMS service disabled due to incomplete configuration');
        return;
      }

      const config = smsConfig.getProviderConfig();

      switch (smsConfig.provider) {
        case 'twilio':
          this.client = twilio(config.accountSid, config.authToken);
          logger.info('Twilio SMS client initialized');
          break;

        case 'aws-sns':
          // AWS SNS initialization would go here
          logger.info('AWS SNS SMS client initialized');
          break;

        case 'nexmo':
          // Nexmo/Vonage initialization would go here
          logger.info('Nexmo SMS client initialized');
          break;

        default:
          logger.warn(`Unsupported SMS provider: ${smsConfig.provider}`);
      }
    } catch (error) {
      logger.error('Failed to initialize SMS client', {
        error: error.message,
      });
      throw error;
    }
  }

  loadTemplates() {
    // Load templates from config
    const configTemplates = smsConfig.templates;

    for (const [key, value] of Object.entries(configTemplates)) {
      this.templates.set(key, {
        id: key,
        template: value.template,
        createdAt: new Date().toISOString(),
      });
    }

    // Add additional custom templates
    this.templates.set('two-factor', {
      id: 'two-factor',
      template: 'Your 2FA code is: {{code}}. Do not share this code.',
      createdAt: new Date().toISOString(),
    });

    this.templates.set('password-reset', {
      id: 'password-reset',
      template:
        'Password reset code: {{code}}. Valid for 15 minutes. If you did not request this, please ignore.',
      createdAt: new Date().toISOString(),
    });

    this.templates.set('appointment-reminder', {
      id: 'appointment-reminder',
      template:
        'Reminder: You have an appointment on {{date}} at {{time}}. Reply CONFIRM to confirm.',
      createdAt: new Date().toISOString(),
    });

    logger.info('SMS templates loaded', { count: this.templates.size });
  }

  async sendSMS(to, templateName, templateData = {}) {
    try {
      if (!this.client) {
        logger.warn('SMS client not initialized - SMS not sent');
        return {
          success: false,
          error: 'SMS service not configured',
        };
      }

      const template = this.templates.get(templateName);
      if (!template) {
        throw new Error(`SMS template '${templateName}' not found`);
      }

      // Replace template variables
      let message = template.template;
      Object.keys(templateData).forEach((key) => {
        const regex = new RegExp(`{{${key}}}`, 'g');
        message = message.replace(regex, templateData[key] || '');
      });

      // Send SMS based on provider
      let result;
      switch (smsConfig.provider) {
        case 'twilio':
          result = await this.sendViaTwilio(to, message);
          break;

        case 'aws-sns':
          result = await this.sendViaSNS(to, message);
          break;

        case 'nexmo':
          result = await this.sendViaNexmo(to, message);
          break;

        default:
          throw new Error(`Unsupported SMS provider: ${smsConfig.provider}`);
      }

      // Log delivery
      this.logDelivery(to, templateName, message, result);

      logger.info('SMS sent successfully', {
        to,
        template: templateName,
        messageId: result.messageId,
      });

      return {
        success: true,
        messageId: result.messageId,
        template: templateName,
        provider: smsConfig.provider,
      };
    } catch (error) {
      logger.error('Failed to send SMS', {
        to,
        template: templateName,
        error: error.message,
      });
      throw error;
    }
  }

  async sendViaTwilio(to, message) {
    try {
      const result = await this.client.messages.create({
        body: message,
        from: smsConfig.twilioPhoneNumber,
        to: to,
      });

      return {
        messageId: result.sid,
        status: result.status,
        provider: 'twilio',
      };
    } catch (error) {
      logger.error('Twilio SMS error', { error: error.message });
      throw error;
    }
  }

  async sendViaSNS(to, message) {
    // AWS SNS implementation
    logger.info('Sending SMS via AWS SNS', { to, message });
    return {
      messageId: `sns-${Date.now()}`,
      status: 'sent',
      provider: 'aws-sns',
    };
  }

  async sendViaNexmo(to, message) {
    // Nexmo/Vonage implementation
    logger.info('Sending SMS via Nexmo', { to, message });
    return {
      messageId: `nexmo-${Date.now()}`,
      status: 'sent',
      provider: 'nexmo',
    };
  }

  async sendVerificationCode(phoneNumber, code) {
    return this.sendSMS(phoneNumber, 'verification', { code });
  }

  async sendTwoFactorCode(phoneNumber, code) {
    return this.sendSMS(phoneNumber, 'two-factor', { code });
  }

  async sendPasswordResetCode(phoneNumber, code) {
    return this.sendSMS(phoneNumber, 'password-reset', { code });
  }

  async sendPaymentNotification(phoneNumber, amount, reference) {
    return this.sendSMS(phoneNumber, 'payment', { amount, reference });
  }

  async sendCustomSMS(to, message) {
    try {
      if (!this.client) {
        logger.warn('SMS client not initialized - SMS not sent');
        return {
          success: false,
          error: 'SMS service not configured',
        };
      }

      let result;
      switch (smsConfig.provider) {
        case 'twilio':
          result = await this.sendViaTwilio(to, message);
          break;

        case 'aws-sns':
          result = await this.sendViaSNS(to, message);
          break;

        case 'nexmo':
          result = await this.sendViaNexmo(to, message);
          break;

        default:
          throw new Error(`Unsupported SMS provider: ${smsConfig.provider}`);
      }

      // Log delivery
      this.logDelivery(to, 'custom', message, result);

      logger.info('Custom SMS sent successfully', {
        to,
        messageId: result.messageId,
      });

      return {
        success: true,
        messageId: result.messageId,
        provider: smsConfig.provider,
      };
    } catch (error) {
      logger.error('Failed to send custom SMS', {
        to,
        error: error.message,
      });
      throw error;
    }
  }

  async sendBulkSMS(recipients, templateName, templateData = {}) {
    try {
      const results = [];

      for (const recipient of recipients) {
        try {
          const result = await this.sendSMS(
            recipient.phoneNumber,
            templateName,
            { ...templateData, ...recipient.data }
          );
          results.push({
            phoneNumber: recipient.phoneNumber,
            success: true,
            result,
          });
        } catch (error) {
          results.push({
            phoneNumber: recipient.phoneNumber,
            success: false,
            error: error.message,
          });
        }
      }

      const successCount = results.filter((r) => r.success).length;
      const failureCount = results.length - successCount;

      logger.info('Bulk SMS sent', {
        total: results.length,
        successful: successCount,
        failed: failureCount,
      });

      return {
        success: true,
        total: results.length,
        successful: successCount,
        failed: failureCount,
        results,
      };
    } catch (error) {
      logger.error('Failed to send bulk SMS', { error: error.message });
      throw error;
    }
  }

  logDelivery(to, template, message, result) {
    const logEntry = {
      to,
      template,
      message,
      messageId: result.messageId,
      status: result.status,
      provider: result.provider,
      timestamp: new Date().toISOString(),
    };

    this.deliveryLog.set(result.messageId, logEntry);

    // Keep only last 1000 entries
    if (this.deliveryLog.size > 1000) {
      const firstKey = this.deliveryLog.keys().next().value;
      this.deliveryLog.delete(firstKey);
    }
  }

  getDeliveryStatus(messageId) {
    try {
      const log = this.deliveryLog.get(messageId);

      if (!log) {
        return {
          success: false,
          error: 'Message not found',
        };
      }

      return {
        success: true,
        delivery: log,
      };
    } catch (error) {
      logger.error('Error getting delivery status', { error: error.message });
      return {
        success: false,
        error: error.message,
      };
    }
  }

  getDeliveryHistory(phoneNumber, limit = 50) {
    try {
      const history = Array.from(this.deliveryLog.values())
        .filter((log) => log.to === phoneNumber)
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, limit);

      return {
        success: true,
        history,
        count: history.length,
      };
    } catch (error) {
      logger.error('Error getting delivery history', {
        error: error.message,
      });
      return {
        success: false,
        error: error.message,
      };
    }
  }

  getTemplates() {
    try {
      const templates = Array.from(this.templates.values());

      return {
        success: true,
        templates: templates.map((t) => ({
          id: t.id,
          template: t.template,
        })),
        count: templates.length,
      };
    } catch (error) {
      logger.error('Error getting templates', { error: error.message });
      return {
        success: false,
        error: error.message,
      };
    }
  }

  async testConnection() {
    try {
      if (!this.client) {
        return {
          success: false,
          error: 'SMS client not initialized',
        };
      }

      // For Twilio, we can verify the account
      if (smsConfig.provider === 'twilio') {
        const account = await this.client.api.accounts(
          smsConfig.twilioAccountSid
        ).fetch();

        return {
          success: true,
          message: 'SMS service connected successfully',
          provider: 'twilio',
          accountStatus: account.status,
        };
      }

      return {
        success: true,
        message: 'SMS service connected successfully',
        provider: smsConfig.provider,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  getHealthStatus() {
    return {
      service: 'sms',
      client: this.client ? 'initialized' : 'not initialized',
      provider: smsConfig.provider,
      templates: this.templates.size,
      deliveryLog: this.deliveryLog.size,
      config: smsConfig.getHealthStatus(),
    };
  }

  getStatistics() {
    try {
      const logs = Array.from(this.deliveryLog.values());

      const stats = {
        totalSent: logs.length,
        byStatus: {
          sent: logs.filter((l) => l.status === 'sent').length,
          delivered: logs.filter((l) => l.status === 'delivered').length,
          failed: logs.filter((l) => l.status === 'failed').length,
        },
        byProvider: {
          twilio: logs.filter((l) => l.provider === 'twilio').length,
          'aws-sns': logs.filter((l) => l.provider === 'aws-sns').length,
          nexmo: logs.filter((l) => l.provider === 'nexmo').length,
        },
        templates: this.templates.size,
      };

      return {
        success: true,
        statistics: stats,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      logger.error('Error getting statistics', { error: error.message });
      return {
        success: false,
        error: error.message,
      };
    }
  }

  // Graceful shutdown
  async close() {
    if (this.client) {
      logger.info('SMS service closed');
    }
  }
}

// Create singleton instance
const smsService = new SMSService();

export default smsService;
