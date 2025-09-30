import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'email-config' },
  transports: [
    new winston.transports.File({ filename: 'logs/email-error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/email.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

class EmailConfig {
  constructor() {
    this.provider = process.env.EMAIL_PROVIDER || 'sendgrid'; // sendgrid, ses, smtp
    this.fromEmail = process.env.EMAIL_FROM || 'noreply@oscar-broome-revenue.com';
    this.fromName = process.env.EMAIL_FROM_NAME || 'Oscar Broome Revenue System';

    // SendGrid configuration
    this.sendgridApiKey = process.env.SENDGRID_API_KEY;

    // AWS SES configuration
    this.sesAccessKeyId = process.env.AWS_SES_ACCESS_KEY_ID;
    this.sesSecretAccessKey = process.env.AWS_SES_SECRET_ACCESS_KEY;
    this.sesRegion = process.env.AWS_SES_REGION || 'us-east-1';

    // SMTP configuration (fallback)
    this.smtpHost = process.env.SMTP_HOST;
    this.smtpPort = parseInt(process.env.SMTP_PORT) || 587;
    this.smtpUser = process.env.SMTP_USER;
    this.smtpPass = process.env.SMTP_PASS;
    this.smtpSecure = process.env.SMTP_SECURE === 'true';

    this.templates = {
      passwordReset: {
        subject: 'Password Reset Request - Oscar Broome Revenue',
        template: 'password-reset'
      },
      welcome: {
        subject: 'Welcome to Oscar Broome Revenue System',
        template: 'welcome'
      },
      accountLocked: {
        subject: 'Account Security Alert - Oscar Broome Revenue',
        template: 'account-locked'
      },
      transactionAlert: {
        subject: 'Transaction Alert - Oscar Broome Revenue',
        template: 'transaction-alert'
      }
    };

    this.validateConfig();
  }

  validateConfig() {
    const requiredConfigs = {
      sendgrid: ['sendgridApiKey'],
      ses: ['sesAccessKeyId', 'sesSecretAccessKey'],
      smtp: ['smtpHost', 'smtpUser', 'smtpPass']
    };

    const provider = this.provider;
    if (!requiredConfigs[provider]) {
      logger.warn(`Unknown email provider: ${provider}, falling back to sendgrid`);
      this.provider = 'sendgrid';
      return;
    }

    const required = requiredConfigs[provider];
    const missing = required.filter(key => !this[key]);

    if (missing.length > 0) {
      logger.error(`Missing required email configuration for ${provider}: ${missing.join(', ')}`);
      throw new Error(`Email configuration incomplete for provider ${provider}`);
    }

    logger.info(`Email configuration validated for provider: ${provider}`);
  }

  getTransporterConfig() {
    switch (this.provider) {
      case 'sendgrid':
        return {
          host: 'smtp.sendgrid.net',
          port: 587,
          secure: false,
          auth: {
            user: 'apikey',
            pass: this.sendgridApiKey
          }
        };

      case 'ses':
        return {
          host: `email-smtp.${this.sesRegion}.amazonaws.com`,
          port: 587,
          secure: false,
          auth: {
            user: this.sesAccessKeyId,
            pass: this.sesSecretAccessKey
          }
        };

      case 'smtp':
        return {
          host: this.smtpHost,
          port: this.smtpPort,
          secure: this.smtpSecure,
          auth: {
            user: this.smtpUser,
            pass: this.smtpPass
          }
        };

      default:
        throw new Error(`Unsupported email provider: ${this.provider}`);
    }
  }

  getTemplateConfig(templateName) {
    return this.templates[templateName] || null;
  }

  updateConfig(updates) {
    Object.assign(this, updates);
    this.validateConfig();
    logger.info('Email configuration updated');
  }

  getHealthStatus() {
    const requiredFields = {
      sendgrid: ['sendgridApiKey'],
      ses: ['sesAccessKeyId', 'sesSecretAccessKey'],
      smtp: ['smtpHost', 'smtpUser', 'smtpPass']
    };

    const provider = this.provider;
    const required = requiredFields[provider] || [];
    const configured = required.filter(key => this[key]).length;

    return {
      provider,
      configured: `${configured}/${required.length} required fields`,
      status: configured === required.length ? 'configured' : 'incomplete',
      fromEmail: this.fromEmail,
      templates: Object.keys(this.templates).length
    };
  }
}

// Create singleton instance
const emailConfig = new EmailConfig();

export default emailConfig;
