import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'sms-config' },
  transports: [
    new winston.transports.File({
      filename: 'logs/sms-error.log',
      level: 'error',
    }),
    new winston.transports.File({ filename: 'logs/sms.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
    })
  );
}

class SMSConfig {
  constructor() {
    this.provider = process.env.SMS_PROVIDER || 'twilio'; // twilio, aws-sns, nexmo
    this.fromNumber = process.env.SMS_FROM_NUMBER || '+1234567890';

    // Twilio configuration
    this.twilioAccountSid = process.env.TWILIO_ACCOUNT_SID;
    this.twilioAuthToken = process.env.TWILIO_AUTH_TOKEN;
    this.twilioPhoneNumber = process.env.TWILIO_PHONE_NUMBER;

    // AWS SNS configuration
    this.snsAccessKeyId = process.env.AWS_SNS_ACCESS_KEY_ID;
    this.snsSecretAccessKey = process.env.AWS_SNS_SECRET_ACCESS_KEY;
    this.snsRegion = process.env.AWS_SNS_REGION || 'us-east-1';

    // Nexmo/Vonage configuration
    this.nexmoApiKey = process.env.NEXMO_API_KEY;
    this.nexmoApiSecret = process.env.NEXMO_API_SECRET;
    this.nexmoFromNumber = process.env.NEXMO_FROM_NUMBER;

    this.templates = {
      verification: {
        template: 'Your verification code is: {{code}}. Valid for 10 minutes.',
      },
      alert: {
        template: 'ALERT: {{message}}',
      },
      notification: {
        template: '{{message}}',
      },
      payment: {
        template:
          'Payment of ${{amount}} processed successfully. Ref: {{reference}}',
      },
      welcome: {
        template:
          'Welcome to Oscar Broome Revenue! Your account is now active.',
      },
    };

    this.validateConfig();
  }

  validateConfig() {
    const requiredConfigs = {
      twilio: ['twilioAccountSid', 'twilioAuthToken', 'twilioPhoneNumber'],
      'aws-sns': ['snsAccessKeyId', 'snsSecretAccessKey'],
      nexmo: ['nexmoApiKey', 'nexmoApiSecret', 'nexmoFromNumber'],
    };

    const provider = this.provider;
    if (!requiredConfigs[provider]) {
      logger.warn(`Unknown SMS provider: ${provider}, falling back to twilio`);
      this.provider = 'twilio';
      return;
    }

    const required = requiredConfigs[provider];
    const missing = required.filter((key) => !this[key]);

    if (missing.length > 0) {
      logger.warn(
        `SMS configuration incomplete for ${provider}: ${missing.join(', ')} - SMS features will be disabled`
      );
      this.smsEnabled = false;
    } else {
      logger.info(`SMS configuration validated for provider: ${provider}`);
      this.smsEnabled = true;
    }
  }

  getProviderConfig() {
    switch (this.provider) {
      case 'twilio':
        return {
          accountSid: this.twilioAccountSid,
          authToken: this.twilioAuthToken,
          fromNumber: this.twilioPhoneNumber,
        };

      case 'aws-sns':
        return {
          accessKeyId: this.snsAccessKeyId,
          secretAccessKey: this.snsSecretAccessKey,
          region: this.snsRegion,
        };

      case 'nexmo':
        return {
          apiKey: this.nexmoApiKey,
          apiSecret: this.nexmoApiSecret,
          fromNumber: this.nexmoFromNumber,
        };

      default:
        throw new Error(`Unsupported SMS provider: ${this.provider}`);
    }
  }

  getTemplateConfig(templateName) {
    return this.templates[templateName] || null;
  }

  updateConfig(updates) {
    Object.assign(this, updates);
    this.validateConfig();
    logger.info('SMS configuration updated');
  }

  getHealthStatus() {
    const requiredFields = {
      twilio: ['twilioAccountSid', 'twilioAuthToken', 'twilioPhoneNumber'],
      'aws-sns': ['snsAccessKeyId', 'snsSecretAccessKey'],
      nexmo: ['nexmoApiKey', 'nexmoApiSecret', 'nexmoFromNumber'],
    };

    const provider = this.provider;
    const required = requiredFields[provider] || [];
    const configured = required.filter((key) => this[key]).length;

    return {
      provider,
      configured: `${configured}/${required.length} required fields`,
      status: configured === required.length ? 'configured' : 'incomplete',
      fromNumber: this.fromNumber,
      templates: Object.keys(this.templates).length,
    };
  }
}

// Create singleton instance
const smsConfig = new SMSConfig();

export default smsConfig;
