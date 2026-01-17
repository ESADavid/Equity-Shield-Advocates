import nodemailer from 'nodemailer';
import emailConfig from '../config/email.js';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'email-service' },
  transports: [
    new winston.transports.File({
      filename: 'logs/email-service-error.log',
      level: 'error',
    }),
    new winston.transports.File({ filename: 'logs/email-service.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
    })
  );
}

class EmailService {
  constructor() {
    this.transporter = null;
    this.templates = new Map();
    this.initializeTransporter();
    this.loadTemplates();
  }

  initializeTransporter() {
    try {
      // Check if email is enabled
      if (!emailConfig.emailEnabled) {
        logger.warn('Email service disabled due to incomplete configuration');
        return;
      }

      const config = emailConfig.getTransporterConfig();
      this.transporter = nodemailer.createTransport(config);

      // Verify connection
      this.transporter.verify((error, success) => {
        if (error) {
          logger.error('Email transporter verification failed', {
            error: error.message,
          });
        } else {
          logger.info('Email transporter verified successfully');
        }
      });
    } catch (error) {
      logger.error('Failed to initialize email transporter', {
        error: error.message,
      });
      throw error;
    }
  }

  loadTemplates() {
    // Basic HTML templates - in production, these would be loaded from files
    this.templates.set('password-reset', {
      subject: 'Password Reset Request - Oscar Broome Revenue',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Password Reset</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #007bff; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background: #f9f9f9; }
            .button { display: inline-block; padding: 10px 20px; background: #28a745; color: white; text-decoration: none; border-radius: 5px; }
            .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Oscar Broome Revenue System</h1>
            </div>
            <div class="content">
              <h2>Password Reset Request</h2>
              <p>Hello {{firstName}},</p>
              <p>You have requested to reset your password. Click the button below to proceed:</p>
              <p style="text-align: center;">
                <a href="{{resetLink}}" class="button">Reset Password</a>
              </p>
              <p>If the button doesn't work, copy and paste this link into your browser:</p>
              <p>{{resetLink}}</p>
              <p>This link will expire in 1 hour for security reasons.</p>
              <p>If you didn't request this reset, please ignore this email.</p>
            </div>
            <div class="footer">
              <p>&copy; 2024 Oscar Broome Revenue System. All rights reserved.</p>
            </div>
          </div>
        </body>
        </html>
      `,
    });

    this.templates.set('welcome', {
      subject: 'Welcome to Oscar Broome Revenue System',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Welcome</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #007bff; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background: #f9f9f9; }
            .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Welcome to Oscar Broome Revenue</h1>
            </div>
            <div class="content">
              <h2>Welcome, {{firstName}}!</h2>
              <p>Your account has been successfully created.</p>
              <p>You can now access the Oscar Broome Revenue System dashboard.</p>
              <p>If you have any questions, please contact support.</p>
            </div>
            <div class="footer">
              <p>&copy; 2024 Oscar Broome Revenue System. All rights reserved.</p>
            </div>
          </div>
        </body>
        </html>
      `,
    });

    logger.info('Email templates loaded', { count: this.templates.size });
  }

  async sendEmail(to, templateName, templateData = {}) {
    try {
      const template = this.templates.get(templateName);
      if (!template) {
        throw new Error(`Email template '${templateName}' not found`);
      }

      // Replace template variables
      let subject = template.subject;
      let html = template.html;

      Object.keys(templateData).forEach((key) => {
        const regex = new RegExp(`{{${key}}}`, 'g');
        subject = subject.replace(regex, templateData[key] || '');
        html = html.replace(regex, templateData[key] || '');
      });

      const mailOptions = {
        from: `"${emailConfig.fromName}" <${emailConfig.fromEmail}>`,
        to,
        subject,
        html,
      };

      const info = await this.transporter.sendMail(mailOptions);

      logger.info('Email sent successfully', {
        to,
        template: templateName,
        messageId: info.messageId,
        response: info.response,
      });

      return {
        success: true,
        messageId: info.messageId,
        template: templateName,
      };
    } catch (error) {
      logger.error('Failed to send email', {
        to,
        template: templateName,
        error: error.message,
      });
      throw error;
    }
  }

  async sendPasswordResetEmail(email, firstName, resetToken) {
    const resetLink = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/reset-password?token=${resetToken}`;

    return this.sendEmail(email, 'password-reset', {
      firstName,
      resetLink,
    });
  }

  async sendWelcomeEmail(email, firstName) {
    return this.sendEmail(email, 'welcome', {
      firstName,
    });
  }

  async sendCustomEmail(to, subject, htmlContent) {
    try {
      const mailOptions = {
        from: `"${emailConfig.fromName}" <${emailConfig.fromEmail}>`,
        to,
        subject,
        html: htmlContent,
      };

      const info = await this.transporter.sendMail(mailOptions);

      logger.info('Custom email sent successfully', {
        to,
        subject,
        messageId: info.messageId,
      });

      return {
        success: true,
        messageId: info.messageId,
      };
    } catch (error) {
      logger.error('Failed to send custom email', {
        to,
        subject,
        error: error.message,
      });
      throw error;
    }
  }

  async testConnection() {
    try {
      await this.transporter.verify();
      return { success: true, message: 'Email service connected successfully' };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  getHealthStatus() {
    return {
      service: 'email',
      transporter: this.transporter ? 'initialized' : 'not initialized',
      templates: this.templates.size,
      config: emailConfig.getHealthStatus(),
    };
  }

  // Graceful shutdown
  async close() {
    if (this.transporter) {
      this.transporter.close();
      logger.info('Email transporter closed');
    }
  }
}

// Create singleton instance
const emailService = new EmailService();

export default emailService;
