import nodemailer from 'nodemailer';
import twilio from 'twilio';
import { info, error } from '../utils/loggerWrapper.js';

// Notification service for real-time alerts
class NotificationService {
  constructor(io) {
    this.io = io;
    this.transporter = null;
    this.twilioClient = null;
    this.initServices();
  }

  initServices() {
    // Initialize email transporter
    if (
      process.env.SMTP_HOST &&
      process.env.SMTP_USER &&
      process.env.SMTP_PASS
    ) {
      this.transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT || 587,
        secure: false,
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS,
        },
      });
      info('✅ Email notification service initialized');
    } else {
      info('⚠️ Email service not configured');
    }

    // Initialize Twilio client
    if (
      process.env.TWILIO_ACCOUNT_SID &&
      process.env.TWILIO_AUTH_TOKEN &&
      process.env.TWILIO_PHONE_NUMBER
    ) {
      this.twilioClient = twilio(
        process.env.TWILIO_ACCOUNT_SID,
        process.env.TWILIO_AUTH_TOKEN
      );
      info('✅ SMS notification service initialized');
    } else {
      info('⚠️ SMS service not configured');
    }
  }

  // Send WebSocket notification
  sendWebSocketNotification(event, data) {
    if (this.io) {
      this.io.emit(event, data);
      info(`📡 WebSocket notification sent: ${event}`);
    }
  }

  // Send email notification
  async sendEmailNotification(to, subject, message) {
    if (!this.transporter) {
      info('⚠️ Email service not available');
      return false;
    }

    try {
      await this.transporter.sendMail({
        from: process.env.SMTP_USER,
        to,
        subject,
        html: message,
      });
      info(`📧 Email sent to ${to}`);
      return true;
    } catch (err) {
      error('Email send error:', err);
      return false;
    }
  }

  // Send SMS notification
  async sendSMSNotification(to, message) {
    if (!this.twilioClient) {
      info('⚠️ SMS service not available');
      return false;
    }

    try {
      await this.twilioClient.messages.create({
        body: message,
        from: process.env.TWILIO_PHONE_NUMBER,
        to,
      });
      info(`📱 SMS sent to ${to}`);
      return true;
    } catch (err) {
      error('SMS send error:', err);
      return false;
    }
  }

  // Send comprehensive notification
  async sendNotification(options) {
    const { email, phone, subject, message, websocket = true } = options;

    const results = {
      websocket: false,
      email: false,
      sms: false,
    };

    // Send WebSocket notification
    if (websocket) {
      this.sendWebSocketNotification('notification', {
        subject,
        message,
        timestamp: new Date().toISOString(),
      });
      results.websocket = true;
    }

    // Send email if provided
    if (email && subject && message) {
      results.email = await this.sendEmailNotification(email, subject, message);
    }

    // Send SMS if provided
    if (phone && message) {
      results.sms = await this.sendSMSNotification(phone, message);
    }

    return results;
  }

  // Revenue milestone notification
  async notifyRevenueMilestone(currentRevenue, targetRevenue) {
    const percentage = (currentRevenue / targetRevenue) * 100;
    const subject = `Revenue Milestone Reached: ${percentage.toFixed(1)}%`;
    const message = `
      <h2>Revenue Milestone Alert</h2>
      <p>Current Revenue: $${currentRevenue.toLocaleString()}</p>
      <p>Target Revenue: $${targetRevenue.toLocaleString()}</p>
      <p>Progress: ${percentage.toFixed(1)}%</p>
      <p>Timestamp: ${new Date().toISOString()}</p>
    `;

    return await this.sendNotification({
      subject,
      message,
      websocket: true,
    });
  }

  // Anomaly detection notification
  async notifyAnomaly(anomalyData) {
    const subject = 'Revenue Anomaly Detected';
    const message = `
      <h2>Revenue Anomaly Alert</h2>
      <p>An unusual revenue pattern has been detected.</p>
      <p>Current Revenue: $${anomalyData.currentRevenue.toLocaleString()}</p>
      <p>Expected Range: $${anomalyData.expectedMin.toLocaleString()} - $${anomalyData.expectedMax.toLocaleString()}</p>
      <p>Timestamp: ${new Date().toISOString()}</p>
    `;

    return await this.sendNotification({
      subject,
      message,
      websocket: true,
    });
  }

  // Payment failure notification
  async notifyPaymentFailure(paymentData) {
    const subject = 'Payment Processing Failed';
    const message = `
      <h2>Payment Failure Alert</h2>
      <p>A payment transaction has failed.</p>
      <p>Amount: $${paymentData.amount.toLocaleString()}</p>
      <p>Reference: ${paymentData.reference}</p>
      <p>Error: ${paymentData.error}</p>
      <p>Timestamp: ${new Date().toISOString()}</p>
    `;

    return await this.sendNotification({
      subject,
      message,
      websocket: true,
    });
  }
}

export default NotificationService;
