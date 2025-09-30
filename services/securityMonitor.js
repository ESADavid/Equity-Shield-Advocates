import winston from 'winston';
import nodemailer from 'nodemailer';
import { createHash } from 'crypto';

// Security event types
const SECURITY_EVENTS = {
  FAILED_LOGIN: 'failed_login',
  SUSPICIOUS_ACTIVITY: 'suspicious_activity',
  UNAUTHORIZED_ACCESS: 'unauthorized_access',
  BRUTE_FORCE: 'brute_force_attempt',
  SQL_INJECTION: 'sql_injection_attempt',
  XSS_ATTEMPT: 'xss_attempt',
  RATE_LIMIT_EXCEEDED: 'rate_limit_exceeded',
  SUSPICIOUS_IP: 'suspicious_ip',
  ANOMALOUS_REQUEST: 'anomalous_request'
};

// Risk levels
const RISK_LEVELS = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
};

class SecurityMonitor {
  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      defaultMeta: { service: 'security-monitor' },
      transports: [
        new winston.transports.File({ filename: 'logs/security.log' }),
        new winston.transports.File({
          filename: 'logs/security-error.log',
          level: 'error'
        })
      ]
    });

    if (process.env.NODE_ENV !== 'production') {
      this.logger.add(new winston.transports.Console({
        format: winston.format.simple()
      }));
    }

    // Initialize email transporter for alerts
    this.emailTransporter = nodemailer.createTransporter({
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: process.env.SMTP_PORT || 587,
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    // Security metrics storage
    this.metrics = {
      failedLogins: new Map(),
      suspiciousIPs: new Set(),
      blockedIPs: new Set(),
      alertsSent: 0
    };

    // Configuration
    this.config = {
      maxFailedLogins: parseInt(process.env.MAX_FAILED_LOGINS) || 5,
      alertThreshold: parseInt(process.env.SECURITY_ALERT_THRESHOLD) || 10,
      blockDuration: parseInt(process.env.IP_BLOCK_DURATION) || 3600000, // 1 hour
      suspiciousPatterns: [
        /union.*select/i,
        /script.*alert/i,
        /\b(or|and)\b.*(=|>|<)/i,
        /eval\(/i,
        /base64_decode/i
      ]
    };
  }

  // Log security event
  async logSecurityEvent(eventType, details, riskLevel = RISK_LEVELS.LOW) {
    const event = {
      type: eventType,
      riskLevel,
      timestamp: new Date(),
      ip: details.ip,
      userAgent: details.userAgent,
      userId: details.userId,
      tenantId: details.tenantId,
      endpoint: details.endpoint,
      method: details.method,
      details: details.additionalInfo || {}
    };

    // Hash sensitive data for privacy
    if (event.details.password) {
      event.details.passwordHash = createHash('sha256')
        .update(event.details.password)
        .digest('hex');
      delete event.details.password;
    }

    this.logger.warn('Security Event Detected', event);

    // Check if alert should be sent
    await this.evaluateAlert(event);

    // Update metrics
    this.updateMetrics(event);

    return event;
  }

  // Evaluate if security alert should be sent
  async evaluateAlert(event) {
    const shouldAlert = this.shouldSendAlert(event);

    if (shouldAlert) {
      await this.sendSecurityAlert(event);
      this.metrics.alertsSent++;
    }
  }

  // Determine if alert should be sent based on risk and frequency
  shouldSendAlert(event) {
    const { riskLevel, type, ip } = event;

    // Always alert on critical events
    if (riskLevel === RISK_LEVELS.CRITICAL) {
      return true;
    }

    // Alert on high-risk events
    if (riskLevel === RISK_LEVELS.HIGH) {
      return true;
    }

    // Check frequency of events from same IP
    const recentEvents = this.getRecentEventsFromIP(ip, 300000); // 5 minutes
    if (recentEvents.length >= this.config.alertThreshold) {
      return true;
    }

    // Alert on specific high-risk event types
    const highRiskTypes = [
      SECURITY_EVENTS.BRUTE_FORCE,
      SECURITY_EVENTS.SQL_INJECTION,
      SECURITY_EVENTS.UNAUTHORIZED_ACCESS
    ];

    return highRiskTypes.includes(type);
  }

  // Send security alert via email
  async sendSecurityAlert(event) {
    try {
      const alertData = {
        subject: `🚨 Security Alert: ${event.type.toUpperCase()}`,
        html: this.generateAlertEmail(event),
        to: process.env.SECURITY_ALERT_EMAILS?.split(',') || ['security@oscar-broome.com']
      };

      await this.emailTransporter.sendMail({
        from: process.env.SMTP_USER,
        ...alertData
      });

      this.logger.info('Security alert sent', { eventType: event.type, recipients: alertData.to });
    } catch (error) {
      this.logger.error('Failed to send security alert', { error: error.message, event });
    }
  }

  // Generate HTML email for security alert
  generateAlertEmail(event) {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #dc3545;">🚨 Security Alert Detected</h2>

        <div style="background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
          <h3>Event Details:</h3>
          <ul>
            <li><strong>Type:</strong> ${event.type}</li>
            <li><strong>Risk Level:</strong> <span style="color: ${this.getRiskColor(event.riskLevel)}">${event.riskLevel.toUpperCase()}</span></li>
            <li><strong>Timestamp:</strong> ${event.timestamp}</li>
            <li><strong>IP Address:</strong> ${event.ip}</li>
            <li><strong>User Agent:</strong> ${event.userAgent}</li>
            <li><strong>Endpoint:</strong> ${event.endpoint}</li>
            <li><strong>Method:</strong> ${event.method}</li>
            ${event.userId ? `<li><strong>User ID:</strong> ${event.userId}</li>` : ''}
            ${event.tenantId ? `<li><strong>Tenant ID:</strong> ${event.tenantId}</li>` : ''}
          </ul>

          ${Object.keys(event.details).length > 0 ? `
            <h3>Additional Details:</h3>
            <pre style="background: white; padding: 10px; border-radius: 3px;">${JSON.stringify(event.details, null, 2)}</pre>
          ` : ''}
        </div>

        <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
          <strong>Recommended Actions:</strong>
          <ul>
            <li>Review the event details above</li>
            <li>Check system logs for related activity</li>
            <li>Consider blocking the IP if suspicious</li>
            <li>Notify relevant security personnel</li>
          </ul>
        </div>

        <p style="color: #6c757d; font-size: 12px;">
          This alert was generated by the OSCAR-BROOME-REVENUE Security Monitor.<br>
          If you believe this is a false positive, please review your security policies.
        </p>
      </div>
    `;
  }

  // Get color for risk level
  getRiskColor(riskLevel) {
    const colors = {
      [RISK_LEVELS.LOW]: '#28a745',
      [RISK_LEVELS.MEDIUM]: '#ffc107',
      [RISK_LEVELS.HIGH]: '#fd7e14',
      [RISK_LEVELS.CRITICAL]: '#dc3545'
    };
    return colors[riskLevel] || '#6c757d';
  }

  // Update security metrics
  updateMetrics(event) {
    const { ip, type } = event;

    // Track failed logins per IP
    if (type === SECURITY_EVENTS.FAILED_LOGIN) {
      const current = this.metrics.failedLogins.get(ip) || 0;
      this.metrics.failedLogins.set(ip, current + 1);

      // Auto-block IP after max failed attempts
      if (current + 1 >= this.config.maxFailedLogins) {
        this.blockIP(ip);
      }
    }

    // Track suspicious IPs
    if ([SECURITY_EVENTS.SUSPICIOUS_IP, SECURITY_EVENTS.BRUTE_FORCE].includes(type)) {
      this.metrics.suspiciousIPs.add(ip);
    }
  }

  // Check if request contains suspicious patterns
  detectSuspiciousPatterns(data) {
    const patterns = this.config.suspiciousPatterns;
    const textToCheck = JSON.stringify(data).toLowerCase();

    for (const pattern of patterns) {
      if (pattern.test(textToCheck)) {
        return {
          detected: true,
          pattern: pattern.toString()
        };
      }
    }

    return { detected: false };
  }

  // Check rate limiting violations
  checkRateLimit(ip, endpoint, timeWindow = 60000) { // 1 minute
    // This would integrate with your rate limiting middleware
    // For now, return false (not implemented)
    return false;
  }

  // Block IP address
  blockIP(ip) {
    this.metrics.blockedIPs.add(ip);
    this.logger.warn('IP blocked due to security policy', { ip });

    // In a real implementation, this would update firewall rules
    // or add to a blocked IPs list in Redis/database
  }

  // Check if IP is blocked
  isBlocked(ip) {
    return this.metrics.blockedIPs.has(ip);
  }

  // Get recent events from IP
  getRecentEventsFromIP(ip, timeWindow = 300000) { // 5 minutes
    // This would query the security logs for recent events
    // For now, return empty array
    return [];
  }

  // Get security metrics
  getMetrics() {
    return {
      failedLogins: Object.fromEntries(this.metrics.failedLogins),
      suspiciousIPsCount: this.metrics.suspiciousIPs.size,
      blockedIPsCount: this.metrics.blockedIPs.size,
      alertsSent: this.metrics.alertsSent,
      suspiciousIPs: Array.from(this.metrics.suspiciousIPs),
      blockedIPs: Array.from(this.metrics.blockedIPs)
    };
  }

  // Middleware for Express.js
  middleware() {
    return async (req, res, next) => {
      const clientIP = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent') || 'Unknown';

      // Check if IP is blocked
      if (this.isBlocked(clientIP)) {
        await this.logSecurityEvent(SECURITY_EVENTS.UNAUTHORIZED_ACCESS, {
          ip: clientIP,
          userAgent,
          endpoint: req.path,
          method: req.method,
          additionalInfo: { reason: 'IP blocked' }
        }, RISK_LEVELS.HIGH);

        return res.status(403).json({
          error: 'Access denied',
          message: 'Your IP address has been blocked due to security policy'
        });
      }

      // Check for suspicious patterns in request
      const suspiciousCheck = this.detectSuspiciousPatterns(req.body);
      if (suspiciousCheck.detected) {
        await this.logSecurityEvent(SECURITY_EVENTS.SUSPICIOUS_ACTIVITY, {
          ip: clientIP,
          userAgent,
          endpoint: req.path,
          method: req.method,
          additionalInfo: {
            pattern: suspiciousCheck.pattern,
            requestBody: req.body
          }
        }, RISK_LEVELS.HIGH);
      }

      // Check rate limiting
      if (this.checkRateLimit(clientIP, req.path)) {
        await this.logSecurityEvent(SECURITY_EVENTS.RATE_LIMIT_EXCEEDED, {
          ip: clientIP,
          userAgent,
          endpoint: req.path,
          method: req.method
        }, RISK_LEVELS.MEDIUM);
      }

      // Store security context for later use
      req.securityContext = {
        ip: clientIP,
        userAgent,
        timestamp: new Date()
      };

      next();
    };
  }
}

// Create singleton instance
const securityMonitor = new SecurityMonitor();

export default securityMonitor;
export { SECURITY_EVENTS, RISK_LEVELS };
