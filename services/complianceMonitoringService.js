/**
 * COMPLIANCE MONITORING SERVICE
 * Automated compliance monitoring and enforcement system
 * Part of the OWLBAN GROUP Heaven on Earth Initiative
 */

import { info, error, warn, debug } from 'utils/loggerWrapper.js';
import Citizen from '../models/Citizen.js';
import UBIPayment from '../models/UBIPayment.js';
import multiChannelNotificationService from './multiChannelNotificationService.js';
import auditService from './auditService.js';

class ComplianceMonitoringService {
  constructor() {
    this.MONITORING_INTERVAL = 60 * 60 * 1000; // 1 hour
    this.ALERT_THRESHOLDS = {
      highRisk: 10, // Alert if > 10 high-risk issues
      mediumRisk: 25, // Alert if > 25 medium-risk issues
      lowRisk: 50, // Alert if > 50 low-risk issues
    };
    this.COMPLIANCE_AREAS = [
      'data_privacy',
      'financial_compliance',
      'security_standards',
      'education_compliance',
      'payment_compliance',
      'identity_verification',
    ];

    // Start monitoring loop
    this.startMonitoring();
    info('Compliance Monitoring Service initialized');
  }

  /**
   * Start automated monitoring loop
   */
  startMonitoring() {
    setInterval(async () => {
      try {
        await this.runAutomatedMonitoring();
      } catch (err) {
        error('Automated monitoring failed:', err);
      }
    }, this.MONITORING_INTERVAL);

    info(
      `Automated compliance monitoring started (interval: ${this.MONITORING_INTERVAL / 1000}s)`
    );
  }

  /**
   * Run comprehensive compliance monitoring
   * @param {string} userId - User ID requesting monitoring
   * @returns {Promise<Object>} Monitoring results
   */
  async monitorCompliance(userId) {
    try {
      info('Starting comprehensive compliance monitoring');

      const startTime = Date.now();
      const results = {
        timestamp: new Date(),
        areas: {},
        summary: {
          totalIssues: 0,
          highRisk: 0,
          mediumRisk: 0,
          lowRisk: 0,
          compliant: 0,
        },
        alerts: [],
        recommendations: [],
      };

      // Run checks for each compliance area
      for (const area of this.COMPLIANCE_AREAS) {
        try {
          const areaResult = await this.runAreaCheck(area);
          results.areas[area] = areaResult;

          // Update summary
          results.summary.totalIssues += areaResult.issues.length;
          results.summary.highRisk += areaResult.issues.filter(
            (i) => i.severity === 'high'
          ).length;
          results.summary.mediumRisk += areaResult.issues.filter(
            (i) => i.severity === 'medium'
          ).length;
          results.summary.lowRisk += areaResult.issues.filter(
            (i) => i.severity === 'low'
          ).length;

          if (areaResult.status === 'compliant') {
            results.summary.compliant++;
          }
        } catch (err) {
          error(`Failed to check compliance area ${area}:`, err);
          results.areas[area] = {
            status: 'error',
            issues: [
              { severity: 'high', description: `Check failed: ${err.message}` },
            ],
          };
        }
      }

      // Generate alerts based on thresholds
      results.alerts = this.generateAlerts(results.summary);

      // Generate recommendations
      results.recommendations = this.generateRecommendations(results);

      const duration = Date.now() - startTime;
      results.duration = `${duration}ms`;

      // Log monitoring completion
      await auditService.logActivity(
        userId || 'system',
        'COMPLIANCE_MONITORING',
        {
          results: results.summary,
          duration,
        }
      );

      info(
        `Compliance monitoring completed: ${results.summary.totalIssues} issues found in ${duration}ms`
      );
      return results;
    } catch (err) {
      error('Compliance monitoring failed:', err);
      throw err;
    }
  }

  /**
   * Run automated monitoring (called by interval)
   */
  async runAutomatedMonitoring() {
    try {
      const results = await this.monitorCompliance('system');

      // Send alerts if necessary
      if (results.alerts.length > 0) {
        await this.sendComplianceAlerts(results);
      }

      // Auto-remediate critical issues
      await this.autoRemediateCriticalIssues(results);

      debug('Automated compliance monitoring completed');
    } catch (err) {
      error('Automated monitoring error:', err);
    }
  }

  /**
   * Run compliance check for specific area
   * @param {string} area - Compliance area to check
   * @returns {Promise<Object>} Area check results
   */
  async runAreaCheck(area) {
    switch (area) {
      case 'data_privacy':
        return await this.checkDataPrivacy();
      case 'financial_compliance':
        return await this.checkFinancialCompliance();
      case 'security_standards':
        return await this.checkSecurityStandards();
      case 'education_compliance':
        return await this.checkEducationCompliance();
      case 'payment_compliance':
        return await this.checkPaymentCompliance();
      case 'identity_verification':
        return await this.checkIdentityVerification();
      default:
        throw new Error(`Unknown compliance area: ${area}`);
    }
  }

  /**
   * Check data privacy compliance
   */
  async checkDataPrivacy() {
    const issues = [];

    try {
      // Check for citizens with incomplete data
      const incompleteCitizens = await Citizen.countDocuments({
        $or: [
          { 'personalInfo.firstName': { $exists: false } },
          { 'personalInfo.lastName': { $exists: false } },
          { 'contactInfo.email': { $exists: false } },
        ],
      });

      if (incompleteCitizens > 0) {
        issues.push({
          severity: 'medium',
          description: `${incompleteCitizens} citizens have incomplete personal information`,
          recommendation: 'Complete citizen data collection',
        });
      }

      // Check for unencrypted sensitive data (placeholder - would need actual encryption checks)
      const unencryptedBanking = await Citizen.countDocuments({
        'bankingInfo.accountNumber': { $exists: true },
        'verification.bankingVerified': false,
      });

      if (unencryptedBanking > 0) {
        issues.push({
          severity: 'high',
          description: `${unencryptedBanking} citizens have unverified banking information`,
          recommendation: 'Verify and secure banking data',
        });
      }

      return {
        status: issues.length === 0 ? 'compliant' : 'non_compliant',
        issues,
        checkedAt: new Date(),
      };
    } catch (err) {
      return {
        status: 'error',
        issues: [
          {
            severity: 'high',
            description: `Data privacy check failed: ${err.message}`,
          },
        ],
      };
    }
  }

  /**
   * Check financial compliance
   */
  async checkFinancialCompliance() {
    const issues = [];

    try {
      // Check for payments without proper authorization
      const unauthorizedPayments = await UBIPayment.countDocuments({
        status: 'completed',
        'metadata.approvedBy': { $exists: false },
      });

      if (unauthorizedPayments > 0) {
        issues.push({
          severity: 'high',
          description: `${unauthorizedPayments} payments lack proper authorization`,
          recommendation: 'Implement payment approval workflow',
        });
      }

      // Check for suspicious payment patterns
      const largePayments = await UBIPayment.countDocuments({
        amount: { $gt: 50000 }, // Over $50k threshold
        status: 'completed',
      });

      if (largePayments > 0) {
        issues.push({
          severity: 'medium',
          description: `${largePayments} unusually large payments detected`,
          recommendation: 'Review large payment transactions',
        });
      }

      return {
        status: issues.length === 0 ? 'compliant' : 'non_compliant',
        issues,
        checkedAt: new Date(),
      };
    } catch (err) {
      return {
        status: 'error',
        issues: [
          {
            severity: 'high',
            description: `Financial compliance check failed: ${err.message}`,
          },
        ],
      };
    }
  }

  /**
   * Check security standards compliance
   */
  async checkSecurityStandards() {
    const issues = [];

    try {
      // Check for citizens without biometric verification
      const unverifiedBiometrics = await Citizen.countDocuments({
        'verification.biometricVerified': false,
        status: 'active',
      });

      if (unverifiedBiometrics > 0) {
        issues.push({
          severity: 'medium',
          description: `${unverifiedBiometrics} active citizens lack biometric verification`,
          recommendation: 'Complete biometric verification process',
        });
      }

      // Check for failed login attempts (placeholder - would need actual security logs)
      // This would integrate with security monitoring service

      return {
        status: issues.length === 0 ? 'compliant' : 'non_compliant',
        issues,
        checkedAt: new Date(),
      };
    } catch (err) {
      return {
        status: 'error',
        issues: [
          {
            severity: 'high',
            description: `Security standards check failed: ${err.message}`,
          },
        ],
      };
    }
  }

  /**
   * Check education compliance
   */
  async checkEducationCompliance() {
    const issues = [];

    try {
      // Check for citizens not meeting education requirements
      const nonCompliant = await Citizen.countDocuments({
        'educationStatus.complianceStatus': 'non_compliant',
        status: 'active',
      });

      if (nonCompliant > 0) {
        issues.push({
          severity: 'high',
          description: `${nonCompliant} citizens are not meeting education requirements`,
          recommendation: 'Enforce education compliance measures',
        });
      }

      // Check for citizens approaching deadline
      const approachingDeadline = await Citizen.countDocuments({
        'educationStatus.complianceStatus': 'in_progress',
        'educationStatus.complianceDeadline': {
          $lte: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // Within 30 days
        },
        status: 'active',
      });

      if (approachingDeadline > 0) {
        issues.push({
          severity: 'medium',
          description: `${approachingDeadline} citizens approaching education deadline`,
          recommendation: 'Monitor progress and provide support',
        });
      }

      return {
        status: issues.length === 0 ? 'compliant' : 'non_compliant',
        issues,
        checkedAt: new Date(),
      };
    } catch (err) {
      return {
        status: 'error',
        issues: [
          {
            severity: 'high',
            description: `Education compliance check failed: ${err.message}`,
          },
        ],
      };
    }
  }

  /**
   * Check payment compliance
   */
  async checkPaymentCompliance() {
    const issues = [];

    try {
      // Check for failed payments
      const failedPayments = await UBIPayment.countDocuments({
        status: 'failed',
        paymentDate: {
          $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // Last 7 days
        },
      });

      if (failedPayments > 10) {
        // More than 10 failed payments in a week
        issues.push({
          severity: 'high',
          description: `${failedPayments} payment failures in the last week`,
          recommendation: 'Investigate payment system issues',
        });
      }

      // Check for payments without blockchain verification
      const unverifiedBlockchain = await UBIPayment.countDocuments({
        status: 'completed',
        blockchainHash: { $exists: false },
      });

      if (unverifiedBlockchain > 0) {
        issues.push({
          severity: 'medium',
          description: `${unverifiedBlockchain} completed payments lack blockchain verification`,
          recommendation: 'Ensure all payments are recorded on blockchain',
        });
      }

      return {
        status: issues.length === 0 ? 'compliant' : 'non_compliant',
        issues,
        checkedAt: new Date(),
      };
    } catch (err) {
      return {
        status: 'error',
        issues: [
          {
            severity: 'high',
            description: `Payment compliance check failed: ${err.message}`,
          },
        ],
      };
    }
  }

  /**
   * Check identity verification compliance
   */
  async checkIdentityVerification() {
    const issues = [];

    try {
      // Check for unverified identities
      const unverified = await Citizen.countDocuments({
        $or: [
          { 'verification.identityVerified': false },
          { 'verification.addressVerified': false },
        ],
        status: 'active',
      });

      if (unverified > 0) {
        issues.push({
          severity: 'high',
          description: `${unverified} active citizens have incomplete verification`,
          recommendation: 'Complete identity verification process',
        });
      }

      return {
        status: issues.length === 0 ? 'compliant' : 'non_compliant',
        issues,
        checkedAt: new Date(),
      };
    } catch (err) {
      return {
        status: 'error',
        issues: [
          {
            severity: 'high',
            description: `Identity verification check failed: ${err.message}`,
          },
        ],
      };
    }
  }

  /**
   * Generate alerts based on monitoring results
   * @param {Object} summary - Monitoring summary
   * @returns {Array} Alert messages
   */
  generateAlerts(summary) {
    const alerts = [];

    if (summary.highRisk >= this.ALERT_THRESHOLDS.highRisk) {
      alerts.push({
        level: 'critical',
        message: `${summary.highRisk} high-risk compliance issues detected`,
        action: 'Immediate attention required',
      });
    }

    if (summary.mediumRisk >= this.ALERT_THRESHOLDS.mediumRisk) {
      alerts.push({
        level: 'warning',
        message: `${summary.mediumRisk} medium-risk compliance issues detected`,
        action: 'Review and address issues',
      });
    }

    if (summary.lowRisk >= this.ALERT_THRESHOLDS.lowRisk) {
      alerts.push({
        level: 'info',
        message: `${summary.lowRisk} low-risk compliance issues detected`,
        action: 'Monitor and plan remediation',
      });
    }

    return alerts;
  }

  /**
   * Generate recommendations based on monitoring results
   * @param {Object} results - Full monitoring results
   * @returns {Array} Recommendations
   */
  generateRecommendations(results) {
    const recommendations = [];

    // Analyze each area for specific recommendations
    Object.entries(results.areas).forEach(([area, areaResult]) => {
      if (areaResult.issues && areaResult.issues.length > 0) {
        areaResult.issues.forEach((issue) => {
          if (issue.recommendation) {
            recommendations.push({
              area,
              priority: issue.severity,
              recommendation: issue.recommendation,
              issue: issue.description,
            });
          }
        });
      }
    });

    // Sort by priority
    const priorityOrder = { high: 3, medium: 2, low: 1 };
    recommendations.sort(
      (a, b) => priorityOrder[b.priority] - priorityOrder[a.priority]
    );

    return recommendations;
  }

  /**
   * Send compliance alerts via notification service
   * @param {Object} results - Monitoring results
   */
  async sendComplianceAlerts(results) {
    try {
      for (const alert of results.alerts) {
        await multiChannelNotificationService.send({
          type: 'COMPLIANCE_ALERT',
          priority: alert.level,
          title: 'Compliance Alert',
          message: alert.message,
          action: alert.action,
          recipients: ['compliance_officers', 'system_administrators'],
          metadata: {
            alertLevel: alert.level,
            monitoringResults: results.summary,
          },
        });
      }

      info(`Sent ${results.alerts.length} compliance alerts`);
    } catch (err) {
      error('Failed to send compliance alerts:', err);
    }
  }

  /**
   * Auto-remediate critical compliance issues
   * @param {Object} results - Monitoring results
   */
  async autoRemediateCriticalIssues(results) {
    try {
      // Auto-remediate non-critical issues only
      // Critical issues require manual intervention

      // Example: Auto-flag suspicious activities for review
      const suspiciousPayments =
        results.areas.payment_compliance?.issues?.filter((issue) =>
          issue.description.includes('unusually large')
        );

      if (suspiciousPayments && suspiciousPayments.length > 0) {
        // Flag for manual review
        await auditService.logActivity('system', 'AUTO_REMEDIATION', {
          action: 'FLAGGED_SUSPICIOUS_PAYMENTS',
          count: suspiciousPayments.length,
        });
      }

      debug('Auto-remediation completed');
    } catch (err) {
      error('Auto-remediation failed:', err);
    }
  }

  /**
   * Get compliance monitoring statistics
   * @returns {Promise<Object>} Statistics
   */
  async getComplianceStats() {
    try {
      const lastMonitoring = await this.monitorCompliance('system');
      return {
        lastCheck: lastMonitoring.timestamp,
        summary: lastMonitoring.summary,
        areas: Object.keys(lastMonitoring.areas).length,
        alerts: lastMonitoring.alerts.length,
        recommendations: lastMonitoring.recommendations.length,
      };
    } catch (err) {
      error('Failed to get compliance statistics:', err);
      throw err;
    }
  }

  /**
   * Get service health status
   * @returns {Object} Health status
   */
  getHealthStatus() {
    return {
      status: 'operational',
      service: 'Compliance Monitoring Service',
      monitoringInterval: `${this.MONITORING_INTERVAL / 1000}s`,
      complianceAreas: this.COMPLIANCE_AREAS.length,
      alertThresholds: this.ALERT_THRESHOLDS,
      lastCheck: new Date().toISOString(),
    };
  }
}

export default new ComplianceMonitoringService();
