/**
 * COMPLIANCE SERVICE
 * Monitors education compliance and enforces UBI eligibility
 * Part of the OWLBAN GROUP Heaven on Earth Initiative
 *
 * Compliance Rules:
 * - Citizens must complete all 4 education tracks within 24 months
 * - Failure to comply results in UBI suspension
 * - Grace period: 30 days
 * - Medical/hardship exemptions available
 */

import Citizen from '../models/Citizen.js';
import EducationProgram from '../models/Education.js';
import UniversalBasicIncomeService from './universalBasicIncomeService.js';
import { createLogger } from '../config/logger.js';

const logger = createLogger('Compliance-Service');

class ComplianceService {
  constructor() {
    this.ubiService = new UniversalBasicIncomeService();
    this.COMPLIANCE_DEADLINE_MONTHS = 24;
    this.GRACE_PERIOD_DAYS = 30;
    this.PROGRESS_CHECKPOINT_MONTHS = 3;

    logger.info('Compliance Service initialized');
  }

  /**
   * Run compliance check for all citizens
   * @param {string} userId - User ID running compliance check
   * @returns {Promise<Object>} Compliance check results
   */
  async runComplianceCheck(userId) {
    try {
      logger.info('Starting compliance check for all citizens');

      const startTime = Date.now();

      // Get all active citizens
      const citizens = await Citizen.find({ status: 'active' });

      const results = {
        totalChecked: 0,
        compliant: 0,
        inProgress: 0,
        nonCompliant: 0,
        gracePeriod: 0,
        exempt: 0,
        actionsTaken: [],
        warnings: [],
      };

      for (const citizen of citizens) {
        results.totalChecked++;

        const complianceResult = await this.checkCitizenCompliance(
          citizen,
          userId
        );

        // Update counters
        switch (complianceResult.status) {
          case 'compliant':
            results.compliant++;
            break;
          case 'in_progress':
            results.inProgress++;
            break;
          case 'non_compliant':
            results.nonCompliant++;
            break;
          case 'grace_period':
            results.gracePeriod++;
            break;
          case 'exempt':
            results.exempt++;
            break;
        }

        // Record actions taken
        if (complianceResult.actionTaken) {
          results.actionsTaken.push({
            citizenId: citizen.citizenId,
            action: complianceResult.actionTaken,
            reason: complianceResult.reason,
          });
        }

        // Record warnings
        if (complianceResult.warning) {
          results.warnings.push({
            citizenId: citizen.citizenId,
            warning: complianceResult.warning,
          });
        }
      }

      const duration = Date.now() - startTime;

      logger.info(
        `Compliance check completed: ${results.totalChecked} citizens checked in ${duration}ms`
      );

      return {
        success: true,
        summary: {
          totalChecked: results.totalChecked,
          compliant: results.compliant,
          inProgress: results.inProgress,
          nonCompliant: results.nonCompliant,
          gracePeriod: results.gracePeriod,
          exempt: results.exempt,
          complianceRate:
            ((results.compliant / results.totalChecked) * 100).toFixed(2) + '%',
          duration: `${duration}ms`,
        },
        actionsTaken: results.actionsTaken,
        warnings: results.warnings,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      logger.error('Error running compliance check:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Check compliance for a single citizen
   * @param {Object} citizen - Citizen document
   * @param {string} userId - User ID performing check
   * @returns {Promise<Object>} Compliance result
   */
  async checkCitizenCompliance(citizen, userId) {
    try {
      // Check if exempt
      if (citizen.educationStatus.complianceStatus === 'exempt') {
        return {
          status: 'exempt',
          reason: citizen.educationStatus.exemptionReason,
        };
      }

      // Calculate enrollment duration
      const enrollmentDate =
        citizen.ubiStatus.enrollmentDate || citizen.createdAt;
      const monthsSinceEnrollment = this.calculateMonthsDifference(
        enrollmentDate,
        new Date()
      );

      // Check if all tracks completed
      const allTracksCompleted =
        citizen.educationStatus.military.completed &&
        citizen.educationStatus.law.completed &&
        citizen.educationStatus.tech.completed &&
        citizen.educationStatus.agriculture.completed;

      if (allTracksCompleted) {
        // Update to compliant if not already
        if (citizen.educationStatus.complianceStatus !== 'compliant') {
          citizen.educationStatus.complianceStatus = 'compliant';
          await citizen.save();
        }

        return {
          status: 'compliant',
          reason: 'All education tracks completed',
        };
      }

      // Check if within deadline
      if (monthsSinceEnrollment < this.COMPLIANCE_DEADLINE_MONTHS) {
        // Still in progress
        if (citizen.educationStatus.complianceStatus !== 'in_progress') {
          citizen.educationStatus.complianceStatus = 'in_progress';
          await citizen.save();
        }

        // Check if approaching deadline (within 3 months)
        if (monthsSinceEnrollment >= this.COMPLIANCE_DEADLINE_MONTHS - 3) {
          return {
            status: 'in_progress',
            warning: `Approaching compliance deadline. ${this.COMPLIANCE_DEADLINE_MONTHS - monthsSinceEnrollment} months remaining.`,
          };
        }

        return {
          status: 'in_progress',
          reason: `${monthsSinceEnrollment} months elapsed, ${this.COMPLIANCE_DEADLINE_MONTHS - monthsSinceEnrollment} months remaining`,
        };
      }

      // Past deadline - check grace period
      if (citizen.ubiStatus.gracePeriodEnd) {
        const gracePeriodEnd = new Date(citizen.ubiStatus.gracePeriodEnd);
        if (new Date() < gracePeriodEnd) {
          return {
            status: 'grace_period',
            reason: `Grace period active until ${gracePeriodEnd.toISOString().split('T')[0]}`,
          };
        }
      }

      // Non-compliant - suspend UBI if not already suspended
      if (!citizen.ubiStatus.suspended) {
        const suspensionResult = await this.ubiService.suspendUBI(
          citizen.citizenId,
          'Education compliance deadline exceeded',
          userId
        );

        return {
          status: 'non_compliant',
          reason: 'Education compliance deadline exceeded',
          actionTaken: 'UBI_SUSPENDED',
          suspensionResult: suspensionResult,
        };
      }

      return {
        status: 'non_compliant',
        reason: 'Education compliance deadline exceeded (already suspended)',
      };
    } catch (error) {
      logger.error(
        `Error checking compliance for citizen ${citizen.citizenId}:`,
        error
      );
      throw error;
    }
  }

  /**
   * Grant exemption to a citizen
   * @param {string} citizenId - Citizen ID
   * @param {string} reason - Exemption reason
   * @param {string} userId - User ID granting exemption
   * @returns {Promise<Object>} Exemption result
   */
  async grantExemption(citizenId, reason, userId) {
    try {
      const citizen = await Citizen.findOne({ citizenId });

      if (!citizen) {
        return {
          success: false,
          error: 'Citizen not found',
        };
      }

      citizen.educationStatus.complianceStatus = 'exempt';
      citizen.educationStatus.exemptionReason = reason;
      citizen.educationStatus.exemptionApprovedBy = userId;

      // Reinstate UBI if suspended
      if (citizen.ubiStatus.suspended) {
        await this.ubiService.reinstateUBI(citizenId, userId);
      }

      citizen.auditLog.push({
        action: 'EXEMPTION_GRANTED',
        performedBy: userId,
        timestamp: new Date(),
        details: { reason: reason },
      });

      await citizen.save();

      logger.info(`Exemption granted to citizen ${citizenId}: ${reason}`);

      return {
        success: true,
        message: 'Exemption granted successfully',
        citizenId: citizenId,
        exemptionReason: reason,
      };
    } catch (error) {
      logger.error('Error granting exemption:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Revoke exemption from a citizen
   * @param {string} citizenId - Citizen ID
   * @param {string} userId - User ID revoking exemption
   * @returns {Promise<Object>} Revocation result
   */
  async revokeExemption(citizenId, userId) {
    try {
      const citizen = await Citizen.findOne({ citizenId });

      if (!citizen) {
        return {
          success: false,
          error: 'Citizen not found',
        };
      }

      if (citizen.educationStatus.complianceStatus !== 'exempt') {
        return {
          success: false,
          error: 'Citizen does not have an active exemption',
        };
      }

      const previousReason = citizen.educationStatus.exemptionReason;

      citizen.educationStatus.complianceStatus = 'in_progress';
      citizen.educationStatus.exemptionReason = null;
      citizen.educationStatus.exemptionApprovedBy = null;

      citizen.auditLog.push({
        action: 'EXEMPTION_REVOKED',
        performedBy: userId,
        timestamp: new Date(),
        details: { previousReason: previousReason },
      });

      await citizen.save();

      logger.info(`Exemption revoked for citizen ${citizenId}`);

      return {
        success: true,
        message: 'Exemption revoked successfully',
        citizenId: citizenId,
      };
    } catch (error) {
      logger.error('Error revoking exemption:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get compliance statistics
   * @returns {Promise<Object>} Compliance statistics
   */
  async getComplianceStatistics() {
    try {
      const totalCitizens = await Citizen.countDocuments({ status: 'active' });

      const complianceStats = await Citizen.aggregate([
        { $match: { status: 'active' } },
        {
          $group: {
            _id: '$educationStatus.complianceStatus',
            count: { $sum: 1 },
          },
        },
      ]);

      const stats = complianceStats.reduce((acc, item) => {
        acc[item._id] = item.count;
        return acc;
      }, {});

      // Get citizens approaching deadline
      const approachingDeadline = await Citizen.countDocuments({
        status: 'active',
        'educationStatus.complianceStatus': 'in_progress',
        'educationStatus.complianceDeadline': {
          $lte: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), // Within 90 days
        },
      });

      // Get suspended due to non-compliance
      const suspendedForCompliance = await Citizen.countDocuments({
        status: 'active',
        'ubiStatus.suspended': true,
        'ubiStatus.suspensionReason': /compliance|education/i,
      });

      return {
        success: true,
        statistics: {
          total: totalCitizens,
          compliant: stats.compliant || 0,
          inProgress: stats.in_progress || 0,
          nonCompliant: stats.non_compliant || 0,
          gracePeriod: stats.grace_period || 0,
          exempt: stats.exempt || 0,
          complianceRate:
            totalCitizens > 0
              ? (((stats.compliant || 0) / totalCitizens) * 100).toFixed(2) +
                '%'
              : '0%',
          approachingDeadline: approachingDeadline,
          suspendedForCompliance: suspendedForCompliance,
        },
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      logger.error('Error getting compliance statistics:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Calculate months difference between two dates
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @returns {number} Months difference
   */
  calculateMonthsDifference(startDate, endDate) {
    const start = new Date(startDate);
    const end = new Date(endDate);

    let months = (end.getFullYear() - start.getFullYear()) * 12;
    months -= start.getMonth();
    months += end.getMonth();

    return months <= 0 ? 0 : months;
  }

  /**
   * Get service health status
   * @returns {Object} Health status
   */
  getHealthStatus() {
    return {
      status: 'operational',
      service: 'Compliance Service',
      complianceDeadline: `${this.COMPLIANCE_DEADLINE_MONTHS} months`,
      gracePeriod: `${this.GRACE_PERIOD_DAYS} days`,
      checkpointInterval: `${this.PROGRESS_CHECKPOINT_MONTHS} months`,
      lastCheck: new Date().toISOString(),
    };
  }
}

export default ComplianceService;
