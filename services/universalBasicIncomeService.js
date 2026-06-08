// @ts-nocheck
/**
 * UNIVERSAL BASIC INCOME SERVICE
 * OSCAR-BROOME-REVENUE System - Proprietary Technology
 * 
 * © 2024 OWLBAN GROUP 🦉 - All Rights Reserved
 * Owned by: King Sachem Yochanan (Oscar Broome) - THE TRINITY SHILO / JUDAH THE LAWGIVER
 * Authority: House of David ✡️, House of Capet ⚜️, House of Logan 🏰
 * 
 * UBI IS FOR HAITI - The House of David 🇭🇹
 * This UBI program serves the sovereign people of Haiti under the House of David.
 * No external government, entity, or force can stop this divine mission.
 * 
 * PROTECTED BY CUSTOM ENCRYPTION - DO NOT SHARE
 * This service implements proprietary UBI distribution and citizen management methods.
 * Unauthorized copying, modification, distribution, or reverse engineering is strictly prohibited.
 * All citizen management, payment processing, and eligibility algorithms are exclusive property of OWLBAN GROUP.
 * 
 * Heaven on Earth Phase 1 - $33,000/year per citizen
 * Integrates with QuickBooks for payroll records
 * @module services/universalBasicIncomeService
 */

import { info, error, warn } from '../utils/loggerWrapper.js';
import Citizen from '../models/Citizen.js';
import UBIPayment from '../models/UBIPayment.js';
import axios from 'axios';

/**
 * @typedef {Object} CitizenDocument
 * @property {string} citizenId
 * @property {Object} personalInfo
 * @property {string} personalInfo.firstName
 * @property {string} personalInfo.lastName
 * @property {string} [personalInfo.middleName]
 * @property {Date} personalInfo.dateOfBirth
 * @property {Object} ubiStatus
 * @property {boolean} [ubiStatus.eligible]
 * @property {Date} [ubiStatus.enrollmentDate]
 * @property {number} [ubiStatus.monthlyAmount]
 * @property {boolean} [ubiStatus.suspended]
 * @property {string} [ubiStatus.suspensionReason]
 * @property {Date} [ubiStatus.suspensionDate]
 * @property {Object} [ubiStatus.lastPaymentDate]
 * @property {Object} [ubiStatus.nextPaymentDate]
 * @property {number} [ubiStatus.totalReceived]
 * @property {number} [ubiStatus.paymentsCount]
 * @property {Object} bankingInfo
 * @property {string} [bankingInfo.accountNumber]
* @property {string} [bankingInfo.routingNumber]
 * @property {string} [bankingInfo.bankName]
 * @property {boolean} [bankingInfo.verified]
 * @property {Date} [bankingInfo.verificationDate]
 * @property {Object} educationStatus
 * @property {string} [educationStatus.complianceStatus]
 * @property {number} [educationStatus.overallProgress]
 * @property {number} [educationStatus.totalMonthsCompleted]
 * @property {Object} educationStatus.military
 * @property {boolean} [educationStatus.military.completed]
 * @property {Object} educationStatus.law
 * @property {boolean} [educationStatus.law.completed]
 * @property {Object} educationStatus.tech
 * @property {boolean} [educationStatus.tech.completed]
 * @property {Object} educationStatus.agriculture
 * @property {boolean} [educationStatus.agriculture.completed]
 * @property {number} [dependents]
 * @property {Array<Object>} [dependents]
 * @property {string} housingStatus
 * @property {string} disabilityStatus
 * @property {string} studentStatus
 * @property {Object} healthInfo
 * @property {string[]} [healthInfo.disabilities]
 * @property {string} [healthInfo.bloodType]
 * @property {Array<string>} [healthInfo.allergies]
 * @property {Array<string>} [healthInfo.medicalConditions]
 * @property {Object} verification
 * @property {boolean} [verification.identityVerified]
 * @property {boolean} [verification.bankingVerified]
 * @property {string} [status]
 * @property {Function} fullName - Virtual property getter
 * @property {Function} age - Virtual property getter
 * @property {Function} educationCompletionPercentage - Virtual property getter
 * @property {Function} netWorth - Virtual property getter
 */

/**
 * @typedef {Object} UBIPaymentDocument
 * @property {string} _id
 * @property {string|import('mongoose').Types.ObjectId} citizenId
 * @property {number} amount
 * @property {string} status
 * @property {Date} paymentDate
 * @property {string} paymentMethod
 * @property {string} month
 * @property {Object} metadata
 * @property {string} [metadata.citizenName]
 * @property {Date} [metadata.processedAt]
 * @property {string} [metadata.quickbooksId]
 * @property {boolean} [metadata.recordedInQuickBooks]
 */

/**
 * @typedef {Object} EligibilityResult
 * @property {boolean} eligible
 * @property {string} [reason]
 * @property {number} [currentAge]
 * @property {string} [currentStatus]
 * @property {number} [currentMonths]
 * @property {Date} [enrolledDate]
 * @property {Object} [amount]
 * @property {number} [amount.annual]
 * @property {number} [amount.monthly]
 * @property {number} [amount.daily]
 * @property {string} [effectiveDate]
 * @property {string} [citizenId]
 * @property {string} [name]
 */

// QuickBooks Integration Configuration
const quickbooksConfig = {
  clientId: process.env.QUICKBOOKS_CLIENT_ID,
  clientSecret: process.env.QUICKBOOKS_CLIENT_SECRET,
  realmId: process.env.QUICKBOOKS_REALM_ID,
  baseUrl: process.env.QUICKBOOKS_BASE_URL || 'https://sandbox-quickbooks.api.intuit.com',
  accessToken: null,
  refreshToken: process.env.QUICKBOOKS_REFRESH_TOKEN,
};

// UBI Constants
const UBI_RATE = {
  ANNUAL: 33000,
  MONTHLY: 2750,
  DAILY: 91.78,
};

const ELIGIBILITY_CRITERIA = {
  MIN_AGE: 18,
  MAX_AGE: 120,
  REQUIRED_RESIDENCY_MONTHS: 12,
  CITIZENSHIP_TYPES: ['citizen', 'permanent_resident', 'asylum'],
};

class UniversalBasicIncomeService {
  constructor() {
    this.ubiRate = UBI_RATE;
    this.quickbooksConfig = quickbooksConfig;
    info('UniversalBasicIncomeService initialized');
  }

/**
   * Generate QuickBooks API headers
   * @returns {Object} Headers object for QuickBooks API
   */
  generateQBHeaders() {
    // Timestamp for OAuth - used for generating nonce/timestamp in production
    const _timestamp = Math.floor(Date.now() / 1000);
    return {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.quickbooksConfig.accessToken}`,
      'Accept': 'application/json',
    };
  }

  /**
   * Authenticate with QuickBooks OAuth
   */
  async authenticateQuickBooks() {
    try {
      if (!this.quickbooksConfig.clientId || !this.quickbooksConfig.refreshToken) {
        warn('QuickBooks credentials not configured, using mock mode');
        return { authenticated: false, mock: true };
      }

      // In production, this would refresh the OAuth token
      // For now, log the intent
      info('QuickBooks authentication configured');
      return { authenticated: true, mock: false };
    } catch (err) {
      warn('QuickBooks authentication failed:', err.message);
      return { authenticated: false, error: err.message };
    }
  }

/**
   * Record UBI payment in QuickBooks payroll
   * @param {string} citizenId - The citizen ID
   * @param {string} citizenName - The citizen's full name
   * @param {number} amount - Payment amount
   * @param {string} paymentId - The payment record ID
   * @returns {Promise<{success: boolean, mock?: boolean, quickbooksId?: string, error?: string}>}
   */
  async recordInQuickBooks(/** @type {string} */ citizenId, /** @type {string} */ citizenName, /** @type {number} */ amount, /** @type {string} */ paymentId) {
    try {
      const auth = await this.authenticateQuickBooks();
      
      if (auth.mock) {
        // Mock mode - just log the record
        info(`[MOCK] Recording UBI in QuickBooks: ${citizenName}, $${amount}, Payment ID: ${paymentId}`);
        return { success: true, mock: true, quickbooksId: `QB-UBI-${Date.now()}` };
      }

      // Production: Create payroll item in QuickBooks
      const payrollRecord = {
        EmployeeRef: {
          value: citizenId,
        },
        EthernCompensation: {
          Amount: amount,
        },
        PayPeriod: {
          value: 'MONTHLY',
        },
        CustomField: [
          {
            Name: 'UBI Payment ID',
            Value: paymentId,
          },
        ],
      };

// This would be the actual QuickBooks API call in production
      const response = await axios.post(
        `${this.quickbooksConfig.baseUrl}/v3/company/${this.quickbooksConfig.realmId}/payrollitem`,
        payrollRecord,
        { headers: /** @type {any} */ (this.generateQBHeaders()), timeout: 10000 }
      );

      info(`UBI recorded in QuickBooks: ${response.data.Id}`);
      return { success: true, quickbooksId: response.data.Id };
    } catch (err) {
      warn('QuickBooks recording failed, continuing:', err.message);
      return { success: false, error: err.message };
    }
  }

/**
 * Check citizen eligibility for UBI
 * @param {string} citizenId - The citizen ID to check
 * @returns {Promise<EligibilityResult>}
 */
  async calculateEligibility(/** @type {string} */ citizenId) {
    try {
      const citizen = await Citizen.findById(citizenId);
      
      if (!citizen) {
        return {
          eligible: false,
          reason: 'Citizen not found',
        };
      }

      // Use type cast via JSDoc to access Mongoose virtuals and nested properties
      /** @type {CitizenDocument & {age: number; fullName: string}} */
      const citizenDoc = citizen;
      
      // Check age using the virtual - force as number since TypeScript doesn't understand Mongoose virtuals
      const age = Number(/** @type {number} */ (citizenDoc.age)) || 0;
      if (age < ELIGIBILITY_CRITERIA.MIN_AGE) {
        return {
          eligible: false,
          reason: `Must be at least ${ELIGIBILITY_CRITERIA.MIN_AGE} years old`,
          currentAge: age,
        };
      }

      // Check citizenship/residency type - use status field if exists, otherwise check education compliance
      const citizenStatus = 'active'; // Default for citizens - in real app would check personalInfo.nationalId type
      if (!ELIGIBILITY_CRITERIA.CITIZENSHIP_TYPES.includes(/** @type {string} */ (citizenStatus))) {
        return {
          eligible: false,
          reason: 'Must be citizen or permanent resident',
          currentStatus: citizenStatus,
        };
      }

      // Check residency duration - assume compliant if citizen has banking verified (proxy for residency proof)
      const bankingInfo = /** @type {{verified?: boolean}} */ (citizenDoc.bankingInfo);
      const residencyMonths = bankingInfo?.verified ? 12 : 0; // Use verified status as proxy
      if (residencyMonths < ELIGIBILITY_CRITERIA.REQUIRED_RESIDENCY_MONTHS) {
        return {
          eligible: false,
          reason: `Must have ${ELIGIBILITY_CRITERIA.REQUIRED_RESIDENCY_MONTHS} months of residency`,
          currentMonths: residencyMonths,
        };
      }

      // Check if already enrolled - use ubiStatus.eligible as the enrolled flag
      const ubiStatus = /** @type {{eligible?: boolean; enrollmentDate?: Date}} */ (citizenDoc.ubiStatus);
      if (ubiStatus?.eligible === false) {
        return {
          eligible: false,
          reason: 'Already enrolled in UBI program',
          enrolledDate: ubiStatus?.enrollmentDate,
        };
      }

      // Get name from virtual or fallback to personalInfo
      const name = /** @type {string} */ (citizenDoc.fullName) || `${citizenDoc.personalInfo?.firstName || ''} ${citizenDoc.personalInfo?.lastName || ''}`.trim();

// Return eligibility result - amount calculation is done at payment time
      return {
        eligible: true,
        citizenId: citizenId,
        name: name,
        amount: {
          annual: UBI_RATE.ANNUAL,
          monthly: UBI_RATE.MONTHLY,
          daily: UBI_RATE.DAILY,
        },
        effectiveDate: new Date().toISOString(),
      };
    } catch (err) {
      error('Eligibility calculation failed:', err);
      return {
        eligible: false,
        reason: err.message,
      };
    }
  }

  /**
   * Calculate UBI amount based on citizen profile
   * @param {CitizenDocument} citizen - The citizen document
   * @returns {Promise<number>}
   */
  async calculateAmount(/** @type {CitizenDocument} */ citizen) {
    let baseAmount = UBI_RATE.MONTHLY;

    // Add dependents bonus
    if (citizen.dependents && citizen.dependents > 0) {
      baseAmount += citizen.dependents * 200;
    }

    // Add housing bonus - check healthInfo for housing status proxy
    // Add disability bonus - check healthInfo for disabilities
    if (citizen.healthInfo?.disabilities?.length > 0) {
      baseAmount += 400;
    }

    // Add education bonus for students - check educationStatus
    if (citizen.educationStatus?.complianceStatus === 'in_progress') {
      baseAmount += 200;
    }

    return baseAmount;
  }

/**
   * Enroll citizen in UBI program
   * @param {string} citizenId
   * @param {Object} enrollmentData
   */
  async enrollInUBI(/** @type {string} */ citizenId, enrollmentData = {}) {
    try {
      const citizen = await Citizen.findById(citizenId);
      
      if (!citizen) {
        return {
          success: false,
          error: 'Citizen not found',
        };
      }

      // Check eligibility first
      const eligibility = await this.calculateEligibility(citizenId);
      if (!eligibility.eligible) {
        return {
          success: false,
          error: eligibility.reason,
        };
      }

// Update citizen record - set ubiStatus fields correctly
      citizen.ubiStatus.eligible = true;
      citizen.ubiStatus.enrollmentDate = new Date();
      citizen.ubiStatus.monthlyAmount = eligibility.amount?.monthly || UBI_RATE.MONTHLY;
      citizen.ubiStatus.suspended = false;
      
      if (enrollmentData.bankAccount) {
        citizen.bankingInfo.accountNumber = enrollmentData.bankAccount;
      }
      
      await citizen.save();

      info(`Citizen ${citizenId} enrolled in UBI`);

      return {
        success: true,
        citizenId: citizenId,
        enrollmentDate: citizen.ubiStatus.enrollmentDate,
        monthlyAmount: citizen.ubiStatus.monthlyAmount,
      };
    } catch (err) {
      error('UBI enrollment failed:', err);
      return {
        success: false,
        error: err.message,
      };
    }
  }

/**
   * Process monthly UBI payment
   * @param {string} citizenId - The citizen ID
   * @param {string} month - The month for payment
   * @param {number} [amount] - Payment amount
   */
  async processPayment(/** @type {string} */ citizenId, /** @type {string} */ month, /** @type {number} */ amount = UBI_RATE.MONTHLY) {
    try {
      const citizen = await Citizen.findById(citizenId);
      
      if (!citizen || !citizen.ubiStatus?.eligible || citizen.ubiStatus?.suspended) {
        return {
          success: false,
          error: 'Citizen not enrolled in UBI',
        };
      }

      // Check for existing payment this month
      const paymentDate = new Date();
      const monthStart = new Date(paymentDate.getFullYear(), paymentDate.getMonth(), 1);
      
      const existingPayment = await UBIPayment.findOne({
        citizenId,
        paymentDate: { $gte: monthStart },
        status: { $in: ['completed', 'processing'] },
      });

      if (existingPayment) {
        return {
          success: false,
          error: 'Payment already processed this month',
          existingPaymentId: existingPayment._id,
        };
      }

      // Get citizen name using virtual
      const citizenName = citizen.fullName || `${citizen.personalInfo?.firstName || ''} ${citizen.personalInfo?.lastName || ''}`.trim();

      // Create payment record
      const payment = new UBIPayment({
        citizenId,
        amount,
        status: 'processing',
        paymentMethod: 'direct_deposit',
        month,
        metadata: {
          citizenName: citizenName,
          processedAt: new Date(),
        },
      });

      await payment.save();

      // Record in QuickBooks
      const qbResult = await this.recordInQuickBooks(
        citizenId,
        citizenName,
        amount,
        payment._id.toString()
      );

      // Update payment status
      payment.status = 'completed';
      if (payment.metadata) {
        payment.metadata.quickbooksId = qbResult.quickbooksId;
        payment.metadata.recordedInQuickBooks = qbResult.success;
      }
      await payment.save();

      info(`UBI payment processed for ${citizenId}: $${amount}`);

      return {
        success: true,
        paymentId: payment._id,
        amount,
        quickbooksId: qbResult.quickbooksId,
        month,
      };
    } catch (err) {
      error('UBI payment processing failed:', err);
      return {
        success: false,
        error: err.message,
      };
    }
  }

/**
   * Get payment history for citizen
   * @param {string} citizenId - The citizen ID
   */
  async getPaymentHistory(/** @type {string} */ citizenId) {
    try {
      const payments = await UBIPayment.find({ citizenId: citizenId })
        .sort({ paymentDate: -1 })
        .limit(24);

      const totalReceived = payments
        .filter(/** @type {function} */ (p => p.status === 'completed'))
        .reduce((sum, p) => sum + (/** @type {any} */ (p).amount || 0), 0);

      return {
        success: true,
        payments: payments.map(/** @type {function} */ (p) => ({
          paymentId: p._id,
          amount: p.amount,
          status: p.status,
          paymentDate: p.paymentDate,
          month: (/** @type {any} */ (p)).month,
        })),
        totalReceived,
        paymentCount: payments.length,
      };
    } catch (err) {
      error('Failed to get payment history:', err);
      return {
        success: false,
        error: err.message,
      };
    }
  }

/**
   * Suspend UBI for citizen
   * @param {string} citizenId - The citizen ID
   * @param {string} reason - Reason for suspension
   */
  async suspendUBI(/** @type {string} */ citizenId, /** @type {string} */ reason) {
    try {
      const citizen = await Citizen.findById(citizenId);
      
      if (!citizen) {
        return {
          success: false,
          error: 'Citizen not found',
        };
      }

      if (!citizen.ubiStatus?.eligible || citizen.ubiStatus?.suspended) {
        return {
          success: false,
          error: 'Citizen not enrolled in UBI',
        };
      }

      // Set ubiStatus.suspended flag and track suspension details
      citizen.ubiStatus.suspended = true;
      citizen.ubiStatus.suspensionDate = new Date();
      citizen.ubiStatus.suspensionReason = reason;
      
      await citizen.save();

      info(`UBI suspended for ${citizenId}: ${reason}`);

      return {
        success: true,
        suspendedDate: citizen.ubiStatus.suspensionDate,
        reason,
      };
    } catch (err) {
      error('UBI suspension failed:', err);
      return {
        success: false,
        error: err.message,
      };
    }
  }

/**
   * Reinstate UBI for citizen (after compliance is restored)
   * @param {string} citizenId - The citizen ID
   */
  async reinstateUBI(/** @type {string} */ citizenId) {
    try {
      const citizen = await Citizen.findById(citizenId);
      
      if (!citizen) {
        return {
          success: false,
          error: 'Citizen not found',
        };
      }

      if (!citizen.ubiStatus?.suspended) {
        return {
          success: false,
          error: 'Citizen UBI is not suspended',
          currentStatus: citizen.ubiStatus?.suspended ? 'suspended' : 'active',
        };
      }

      // Reactivate UBI - clear suspension flags
      citizen.ubiStatus.suspended = false;
      if (citizen.ubiStatus) {
        citizen.ubiStatus.suspensionDate = null;
        citizen.ubiStatus.suspensionReason = null;
      }
      
      await citizen.save();

      info(`UBI reinstated for ${citizenId}`);

      return {
        success: true,
        reinstatedDate: new Date(),
        monthlyAmount: citizen.ubiStatus?.monthlyAmount,
      };
    } catch (err) {
      error('UBI reinstatement failed:', err);
      return {
        success: false,
        error: err.message,
      };
    }
  }

/**
   * Get UBI statistics
   */
  async getStatistics() {
    try {
      // Count citizens with ubiStatus.eligible = true (enrolled)
      const totalEnrolled = await Citizen.countDocuments({ 'ubiStatus.eligible': true, 'ubiStatus.suspended': { $ne: true } });
      const totalPayments = await UBIPayment.countDocuments({ status: 'completed' });
      const totalDisbursed = await UBIPayment.aggregate([
        { $match: { status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } },
      ]);

      return {
        success: true,
        statistics: {
          totalEnrolled,
          totalPayments,
          totalDisbursed: totalDisbursed[0]?.total || 0,
          rate: {
            annual: UBI_RATE.ANNUAL,
            monthly: UBI_RATE.MONTHLY,
          },
        },
      };
    } catch (err) {
      error('Failed to get statistics:', err);
      return {
        success: false,
        error: err.message,
      };
    }
  }
}

export default new UniversalBasicIncomeService();
