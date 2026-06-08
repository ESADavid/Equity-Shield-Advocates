/**
 * UNIVERSAL BASIC INCOME SERVICE
 * Heaven on Earth Phase 1 - $33,000/year per citizen
 * Integrates with QuickBooks for payroll records
 */

import { info, error, warn } from '../utils/loggerWrapper.js';
import Citizen from '../models/Citizen.js';
import UBIPayment from '../models/UBIPayment.js';
import axios from 'axios';
import crypto from 'crypto';

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
   */
  generateQBHeaders() {
    const timestamp = Math.floor(Date.now() / 1000);
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
   */
  async recordInQuickBooks(citizenId, citizenName, amount, paymentId) {
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
        { headers: this.generateQBHeaders(), timeout: 10000 }
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
   */
  async calculateEligibility(citizenId) {
    try {
      const citizen = await Citizen.findById(citizenId);
      
      if (!citizen) {
        return {
          eligible: false,
          reason: 'Citizen not found',
        };
      }

      // Check age
      const age = citizen.age || 0;
      if (age < ELIGIBILITY_CRITERIA.MIN_AGE) {
        return {
          eligible: false,
          reason: `Must be at least ${ELIGIBILITY_CRITERIA.MIN_AGE} years old`,
          currentAge: age,
        };
      }

      // Check citizenship/residency type
      if (!ELIGIBILITY_CRITERIA.CITIZENSHIP_TYPES.includes(citizen.citizenshipStatus)) {
        return {
          eligible: false,
          reason: 'Must be citizen or permanent resident',
          currentStatus: citizen.citizenshipStatus,
        };
      }

      // Check residency duration
      const residencyMonths = citizen.residencyMonths || 0;
      if (residencyMonths < ELIGIBILITY_CRITERIA.REQUIRED_RESIDENCY_MONTHS) {
        return {
          eligible: false,
          reason: `Must have ${ELIGIBILITY_CRITERIA.REQUIRED_RESIDENCY_MONTHS} months of residency`,
          currentMonths: residencyMonths,
        };
      }

      // Check if already enrolled
      if (citizen.ubiStatus === 'enrolled') {
        return {
          eligible: false,
          reason: 'Already enrolled in UBI program',
          enrolledDate: citizen.ubiEnrollmentDate,
        };
      }

      // Calculate eligible amount
      const eligibleAmount = await this.calculateAmount(citizen);

      return {
        eligible: true,
        citizenId: citizenId,
        name: citizen.name,
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
   */
  async calculateAmount(citizen) {
    let baseAmount = UBI_RATE.MONTHLY;

    // Add dependents bonus
    if (citizen.dependents && citizen.dependents > 0) {
      baseAmount += citizen.dependents * 200;
    }

    // Add housing bonus for renters
    if (citizen.housingStatus === 'renting') {
      baseAmount += 300;
    }

    // Add disability bonus
    if (citizen.disabilityStatus === 'active') {
      baseAmount += 400;
    }

    // Add education bonus for students
    if (citizen.studentStatus === 'enrolled') {
      baseAmount += 200;
    }

    return baseAmount;
  }

  /**
   * Enroll citizen in UBI program
   */
  async enrollInUBI(citizenId, enrollmentData = {}) {
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

      // Update citizen record
      citizen.ubiStatus = 'enrolled';
      citizen.ubiEnrollmentDate = new Date();
      citizen.ubiMonthlyAmount = eligibility.amount?.monthly || UBI_RATE.MONTHLY;
      
      if (enrollmentData.bankAccount) {
        citizen.bankAccount = enrollmentData.bankAccount;
      }
      
      await citizen.save();

      info(`Citizen ${citizenId} enrolled in UBI`);

      return {
        success: true,
        citizenId: citizenId,
        enrollmentDate: citizen.ubiEnrollmentDate,
        monthlyAmount: citizen.ubiMonthlyAmount,
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
   */
  async processPayment(citizenId, month, amount = UBI_RATE.MONTHLY) {
    try {
      const citizen = await Citizen.findById(citizenId);
      
      if (!citizen || citizen.ubiStatus !== 'enrolled') {
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

      // Create payment record
      const payment = new UBIPayment({
        citizenId,
        amount,
        status: 'processing',
        paymentMethod: 'direct_deposit',
        month,
        metadata: {
          citizenName: citizen.name,
          processedAt: new Date(),
        },
      });

      await payment.save();

      // Record in QuickBooks
      const qbResult = await this.recordInQuickBooks(
        citizenId,
        citizen.name,
        amount,
        payment._id.toString()
      );

      // Update payment status
      payment.status = 'completed';
      payment.metadata.quickbooksId = qbResult.quickbooksId;
      payment.metadata.recordedInQuickBooks = qbResult.success;
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
   */
  async getPaymentHistory(citizenId) {
    try {
      const payments = await UBIPayment.find({ citizenId })
        .sort({ paymentDate: -1 })
        .limit(24);

      const totalReceived = payments
        .filter(p => p.status === 'completed')
        .reduce((sum, p) => sum + p.amount, 0);

      return {
        success: true,
        payments: payments.map(p => ({
          paymentId: p._id,
          amount: p.amount,
          status: p.status,
          paymentDate: p.paymentDate,
          month: p.month,
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
   */
  async suspendUBI(citizenId, reason) {
    try {
      const citizen = await Citizen.findById(citizenId);
      
      if (!citizen) {
        return {
          success: false,
          error: 'Citizen not found',
        };
      }

      if (citizen.ubiStatus !== 'enrolled') {
        return {
          success: false,
          error: 'Citizen not enrolled in UBI',
        };
      }

      citizen.ubiStatus = 'suspended';
      citizen.ubiSuspensionDate = new Date();
      citizen.ubiSuspensionReason = reason;
      
      await citizen.save();

      info(`UBI suspended for ${citizenId}: ${reason}`);

      return {
        success: true,
        suspendedDate: citizen.ubiSuspensionDate,
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
   * Get UBI statistics
   */
  async getStatistics() {
    try {
      const totalEnrolled = await Citizen.countDocuments({ ubiStatus: 'enrolled' });
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
