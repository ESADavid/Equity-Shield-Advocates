/**
 * UNIVERSAL BASIC INCOME SERVICE
 * Manages $33,000/year payments to all citizens
 * Part of the OWLBAN GROUP Heaven on Earth Initiative
 */

import Citizen from '../models/Citizen.js';
import { payrollSystem } from '../payrollSystem.js';
import BlockchainService from '../blockchain/blockchainService.js';
import { createLogger } from '../config/logger.js';

const logger = createLogger('UBI-Service');

class UniversalBasicIncomeService {
  constructor() {
    this.blockchainService = new BlockchainService();
    this.ANNUAL_UBI_AMOUNT = 33000; // $33,000 per year
    this.MONTHLY_UBI_AMOUNT = 2750; // $2,750 per month
    this.paymentSchedule = 'monthly'; // Can be: monthly, bi-weekly, weekly
    this.totalCitizens = 0;
    this.totalPaymentsProcessed = 0;
    this.totalAmountDisbursed = 0;

    logger.info('Universal Basic Income Service initialized');
  }

  /**
   * Register a new citizen for UBI
   * @param {Object} citizenData - Citizen registration data
   * @param {string} userId - User ID of registrar
   * @returns {Promise<Object>} Registration result
   */
  async registerCitizen(citizenData, userId) {
    try {
      logger.info(
        `Registering new citizen: ${citizenData.personalInfo?.firstName} ${citizenData.personalInfo?.lastName}`
      );

      // Validate required fields
      const validation = this.validateCitizenData(citizenData);
      if (!validation.valid) {
        return {
          success: false,
          error: 'Validation failed',
          errors: validation.errors,
        };
      }

      // Check for duplicate national ID
      const existingCitizen = await Citizen.findOne({
        'personalInfo.nationalId': citizenData.personalInfo.nationalId,
      });

      if (existingCitizen) {
        return {
          success: false,
          error: 'Citizen with this National ID already exists',
          citizenId: existingCitizen.citizenId,
        };
      }

      // Create new citizen
      const citizen = new Citizen({
        ...citizenData,
        ubiStatus: {
          eligible: true,
          enrollmentDate: new Date(),
          monthlyAmount: this.MONTHLY_UBI_AMOUNT,
          annualAmount: this.ANNUAL_UBI_AMOUNT,
          totalReceived: 0,
          paymentsCount: 0,
          suspended: false,
          paymentMethod:
            citizenData.ubiStatus?.paymentMethod || 'direct_deposit',
        },
        metadata: {
          ...citizenData.metadata,
          registeredBy: userId,
        },
        auditLog: [
          {
            action: 'CITIZEN_REGISTERED',
            performedBy: userId,
            timestamp: new Date(),
            details: { source: 'UBI Registration' },
          },
        ],
      });

      await citizen.save();

      // Create blockchain wallet for citizen
      if (this.blockchainService) {
        try {
          const wallet = await this.blockchainService.createWallet(
            citizen.citizenId
          );
          citizen.blockchain.walletAddress = wallet.address;
          citizen.blockchain.publicKey = wallet.publicKey;
          await citizen.save();
        } catch (blockchainError) {
          logger.warn(
            `Blockchain wallet creation failed for ${citizen.citizenId}:`,
            blockchainError.message
          );
        }
      }

      this.totalCitizens++;

      logger.info(`Citizen registered successfully: ${citizen.citizenId}`);

      return {
        success: true,
        citizen: {
          citizenId: citizen.citizenId,
          fullName: citizen.fullName,
          nationalId: citizen.personalInfo.nationalId,
          ubiStatus: citizen.ubiStatus,
          educationStatus: citizen.educationStatus,
        },
        message: 'Citizen registered successfully for Universal Basic Income',
      };
    } catch (error) {
      logger.error('Error registering citizen:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Process monthly UBI payments for all eligible citizens
   * @param {string} userId - User ID initiating payment
   * @returns {Promise<Object>} Payment processing result
   */
  async processMonthlyPayments(userId) {
    try {
      logger.info('Starting monthly UBI payment processing...');

      const startTime = Date.now();
      const paymentDate = new Date();
      const paymentMonth = paymentDate.toISOString().slice(0, 7); // YYYY-MM

      // Get all eligible citizens
      const eligibleCitizens = await Citizen.find({
        status: 'active',
        'ubiStatus.eligible': true,
        'ubiStatus.suspended': false,
        'verification.identityVerified': true,
        'verification.bankingVerified': true,
      });

      logger.info(
        `Found ${eligibleCitizens.length} eligible citizens for payment`
      );

      const results = {
        totalProcessed: 0,
        successful: 0,
        failed: 0,
        totalAmount: 0,
        payments: [],
        errors: [],
      };

      // Process payments in batches
      const batchSize = 100;
      for (let i = 0; i < eligibleCitizens.length; i += batchSize) {
        const batch = eligibleCitizens.slice(i, i + batchSize);
        const batchResults = await Promise.allSettled(
          batch.map((citizen) =>
            this.processSinglePayment(citizen, paymentDate, userId)
          )
        );

        batchResults.forEach((result, index) => {
          results.totalProcessed++;

          if (result.status === 'fulfilled' && result.value.success) {
            results.successful++;
            results.totalAmount += result.value.amount;
            results.payments.push(result.value);
          } else {
            results.failed++;
            results.errors.push({
              citizenId: batch[index].citizenId,
              error: result.reason || result.value?.error,
            });
          }
        });

        logger.info(
          `Processed batch ${Math.floor(i / batchSize) + 1}: ${results.successful} successful, ${results.failed} failed`
        );
      }

      const duration = Date.now() - startTime;

      // Update service statistics
      this.totalPaymentsProcessed += results.successful;
      this.totalAmountDisbursed += results.totalAmount;

      logger.info(
        `Monthly UBI payment processing completed: ${results.successful}/${results.totalProcessed} successful in ${duration}ms`
      );

      return {
        success: true,
        summary: {
          paymentMonth,
          totalProcessed: results.totalProcessed,
          successful: results.successful,
          failed: results.failed,
          totalAmount: results.totalAmount,
          duration: `${duration}ms`,
          averagePerPayment:
            results.successful > 0
              ? `${(duration / results.successful).toFixed(2)}ms`
              : 'N/A',
        },
        payments: results.payments,
        errors: results.errors,
      };
    } catch (error) {
      logger.error('Error processing monthly payments:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Process single UBI payment for a citizen
   * @param {Object} citizen - Citizen document
   * @param {Date} paymentDate - Payment date
   * @param {string} userId - User ID initiating payment
   * @returns {Promise<Object>} Payment result
   */
  async processSinglePayment(citizen, paymentDate, userId) {
    try {
      // Check eligibility
      const eligibility = citizen.checkUBIEligibility();
      if (!eligibility.eligible) {
        throw new Error(eligibility.reason);
      }

      // Check if already paid this month
      const paymentMonth = paymentDate.toISOString().slice(0, 7);
      const lastPaymentMonth = citizen.ubiStatus.lastPaymentDate
        ? new Date(citizen.ubiStatus.lastPaymentDate).toISOString().slice(0, 7)
        : null;

      if (lastPaymentMonth === paymentMonth) {
        throw new Error('Payment already processed for this month');
      }

      const amount = citizen.ubiStatus.monthlyAmount;

      // Process payment through existing payroll system
      let paymentResult;
      try {
        paymentResult = await this.processPaymentThroughPayroll(
          citizen,
          amount,
          paymentDate
        );
      } catch (paymentError) {
        throw new Error(`Payment processing failed: ${paymentError.message}`);
      }

      // Record on blockchain
      let blockchainTxHash;
      if (this.blockchainService && citizen.blockchain.walletAddress) {
        try {
          const blockchainTx = await this.blockchainService.recordTransaction({
            from: 'UBI_TREASURY',
            to: citizen.blockchain.walletAddress,
            amount: amount,
            type: 'UBI_PAYMENT',
            metadata: {
              citizenId: citizen.citizenId,
              paymentDate: paymentDate.toISOString(),
              paymentMonth: paymentMonth,
            },
          });
          blockchainTxHash = blockchainTx.hash;
          citizen.blockchain.transactionHashes.push(blockchainTxHash);
        } catch (blockchainError) {
          logger.warn(
            `Blockchain recording failed for ${citizen.citizenId}:`,
            blockchainError.message
          );
        }
      }

      // Update citizen UBI status
      citizen.ubiStatus.lastPaymentDate = paymentDate;
      citizen.ubiStatus.nextPaymentDate = citizen.calculateNextPaymentDate();
      citizen.ubiStatus.totalReceived += amount;
      citizen.ubiStatus.paymentsCount += 1;

      // Add audit log entry
      citizen.auditLog.push({
        action: 'UBI_PAYMENT_PROCESSED',
        performedBy: userId,
        timestamp: paymentDate,
        details: {
          amount: amount,
          paymentMonth: paymentMonth,
          transactionHash: blockchainTxHash,
          paymentMethod: citizen.ubiStatus.paymentMethod,
        },
      });

      await citizen.save();

      return {
        success: true,
        citizenId: citizen.citizenId,
        fullName: citizen.fullName,
        amount: amount,
        paymentDate: paymentDate,
        paymentMonth: paymentMonth,
        transactionHash: blockchainTxHash,
        totalReceived: citizen.ubiStatus.totalReceived,
        paymentsCount: citizen.ubiStatus.paymentsCount,
      };
    } catch (error) {
      logger.error(
        `Error processing payment for citizen ${citizen.citizenId}:`,
        error
      );
      throw error;
    }
  }

  /**
   * Process payment through existing payroll system
   * @param {Object} citizen - Citizen document
   * @param {number} amount - Payment amount
   * @param {Date} paymentDate - Payment date
   * @returns {Promise<Object>} Payment result
   */
  async processPaymentThroughPayroll(citizen, amount, paymentDate) {
    // Integration with existing payroll system
    // This would connect to JPMorgan, QuickBooks, etc.

    const paymentData = {
      recipientId: citizen.citizenId,
      recipientName: citizen.fullName,
      amount: amount,
      currency: 'USD',
      paymentMethod: citizen.ubiStatus.paymentMethod,
      accountNumber: citizen.bankingInfo.accountNumber,
      routingNumber: citizen.bankingInfo.routingNumber,
      bankName: citizen.bankingInfo.bankName,
      paymentDate: paymentDate,
      description: `Universal Basic Income - ${paymentDate.toISOString().slice(0, 7)}`,
      category: 'UBI_PAYMENT',
    };

    // Simulate payment processing (replace with actual integration)
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          success: true,
          transactionId: `UBI-${Date.now()}-${citizen.citizenId}`,
          amount: amount,
          status: 'completed',
        });
      }, 100);
    });
  }

  /**
   * Get citizen UBI status
   * @param {string} citizenId - Citizen ID
   * @returns {Promise<Object>} UBI status
   */
  async getCitizenUBIStatus(citizenId) {
    try {
      const citizen = await Citizen.findOne({ citizenId });

      if (!citizen) {
        return {
          success: false,
          error: 'Citizen not found',
        };
      }

      const eligibility = citizen.checkUBIEligibility();

      return {
        success: true,
        citizen: {
          citizenId: citizen.citizenId,
          fullName: citizen.fullName,
          age: citizen.age,
        },
        ubiStatus: citizen.ubiStatus,
        eligibility: eligibility,
        educationStatus: {
          overallProgress: citizen.educationStatus.overallProgress,
          complianceStatus: citizen.educationStatus.complianceStatus,
          military: citizen.educationStatus.military.completed,
          law: citizen.educationStatus.law.completed,
          tech: citizen.educationStatus.tech.completed,
          agriculture: citizen.educationStatus.agriculture.completed,
        },
        verification: citizen.verification,
      };
    } catch (error) {
      logger.error('Error getting citizen UBI status:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Suspend UBI payments for a citizen
   * @param {string} citizenId - Citizen ID
   * @param {string} reason - Suspension reason
   * @param {string} userId - User ID performing suspension
   * @returns {Promise<Object>} Suspension result
   */
  async suspendUBI(citizenId, reason, userId) {
    try {
      const citizen = await Citizen.findOne({ citizenId });

      if (!citizen) {
        return {
          success: false,
          error: 'Citizen not found',
        };
      }

      citizen.ubiStatus.suspended = true;
      citizen.ubiStatus.suspensionReason = reason;
      citizen.ubiStatus.suspensionDate = new Date();

      // Set grace period (30 days)
      const gracePeriodEnd = new Date();
      gracePeriodEnd.setDate(gracePeriodEnd.getDate() + 30);
      citizen.ubiStatus.gracePeriodEnd = gracePeriodEnd;

      citizen.auditLog.push({
        action: 'UBI_SUSPENDED',
        performedBy: userId,
        timestamp: new Date(),
        details: { reason: reason },
      });

      await citizen.save();

      logger.info(`UBI suspended for citizen ${citizenId}: ${reason}`);

      return {
        success: true,
        message: 'UBI payments suspended',
        citizenId: citizenId,
        suspensionReason: reason,
        gracePeriodEnd: gracePeriodEnd,
      };
    } catch (error) {
      logger.error('Error suspending UBI:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Reinstate UBI payments for a citizen
   * @param {string} citizenId - Citizen ID
   * @param {string} userId - User ID performing reinstatement
   * @returns {Promise<Object>} Reinstatement result
   */
  async reinstateUBI(citizenId, userId) {
    try {
      const citizen = await Citizen.findOne({ citizenId });

      if (!citizen) {
        return {
          success: false,
          error: 'Citizen not found',
        };
      }

      // Check if eligible for reinstatement
      const eligibility = citizen.checkUBIEligibility();
      if (
        !eligibility.eligible &&
        eligibility.reason !== citizen.ubiStatus.suspensionReason
      ) {
        return {
          success: false,
          error: `Cannot reinstate: ${eligibility.reason}`,
        };
      }

      citizen.ubiStatus.suspended = false;
      citizen.ubiStatus.suspensionReason = null;
      citizen.ubiStatus.suspensionDate = null;
      citizen.ubiStatus.gracePeriodEnd = null;

      citizen.auditLog.push({
        action: 'UBI_REINSTATED',
        performedBy: userId,
        timestamp: new Date(),
        details: { previousSuspension: citizen.ubiStatus.suspensionReason },
      });

      await citizen.save();

      logger.info(`UBI reinstated for citizen ${citizenId}`);

      return {
        success: true,
        message: 'UBI payments reinstated',
        citizenId: citizenId,
      };
    } catch (error) {
      logger.error('Error reinstating UBI:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get UBI system statistics
   * @returns {Promise<Object>} System statistics
   */
  async getSystemStatistics() {
    try {
      const totalCitizens = await Citizen.countDocuments({ status: 'active' });
      const eligibleCitizens = await Citizen.countDocuments({
        status: 'active',
        'ubiStatus.eligible': true,
        'ubiStatus.suspended': false,
      });
      const suspendedCitizens = await Citizen.countDocuments({
        'ubiStatus.suspended': true,
      });

      const totalDisbursed = await Citizen.aggregate([
        { $match: { status: 'active' } },
        { $group: { _id: null, total: { $sum: '$ubiStatus.totalReceived' } } },
      ]);

      const monthlyBudget = eligibleCitizens * this.MONTHLY_UBI_AMOUNT;
      const annualBudget = eligibleCitizens * this.ANNUAL_UBI_AMOUNT;

      return {
        success: true,
        statistics: {
          citizens: {
            total: totalCitizens,
            eligible: eligibleCitizens,
            suspended: suspendedCitizens,
            eligibilityRate:
              ((eligibleCitizens / totalCitizens) * 100).toFixed(2) + '%',
          },
          payments: {
            totalProcessed: this.totalPaymentsProcessed,
            totalDisbursed: totalDisbursed[0]?.total || 0,
            monthlyBudget: monthlyBudget,
            annualBudget: annualBudget,
          },
          amounts: {
            perCitizen: {
              monthly: this.MONTHLY_UBI_AMOUNT,
              annual: this.ANNUAL_UBI_AMOUNT,
            },
            total: {
              monthly: monthlyBudget,
              annual: annualBudget,
            },
          },
          timestamp: new Date().toISOString(),
        },
      };
    } catch (error) {
      logger.error('Error getting system statistics:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Validate citizen registration data
   * @param {Object} citizenData - Citizen data to validate
   * @returns {Object} Validation result
   */
  validateCitizenData(citizenData) {
    const errors = [];

    // Personal Info validation
    if (!citizenData.personalInfo?.firstName) {
      errors.push('First name is required');
    }
    if (!citizenData.personalInfo?.lastName) {
      errors.push('Last name is required');
    }
    if (!citizenData.personalInfo?.dateOfBirth) {
      errors.push('Date of birth is required');
    }
    if (!citizenData.personalInfo?.nationalId) {
      errors.push('National ID is required');
    }
    if (!citizenData.personalInfo?.biometricHash) {
      errors.push('Biometric data is required');
    }

    // Contact Info validation
    if (!citizenData.contactInfo?.phone) {
      errors.push('Phone number is required');
    }
    if (!citizenData.contactInfo?.email) {
      errors.push('Email is required');
    }

    // Banking Info validation
    if (!citizenData.bankingInfo?.accountNumber) {
      errors.push('Bank account number is required');
    }
    if (!citizenData.bankingInfo?.routingNumber) {
      errors.push('Bank routing number is required');
    }
    if (!citizenData.bankingInfo?.bankName) {
      errors.push('Bank name is required');
    }

    return {
      valid: errors.length === 0,
      errors: errors,
    };
  }

  /**
   * Get service health status
   * @returns {Object} Health status
   */
  getHealthStatus() {
    return {
      status: 'operational',
      service: 'Universal Basic Income',
      totalCitizens: this.totalCitizens,
      totalPaymentsProcessed: this.totalPaymentsProcessed,
      totalAmountDisbursed: this.totalAmountDisbursed,
      paymentSchedule: this.paymentSchedule,
      amounts: {
        monthly: this.MONTHLY_UBI_AMOUNT,
        annual: this.ANNUAL_UBI_AMOUNT,
      },
      lastCheck: new Date().toISOString(),
    };
  }
}

export default UniversalBasicIncomeService;
