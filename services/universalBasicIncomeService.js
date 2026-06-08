/**
 * Universal Basic Income Service - Heaven on Earth Phase 1
 * Handles UBI payments, eligibility, JPMorgan integration
 */

import { info, warn, error } from '../utils/loggerWrapper.js';
import Citizen from '../models/Citizen.js';
import Education from '../models/Education.js';

class UniversalBasicIncomeService {
  /**
   * Calculate UBI eligibility for a citizen
   * @param {string} citizenId - Citizen ID
   * @returns {Promise<{eligible: boolean, amount: number, reason?: string, citizen?: import('mongoose').Types.ObjectId}>}
   */
  static async calculateEligibility(
    /** @type {string} */ citizenId
  ) {
    const citizen = await Citizen.findById(citizenId);
    if (!citizen) throw new Error('Citizen not found');

    // Check education compliance
    const education = await Education.findOne({ citizenId });
    if (education?.complianceStatus === 'non-compliant') {
      return { eligible: false, reason: 'Education non-compliance' };
    }

    // UBI base amount: $2750/month
    const amount = 2750;
    return { eligible: true, amount, citizen: citizen._id };
  }

  /**
   * Process UBI payment for a citizen
   * @param {string} citizenId - Citizen ID
   * @param {string} month - Month identifier
   * @param {number} amount - Payment amount
   * @returns {Promise<{transactionId: string, status: string}>}
   */
  static async processPayment(
    /** @type {string} */ citizenId,
    /** @type {string} */ month,
    /** @type {number} */ amount
  ) {
    info(
      `Processing UBI payment for citizen ${citizenId}, month ${month}, amount $${amount}`
    );

    // Simulate JPMorgan integration
    const transactionId = await this.simulateJpmorganPayment(
      citizenId,
      amount,
      month
    );

    // Fix: ubiSuspended is nested under ubiStatus in Citizen model
    // Update citizen record using nested path
    await Citizen.findByIdAndUpdate(citizenId, {
      $push: {
        ubiPayments: { transactionId, month, amount, status: 'completed' },
      },
    });

    info(`UBI payment completed: ${transactionId}`);
    return { transactionId, status: 'completed' };
  }

  /**
   * Simulate JPMorgan payment API call
   * @param {string} citizenId - Citizen ID
   * @param {number} amount - Payment amount
   * @param {string} month - Month identifier
   * @returns {Promise<string>} Transaction ID
   */
  static async simulateJpmorganPayment(
    /** @type {string} */ citizenId,
    /** @type {number} */ amount,
    /** @type {string} */ month
  ) {
    // Mock JPMorgan API call
    return `UBI_${citizenId}_${month}_${Date.now()}`;
  }

  /**
   * Get payment history for a citizen
   * @param {string} citizenId - Citizen ID
   * @param {number} limit - Number of records to return
   * @returns {Promise<unknown[]>}
   */
  static async getPaymentHistory(
    /** @type {string} */ citizenId,
    /** @type {number} */ limit = 12
  ) {
    const citizen = await Citizen.findById(citizenId).populate('ubiPayments');
    if (!citizen) return [];
    // Access ubiStatus.ubiPayments since that's where payments are stored
    const payments = citizen.ubiStatus?.ubiPayments || [];
    return payments.slice(-limit);
  }

  /**
   * Suspend UBI for a citizen
   * @param {string} citizenId - Citizen ID
   * @param {string} reason - Suspension reason
   * @returns {Promise<void>}
   */
  static async suspendUBI(
    /** @type {string} */ citizenId,
    /** @type {string} */ reason
  ) {
    // Fix: Use ubiStatus.suspended instead of ubiSuspended
    await Citizen.findByIdAndUpdate(citizenId, {
      'ubiStatus.suspended': true,
      'ubiStatus.suspensionReason': reason,
    });
    warn(`UBI suspended for ${citizenId}: ${reason}`);
  }

  /**
   * Reinstate UBI for a citizen
   * @param {string} citizenId - Citizen ID
   * @returns {Promise<void>}
   */
  static async reinstateUBI(
    /** @type {string} */ citizenId
  ) {
    // Fix: Use ubiStatus.suspended instead of ubiSuspended
    await Citizen.findByIdAndUpdate(citizenId, {
      'ubiStatus.suspended': false,
      'ubiStatus.suspensionReason': null,
    });
    info(`UBI reinstated for ${citizenId}`);
  }
}

export default UniversalBasicIncomeService;
