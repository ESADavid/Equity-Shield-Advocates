/**
 * Universal Basic Income Service - Heaven on Earth Phase 1
 * Handles UBI payments, eligibility, JPMorgan integration
 */

import { info, warn, error } from '../utils/logger.js';
const Citizen = require('../models/Citizen');
const Education = require('../models/Education');
const mongoose = require('mongoose');

class UniversalBasicIncomeService {
  static async calculateEligibility(citizenId) {
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

  static async processPayment(citizenId, month, amount) {
    logger.info(`Processing UBI payment for citizen ${citizenId}, month ${month}, amount $${amount}`);

    // Simulate JPMorgan integration
    const transactionId = await this.simulateJpmorganPayment(citizenId, amount, month);

    // Update citizen record
    await Citizen.findByIdAndUpdate(citizenId, {
      $push: { ubiPayments: { transactionId, month, amount, status: 'completed' } }
    });

    logger.info(`UBI payment completed: ${transactionId}`);
    return { transactionId, status: 'completed' };
  }

  static async simulateJpmorganPayment(citizenId, amount, month) {
    // Mock JPMorgan API call
    return `UBI_${citizenId}_${month}_${Date.now()}`;
  }

  static async getPaymentHistory(citizenId, limit = 12) {
    const citizen = await Citizen.findById(citizenId).populate('ubiPayments');
    return citizen.ubiPayments.slice(-limit);
  }

  static async suspendUBI(citizenId, reason) {
    await Citizen.findByIdAndUpdate(citizenId, { ubiSuspended: true, suspensionReason: reason });
    logger.warn(`UBI suspended for ${citizenId}: ${reason}`);
  }

  static async reinstateUBI(citizenId) {
    await Citizen.findByIdAndUpdate(citizenId, { ubiSuspended: false, suspensionReason: null });
    logger.info(`UBI reinstated for ${citizenId}`);
  }
}

module.exports = UniversalBasicIncomeService;

