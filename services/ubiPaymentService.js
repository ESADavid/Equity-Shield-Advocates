/**
 * UBI Payment Service
 * Handles Universal Basic Income payment processing
 */

import { info, error } from '../utils/loggerWrapper.js';
import UBIPayment from '../models/UBIPayment.js';
import Citizen from '../models/Citizen.js';

class UBIPaymentService {
  constructor() {
    this.baseAmount = 2000; // Base UBI amount per month
    this.dependentBonus = 500; // Additional per dependent
  }

  /**
   * Calculate UBI amount for a citizen
   */
  async calculateUBIAmount(citizenId) {
    try {
      const citizen = await Citizen.findById(citizenId);
      if (!citizen) {
        throw new Error('Citizen not found');
      }
      
      let amount = this.baseAmount;
      
      // Add dependent bonuses
      if (citizen.dependents && citizen.dependents > 0) {
        amount += citizen.dependents * this.dependentBonus;
      }
      
      // Apply any adjustments based on citizen status
      if (citizen.status === 'veteran') {
        amount += 500; // Veteran bonus
      }
      
      info(`UBI calculated for citizen ${citizenId}: $${amount}`);
      return amount;
    } catch (err) {
      error('UBI calculation failed:', err);
      throw err;
    }
  }

  /**
   * Process UBI payment for a citizen
   */
  async processPayment(citizenId) {
    try {
      const amount = await this.calculateUBIAmount(citizenId);
      
      const payment = new UBIPayment({
        citizenId,
        amount,
        status: 'processing',
        transactionId: `UBI-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        paymentMethod: 'jpmorgan'
      });
      
      await payment.save();
      info(`UBI payment initiated: ${payment._id}`);
      
      // Simulate async payment processing
      this.completePayment(payment._id);
      
      return payment;
    } catch (err) {
      error('Payment processing failed:', err);
      throw err;
    }
  }

  /**
   * Complete payment processing (async)
   */
  async completePayment(paymentId) {
    try {
      setTimeout(async () => {
        const payment = await UBIPayment.findById(paymentId);
        if (payment) {
          payment.status = 'completed';
          await payment.save();
          info(`Payment completed: ${paymentId}`);
        }
      }, 2000);
    } catch (err) {
      error('Payment completion failed:', err);
    }
  }

  /**
   * Get payment history for a citizen
   */
  async getPaymentHistory(citizenId, limit = 10) {
    try {
      const history = await UBIPayment.find({ citizenId })
        .sort({ paymentDate: -1 })
        .limit(limit);
      
      info(`Retrieved ${history.length} payments for citizen ${citizenId}`);
      return history;
    } catch (err) {
      error('Failed to get payment history:', err);
      throw err;
    }
  }

  /**
   * Get payment status
   */
  async getPaymentStatus(paymentId) {
    try {
      const payment = await UBIPayment.findById(paymentId);
      if (!payment) {
        throw new Error('Payment not found');
      }
      return payment;
    } catch (err) {
      error('Failed to get payment status:', err);
      throw err;
    }
  }

  /**
   * Get all pending payments
   */
  async getPendingPayments() {
    try {
      return await UBIPayment.find({ status: 'pending' });
    } catch (err) {
      error('Failed to get pending payments:', err);
      throw err;
    }
  }

  /**
   * Retry failed payment
   */
  async retryPayment(paymentId) {
    try {
      const payment = await UBIPayment.findById(paymentId);
      if (!payment) {
        throw new Error('Payment not found');
      }
      
      if (payment.status !== 'failed') {
        throw new Error('Only failed payments can be retried');
      }
      
      payment.status = 'processing';
      await payment.save();
      
      this.completePayment(paymentId);
      
      info(`Payment retry initiated: ${paymentId}`);
      return payment;
    } catch (err) {
      error('Payment retry failed:', err);
      throw err;
    }
  }
}

export default new UBIPaymentService();
