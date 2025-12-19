/**
 * UBI Blockchain Ledger
 * Records UBI payments on blockchain for transparency and immutability
 */

import { info, error } from '../utils/loggerWrapper.js';
import blockchainService from './blockchainService.js';

class UBILedger {
  /**
   * Record UBI payment on blockchain
   */
  async recordPayment(payment) {
    try {
      const record = {
        type: 'UBI_PAYMENT',
        citizenId: payment.citizenId.toString(),
        amount: payment.amount,
        timestamp: new Date().toISOString(),
        paymentId: payment._id.toString(),
        transactionId: payment.transactionId,
        status: payment.status,
      };

      const hash = await blockchainService.addBlock(record);
      info(`UBI payment recorded on blockchain: ${hash}`);

      // Update payment with blockchain hash
      payment.blockchainHash = hash;
      await payment.save();

      return hash;
    } catch (err) {
      error('Failed to record payment on blockchain:', err);
      throw err;
    }
  }

  /**
   * Verify payment on blockchain
   */
  async verifyPayment(paymentId) {
    try {
      const isValid = await blockchainService.verifyBlock(paymentId);
      info(`Payment verification result for ${paymentId}: ${isValid}`);
      return isValid;
    } catch (err) {
      error('Payment verification failed:', err);
      throw err;
    }
  }

  /**
   * Get all blockchain records for a citizen
   */
  async getPaymentChain(citizenId) {
    try {
      const chain = await blockchainService.getChain();
      const citizenPayments = chain.filter(
        (block) =>
          block.data &&
          block.data.type === 'UBI_PAYMENT' &&
          block.data.citizenId === citizenId.toString()
      );

      info(
        `Retrieved ${citizenPayments.length} blockchain records for citizen ${citizenId}`
      );
      return citizenPayments;
    } catch (err) {
      error('Failed to get payment chain:', err);
      throw err;
    }
  }

  /**
   * Get blockchain audit trail
   */
  async getAuditTrail(startDate, endDate) {
    try {
      const chain = await blockchainService.getChain();
      const ubiPayments = chain.filter((block) => {
        if (!block.data || block.data.type !== 'UBI_PAYMENT') return false;
        const blockDate = new Date(block.data.timestamp);
        return blockDate >= startDate && blockDate <= endDate;
      });

      info(
        `Retrieved ${ubiPayments.length} UBI payments from blockchain audit trail`
      );
      return ubiPayments;
    } catch (err) {
      error('Failed to get audit trail:', err);
      throw err;
    }
  }
}

export default new UBILedger();
