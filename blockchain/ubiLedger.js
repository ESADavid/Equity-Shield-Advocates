/**
 * UBI BLOCKCHAIN LEDGER
 * Blockchain integration for UBI payment tracking and verification
 * Part of the OWLBAN GROUP Heaven on Earth Initiative
 */

import { info, error, warn, debug } from 'utils/loggerWrapper.js';
import blockchainService from './blockchainService.js';
import UBIPayment from '../models/UBIPayment.js';

class UBILedger {
  constructor() {
    this.LEDGER_TYPE = 'UBI_LEDGER';
    this.BATCH_SIZE = 100; // Process payments in batches
  }

  /**
   * Record a single UBI payment on the blockchain
   * @param {Object} payment - UBI payment document
   * @returns {Promise<string>} Blockchain hash
   */
  async recordPayment(payment) {
    try {
      const record = {
        type: 'UBI_PAYMENT',
        ledgerType: this.LEDGER_TYPE,
        citizenId: payment.citizenId.toString(),
        amount: payment.amount,
        paymentDate: payment.paymentDate,
        paymentId: payment._id.toString(),
        transactionId: payment.transactionId,
        paymentMethod: payment.paymentMethod,
        timestamp: new Date(),
        metadata: {
          citizenName: payment.metadata?.citizenName,
          processedBy: payment.metadata?.processedBy,
        },
      };

      const hash = await blockchainService.addBlock(record);

      // Update payment with blockchain hash
      await UBIPayment.findByIdAndUpdate(payment._id, {
        blockchainHash: hash,
        'metadata.blockchainRecorded': new Date(),
      });

      info(
        `UBI payment recorded on blockchain: ${hash} for payment ${payment._id}`
      );
      return hash;
    } catch (err) {
      error('Failed to record UBI payment on blockchain:', err);
      throw err;
    }
  }

  /**
   * Record multiple UBI payments in batch
   * @param {Array} payments - Array of UBI payment documents
   * @returns {Promise<Array>} Array of blockchain hashes
   */
  async recordPaymentsBatch(payments) {
    try {
      if (!payments || payments.length === 0) {
        return [];
      }

      info(`Recording ${payments.length} UBI payments on blockchain in batch`);

      const records = payments.map((payment) => ({
        type: 'UBI_PAYMENT_BATCH',
        ledgerType: this.LEDGER_TYPE,
        payments: payments.map((p) => ({
          citizenId: p.citizenId.toString(),
          amount: p.amount,
          paymentId: p._id.toString(),
          transactionId: p.transactionId,
        })),
        batchSize: payments.length,
        totalAmount: payments.reduce((sum, p) => sum + p.amount, 0),
        timestamp: new Date(),
      }));

      const hashes = [];
      for (const record of records) {
        const hash = await blockchainService.addBlock(record);
        hashes.push(hash);
      }

      // Update payments with blockchain hashes
      const updatePromises = payments.map((payment, index) =>
        UBIPayment.findByIdAndUpdate(payment._id, {
          blockchainHash: hashes[index],
          'metadata.blockchainRecorded': new Date(),
        })
      );

      await Promise.all(updatePromises);

      info(
        `UBI payment batch recorded on blockchain: ${hashes.length} blocks created`
      );
      return hashes;
    } catch (err) {
      error('Failed to record UBI payment batch on blockchain:', err);
      throw err;
    }
  }

  /**
   * Verify a UBI payment on the blockchain
   * @param {string} paymentId - Payment ID to verify
   * @returns {Promise<Object>} Verification result
   */
  async verifyPayment(paymentId) {
    try {
      const payment = await UBIPayment.findById(paymentId);
      if (!payment) {
        throw new Error('Payment not found');
      }

      if (!payment.blockchainHash) {
        return {
          verified: false,
          reason: 'Payment not recorded on blockchain',
          paymentId,
        };
      }

      const isValid = await blockchainService.verifyBlock(
        payment.blockchainHash
      );

      return {
        verified: isValid,
        paymentId,
        blockchainHash: payment.blockchainHash,
        citizenId: payment.citizenId,
        amount: payment.amount,
        paymentDate: payment.paymentDate,
        reason: isValid
          ? 'Payment verified on blockchain'
          : 'Payment verification failed',
      };
    } catch (err) {
      error(`Failed to verify UBI payment ${paymentId}:`, err);
      return {
        verified: false,
        paymentId,
        error: err.message,
      };
    }
  }

  /**
   * Get blockchain history for a citizen
   * @param {string} citizenId - Citizen ID
   * @param {number} limit - Maximum records to return
   * @returns {Promise<Array>} Blockchain records
   */
  async getCitizenBlockchainHistory(citizenId, limit = 50) {
    try {
      const payments = await UBIPayment.find({
        citizenId,
        blockchainHash: { $exists: true, $ne: null },
      })
        .sort({ paymentDate: -1 })
        .limit(limit)
        .select('amount paymentDate blockchainHash transactionId status');

      const history = [];

      for (const payment of payments) {
        try {
          const blockData = await blockchainService.getBlock(
            payment.blockchainHash
          );
          if (blockData) {
            history.push({
              paymentId: payment._id,
              amount: payment.amount,
              paymentDate: payment.paymentDate,
              blockchainHash: payment.blockchainHash,
              status: payment.status,
              blockData: {
                timestamp: blockData.timestamp,
                previousHash: blockData.previousHash,
                nonce: blockData.nonce,
              },
            });
          }
        } catch (blockErr) {
          warn(
            `Failed to get block data for payment ${payment._id}:`,
            blockErr.message
          );
        }
      }

      return history;
    } catch (err) {
      error(`Failed to get blockchain history for citizen ${citizenId}:`, err);
      throw err;
    }
  }

  /**
   * Audit UBI payments against blockchain
   * @param {Date} startDate - Start date for audit
   * @param {Date} endDate - End date for audit
   * @returns {Promise<Object>} Audit results
   */
  async auditPayments(startDate, endDate) {
    try {
      info('Starting UBI payment blockchain audit');

      const payments = await UBIPayment.find({
        paymentDate: { $gte: startDate, $lte: endDate },
        status: 'completed',
      });

      const results = {
        totalPayments: payments.length,
        blockchainVerified: 0,
        blockchainMissing: 0,
        blockchainInvalid: 0,
        issues: [],
      };

      for (const payment of payments) {
        if (!payment.blockchainHash) {
          results.blockchainMissing++;
          results.issues.push({
            paymentId: payment._id,
            issue: 'Missing blockchain hash',
            citizenId: payment.citizenId,
            amount: payment.amount,
          });
          continue;
        }

        try {
          const isValid = await blockchainService.verifyBlock(
            payment.blockchainHash
          );
          if (isValid) {
            results.blockchainVerified++;
          } else {
            results.blockchainInvalid++;
            results.issues.push({
              paymentId: payment._id,
              issue: 'Invalid blockchain record',
              citizenId: payment.citizenId,
              blockchainHash: payment.blockchainHash,
            });
          }
        } catch (verifyErr) {
          results.blockchainInvalid++;
          results.issues.push({
            paymentId: payment._id,
            issue: 'Blockchain verification error',
            error: verifyErr.message,
          });
        }
      }

      const auditResult = {
        period: { startDate, endDate },
        summary: results,
        integrityScore:
          results.totalPayments > 0
            ? (
                (results.blockchainVerified / results.totalPayments) *
                100
              ).toFixed(2) + '%'
            : '0%',
      };

      info(
        `UBI payment audit completed: ${results.blockchainVerified}/${results.totalPayments} verified`
      );
      return auditResult;
    } catch (err) {
      error('UBI payment audit failed:', err);
      throw err;
    }
  }

  /**
   * Process pending payments for blockchain recording
   * @returns {Promise<Object>} Processing results
   */
  async processPendingBlockchainRecords() {
    try {
      const pendingPayments = await UBIPayment.find({
        status: 'completed',
        blockchainHash: { $exists: false },
      }).limit(this.BATCH_SIZE);

      if (pendingPayments.length === 0) {
        return { processed: 0, message: 'No pending payments to record' };
      }

      info(
        `Processing ${pendingPayments.length} pending UBI payments for blockchain recording`
      );

      const hashes = await this.recordPaymentsBatch(pendingPayments);

      return {
        processed: pendingPayments.length,
        hashes: hashes,
        message: `Successfully recorded ${pendingPayments.length} payments on blockchain`,
      };
    } catch (err) {
      error('Failed to process pending blockchain records:', err);
      throw err;
    }
  }

  /**
   * Get ledger statistics
   * @returns {Promise<Object>} Ledger statistics
   */
  async getLedgerStats() {
    try {
      const [totalPayments, blockchainRecorded, pendingRecording] =
        await Promise.all([
          UBIPayment.countDocuments(),
          UBIPayment.countDocuments({ blockchainHash: { $exists: true } }),
          UBIPayment.countDocuments({
            status: 'completed',
            blockchainHash: { $exists: false },
          }),
        ]);

      return {
        totalPayments,
        blockchainRecorded,
        pendingRecording,
        recordingCoverage:
          totalPayments > 0
            ? ((blockchainRecorded / totalPayments) * 100).toFixed(2) + '%'
            : '0%',
        lastUpdated: new Date(),
      };
    } catch (err) {
      error('Failed to get ledger statistics:', err);
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
      service: 'UBI Blockchain Ledger',
      ledgerType: this.LEDGER_TYPE,
      batchSize: this.BATCH_SIZE,
      blockchainService: blockchainService.getHealthStatus(),
      lastCheck: new Date().toISOString(),
    };
  }
}

export default new UBILedger();
