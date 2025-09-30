import { getBlockchainInstance, Transaction } from './blockchainLedger.js';
import winston from 'winston';

// Blockchain service for audit trail management
export class BlockchainService {
  constructor() {
    this.blockchain = getBlockchainInstance();
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.File({ filename: 'blockchain-audit.log' }),
        new winston.transports.Console()
      ]
    });
  }

  // Record a transaction in the blockchain
  async recordTransaction(fromAddress, toAddress, amount, transactionData) {
    try {
      const transaction = new Transaction(fromAddress, toAddress, amount, transactionData);

      // Sign transaction (simplified for demo)
      transaction.signTransaction(fromAddress);

      // Add to pending transactions
      this.blockchain.addTransaction(transaction);

      // Mine a new block (in production, this would be done periodically)
      this.blockchain.minePendingTransactions('system-reward-address');

      this.logger.info('Transaction recorded in blockchain', {
        transactionId: transaction.id,
        blockIndex: this.blockchain.getLatestBlock().index,
        hash: this.blockchain.getLatestBlock().hash
      });

      return {
        success: true,
        transactionId: transaction.id,
        blockHash: this.blockchain.getLatestBlock().hash,
        blockIndex: this.blockchain.getLatestBlock().index
      };
    } catch (error) {
      this.logger.error('Failed to record transaction in blockchain', { error: error.message });
      throw error;
    }
  }

  // Get audit trail for a transaction
  async getAuditTrail(transactionId) {
    try {
      const auditTrail = this.blockchain.getAuditTrail(transactionId);

      if (auditTrail.length === 0) {
        return { success: false, message: 'Transaction not found in blockchain' };
      }

      return {
        success: true,
        transactionId,
        auditTrail,
        verificationStatus: this.verifyAuditTrail(auditTrail)
      };
    } catch (error) {
      this.logger.error('Failed to retrieve audit trail', { transactionId, error: error.message });
      throw error;
    }
  }

  // Verify the integrity of an audit trail
  verifyAuditTrail(auditTrail) {
    const verificationResults = auditTrail.map(entry => ({
      blockIndex: entry.blockIndex,
      verified: entry.verified,
      blockHash: entry.blockHash,
      timestamp: entry.timestamp
    }));

    const allVerified = verificationResults.every(result => result.verified);

    return {
      overallVerified: allVerified && this.blockchain.isChainValid(),
      blockVerifications: verificationResults,
      chainIntegrity: this.blockchain.isChainValid()
    };
  }

  // Get blockchain statistics
  async getBlockchainStats() {
    try {
      const stats = this.blockchain.getStats();

      return {
        success: true,
        stats: {
          ...stats,
          lastBlockHash: this.blockchain.getLatestBlock().hash,
          lastBlockTimestamp: this.blockchain.getLatestBlock().timestamp,
          totalBlocks: stats.totalBlocks,
          totalTransactions: stats.totalTransactions,
          pendingTransactions: stats.pendingTransactions,
          difficulty: stats.difficulty,
          chainValid: stats.isValid
        }
      };
    } catch (error) {
      this.logger.error('Failed to get blockchain stats', { error: error.message });
      throw error;
    }
  }

  // Verify blockchain integrity
  async verifyBlockchainIntegrity() {
    try {
      const isValid = this.blockchain.isChainValid();

      this.logger.info('Blockchain integrity verification', { isValid });

      return {
        success: true,
        chainValid: isValid,
        totalBlocks: this.blockchain.chain.length,
        lastVerification: Date.now()
      };
    } catch (error) {
      this.logger.error('Blockchain integrity verification failed', { error: error.message });
      throw error;
    }
  }

  // Create audit trail entry for system events
  async recordSystemEvent(eventType, eventData, userId = 'system') {
    try {
      const transactionData = {
        type: 'system_event',
        eventType,
        eventData,
        userId,
        timestamp: Date.now()
      };

      return await this.recordTransaction('system', userId, 0, transactionData);
    } catch (error) {
      this.logger.error('Failed to record system event', { eventType, error: error.message });
      throw error;
    }
  }

  // Create audit trail entry for transaction overrides
  async recordTransactionOverride(originalTransaction, overrideData, userId) {
    try {
      const transactionData = {
        type: 'transaction_override',
        originalTransaction,
        overrideData,
        userId,
        timestamp: Date.now(),
        reason: overrideData.reason || 'Administrative override'
      };

      return await this.recordTransaction(originalTransaction.fromAddress, 'override-system', 0, transactionData);
    } catch (error) {
      this.logger.error('Failed to record transaction override', {
        transactionId: originalTransaction.id,
        userId,
        error: error.message
      });
      throw error;
    }
  }

  // Get comprehensive audit report
  async getAuditReport(timeRange = { start: 0, end: Date.now() }) {
    try {
      const report = {
        totalBlocks: this.blockchain.chain.length,
        totalTransactions: 0,
        systemEvents: [],
        transactionOverrides: [],
        userActivities: [],
        timeRange
      };

      // Analyze all blocks in the chain
      for (const block of this.blockchain.chain) {
        if (block.timestamp >= timeRange.start && block.timestamp <= timeRange.end) {
          report.totalTransactions += block.transactions.length;

          for (const transaction of block.transactions) {
            if (transaction.data.type === 'system_event') {
              report.systemEvents.push({
                blockIndex: block.index,
                timestamp: transaction.timestamp,
                eventType: transaction.data.eventType,
                userId: transaction.data.userId,
                eventData: transaction.data.eventData
              });
            } else if (transaction.data.type === 'transaction_override') {
              report.transactionOverrides.push({
                blockIndex: block.index,
                timestamp: transaction.timestamp,
                userId: transaction.data.userId,
                reason: transaction.data.reason,
                originalTransaction: transaction.data.originalTransaction
              });
            } else if (transaction.fromAddress && transaction.toAddress) {
              report.userActivities.push({
                blockIndex: block.index,
                timestamp: transaction.timestamp,
                fromAddress: transaction.fromAddress,
                toAddress: transaction.toAddress,
                amount: transaction.amount,
                transactionData: transaction.data
              });
            }
          }
        }
      }

      return {
        success: true,
        report,
        generatedAt: Date.now()
      };
    } catch (error) {
      this.logger.error('Failed to generate audit report', { error: error.message });
      throw error;
    }
  }
}

// Singleton instance
let blockchainServiceInstance = null;

export function getBlockchainService() {
  if (!blockchainServiceInstance) {
    blockchainServiceInstance = new BlockchainService();
  }
  return blockchainServiceInstance;
}

export default BlockchainService;
