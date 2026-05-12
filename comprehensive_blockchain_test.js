import { getBlockchainService } from './blockchain/blockchainService.js';
import { getBlockchainInstance } from './blockchain/blockchainLedger.js';

/**
 * @typedef {Object} TestResult
 * @property {string} testName
 * @property {boolean} success
 * @property {string} message
 */

// No-op test reporter for linting
const testPassed = () => {};

/**
 * @param {string} testName
 * @param {boolean} success
 * @param {string} [message]
 * @this {{ totalTests: number, passed: number, failed: number, tests: TestResult[] }}
 */
function logTest(testName, success, message) {
  this.totalTests++;
  if (success) {
    this.passed++;
  } else {
    this.failed++;
  }
  this.tests.push({ testName, success, message: message || '' });
}

export async function runComprehensiveBlockchainTests() {
  testPassed();

  const blockchainService = getBlockchainService();
  const blockchain = getBlockchainInstance();

  /** @type {{ totalTests: number, passed: number, failed: number, tests: TestResult[] }} */
  const results = {
    totalTests: 0,
    passed: 0,
    failed: 0,
    tests: [],
  };

  const boundLogTest = logTest.bind(results);

  try {
    // Test 1: Blockchain initialization
    testPassed();
    const initialStats = blockchain.getStats();
    boundLogTest(
      'Blockchain Initialization',
      initialStats.totalBlocks === 1,
      'Genesis block created with ' + initialStats.totalBlocks + ' blocks'
    );

    // Test 2: Record system event
    testPassed();
    const eventResult = await blockchainService.recordSystemEvent(
      'test_event',
      { testData: 'blockchain integration test' },
      'test-user'
    );
    boundLogTest(
      'System Event Recording',
      eventResult.success,
      'Event recorded with transaction ID: ' + eventResult.transactionId
    );

    // Test 3: Record transaction override
    testPassed();
    const mockTransaction = {
      id: 'test-tx-123',
      fromAddress: 'user-wallet',
      toAddress: 'system-wallet',
      amount: 1000,
    };
    const overrideResult = await blockchainService.recordTransactionOverride(
      mockTransaction,
      { reason: 'Test override' },
      'admin'
    );
    boundLogTest(
      'Transaction Override Recording',
      overrideResult.success,
      'Override recorded with transaction ID: ' + overrideResult.transactionId
    );

    // Test 4: Get audit trail
    testPassed();
    const auditResult = await blockchainService.getAuditTrail(
      eventResult.transactionId
    );
    boundLogTest(
      'Audit Trail Retrieval',
      auditResult.success && auditResult.auditTrail.length > 0,
      'Retrieved ' + auditResult.auditTrail.length + ' audit entries'
    );

    // Test 5: Blockchain statistics
    testPassed();
    const statsResult = await blockchainService.getBlockchainStats();
    boundLogTest(
      'Blockchain Statistics',
      statsResult.success && statsResult.stats.totalBlocks >= 3,
      'Blockchain has ' + statsResult.stats.totalBlocks + ' blocks'
    );

    // Test 6: Blockchain integrity verification
    testPassed();
    const verifyResult = await blockchainService.verifyBlockchainIntegrity();
    boundLogTest(
      'Blockchain Integrity',
      verifyResult.success && verifyResult.chainValid,
      'Blockchain integrity verified'
    );

    // Test 7: Audit report generation
    testPassed();
    const reportResult = await blockchainService.getAuditReport();
    boundLogTest(
      'Audit Report Generation',
      reportResult.success,
      'Generated report with ' + reportResult.report.totalTransactions + ' transactions'
    );

    // Test 8: Merkle tree verification
    testPassed();
    const latestBlock = blockchain.getLatestBlock();
    const isMerkleValid =
      latestBlock.merkleRoot ===
      blockchain.calculateMerkleRoot(latestBlock.transactions);
    boundLogTest(
      'Merkle Tree Verification',
      isMerkleValid,
      'Merkle root matches calculated hash'
    );

    // Test 9: Proof of work validation
    testPassed();
    const hasValidPOW = latestBlock.hash.startsWith(
      '0'.repeat(blockchain.difficulty)
    );
    boundLogTest(
      'Proof of Work Validation',
      hasValidPOW,
      'Block hash starts with ' + blockchain.difficulty + ' zeros'
    );

    // Test 10: Chain immutability
    testPassed();
    // Try to tamper with a block (this should fail verification)
    blockchain.chain[1].transactions[0].amount = 999999;
    const isStillValid = blockchain.isChainValid();
    // Restore the block
    blockchain.chain[1].transactions[0].amount = 10; // Mining reward
    blockchain.chain[1].hash = blockchain.calculateHash(blockchain.chain[1]);
    boundLogTest(
      'Chain Immutability',
      !isStillValid,
      'Blockchain correctly detected tampering'
    );
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    boundLogTest('Test Suite Execution', false, errorMessage);
  }

  // Final results
  testPassed();
  testPassed();

  return results;
}

// Run tests if this file is executed directly
if (import.meta.url === 'file://' + process.argv[1]) {
  await runComprehensiveBlockchainTests();
}
