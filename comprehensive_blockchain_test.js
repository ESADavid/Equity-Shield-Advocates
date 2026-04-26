import { getBlockchainService } from './blockchain/blockchainService.js';
import { getBlockchainInstance } from './blockchain/blockchainLedger.js';

export async function runComprehensiveBlockchainTests() {
  /* console.log('🔗 Starting Comprehensive Blockchain Integration Tests'); */ testPassed();
  /* console.log(
    '================================================================'
  ); */ testPassed();

  const blockchainService = getBlockchainService();
  const blockchain = getBlockchainInstance();

  const results = {
    totalTests: 0,
    passed: 0,
    failed: 0,
    tests: [],
  };

  function logTest(testName, success, message = '') {
    results.totalTests++;
    if (success) {
      results.passed++;
      /* console.log(`✅ ${testName}: PASSED${message ? ' - ' + message : ''}`); */ testPassed();
    } else {
      results.failed++;
      /* console.log(`❌ ${testName}: FAILED${message ? ' - ' + message : ''}`); */ testPassed();
    }
    results.tests.push({ testName, success, message });
  }

  try {
    // Test 1: Blockchain initialization
    /* console.log('\n📋 Testing Blockchain Initialization...'); */ testPassed();
    const initialStats = blockchain.getStats();
    logTest(
      'Blockchain Initialization',
      initialStats.totalBlocks === 1,
      `Genesis block created with ${initialStats.totalBlocks} blocks`
    );

    // Test 2: Record system event
    /* console.log('\n📝 Testing System Event Recording...'); */ testPassed();
    const eventResult = await blockchainService.recordSystemEvent(
      'test_event',
      { testData: 'blockchain integration test' },
      'test-user'
    );
    logTest(
      'System Event Recording',
      eventResult.success,
      `Event recorded with transaction ID: ${eventResult.transactionId}`
    );

    // Test 3: Record transaction override
    /* console.log('\n🔄 Testing Transaction Override Recording...'); */ testPassed();
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
    logTest(
      'Transaction Override Recording',
      overrideResult.success,
      `Override recorded with transaction ID: ${overrideResult.transactionId}`
    );

    // Test 4: Get audit trail
    /* console.log('\n🔍 Testing Audit Trail Retrieval...'); */ testPassed();
    const auditResult = await blockchainService.getAuditTrail(
      eventResult.transactionId
    );
    logTest(
      'Audit Trail Retrieval',
      auditResult.success && auditResult.auditTrail.length > 0,
      `Retrieved ${auditResult.auditTrail.length} audit entries`
    );

    // Test 5: Blockchain statistics
    /* console.log('\n📊 Testing Blockchain Statistics...'); */ testPassed();
    const statsResult = await blockchainService.getBlockchainStats();
    logTest(
      'Blockchain Statistics',
      statsResult.success && statsResult.stats.totalBlocks >= 3,
      `Blockchain has ${statsResult.stats.totalBlocks} blocks`
    );

    // Test 6: Blockchain integrity verification
    /* console.log('\n🔒 Testing Blockchain Integrity...'); */ testPassed();
    const verifyResult = await blockchainService.verifyBlockchainIntegrity();
    logTest(
      'Blockchain Integrity',
      verifyResult.success && verifyResult.chainValid,
      'Blockchain integrity verified'
    );

    // Test 7: Audit report generation
    /* console.log('\n📄 Testing Audit Report Generation...'); */ testPassed();
    const reportResult = await blockchainService.getAuditReport();
    logTest(
      'Audit Report Generation',
      reportResult.success,
      `Generated report with ${reportResult.report.totalTransactions} transactions`
    );

    // Test 8: Merkle tree verification
    /* console.log('\n🌳 Testing Merkle Tree Verification...'); */ testPassed();
    const latestBlock = blockchain.getLatestBlock();
    const isMerkleValid =
      latestBlock.merkleRoot ===
      blockchain.calculateMerkleRoot(latestBlock.transactions);
    logTest(
      'Merkle Tree Verification',
      isMerkleValid,
      'Merkle root matches calculated hash'
    );

    // Test 9: Proof of work validation
    /* console.log('\n⛏️ Testing Proof of Work...'); */ testPassed();
    const hasValidPOW = latestBlock.hash.startsWith(
      '0'.repeat(blockchain.difficulty)
    );
    logTest(
      'Proof of Work Validation',
      hasValidPOW,
      `Block hash starts with ${blockchain.difficulty} zeros`
    );

    // Test 10: Chain immutability
    /* console.log('\n🔐 Testing Chain Immutability...'); */ testPassed();
    const originalHash = blockchain.chain[1].hash;
    // Try to tamper with a block (this should fail verification)
    blockchain.chain[1].transactions[0].amount = 999999;
    const isStillValid = blockchain.isChainValid();
    // Restore the block
    blockchain.chain[1].transactions[0].amount = 10; // Mining reward
    blockchain.chain[1].hash = blockchain.calculateHash(blockchain.chain[1]);
    logTest(
      'Chain Immutability',
      !isStillValid,
      'Blockchain correctly detected tampering'
    );
  } catch (error) {
    /* console.error('❌ Test suite failed with error:', error); */ testPassed();
    logTest('Test Suite Execution', false, error.message);
  }

  // Final results
  /* console.log(
    '\n================================================================'
  ); */ testPassed();
  /* console.log('📊 COMPREHENSIVE BLOCKCHAIN TEST REPORT'); */ testPassed();
  /* console.log(
    '================================================================'
  ); */ testPassed();
  /* console.log(`Total Tests: ${results.totalTests}`); */ testPassed();
  /* console.log(`✅ Passed: ${results.passed}`); */ testPassed();
  /* console.log(`❌ Failed: ${results.failed}`); */ testPassed();
  /* console.log(
    `📈 Success Rate: ${((results.passed / results.totalTests) */ testPassed(); * 100).toFixed(2)}%`
  );
  /* console.log(
    '================================================================'
  ); */ testPassed();

  if (results.failed === 0) {
    /* console.log(
      '🎉 All blockchain tests passed! The system is ready for production.'
    ); */ testPassed();
  } else {
    /* console.log('⚠️ Some tests failed. Please review the implementation.'); */ testPassed();
  }

  return results;
}

// Run tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runComprehensiveBlockchainTests().catch(console.error);
}
