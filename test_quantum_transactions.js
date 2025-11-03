/**
 * QUANTUM TRANSACTIONS DEMO
 * Demonstrates the quantum transaction engine processing various transaction types
 */

import { QuantumTransactionEngine } from './quantum/quantumTransactionEngine.js';

async function demonstrateQuantumTransactions() {
  console.log('🚀 Initializing Quantum Transaction Engine...');

  // Create quantum transaction engine
  const transactionEngine = new QuantumTransactionEngine();

  console.log('✅ Quantum Transaction Engine initialized');
  console.log('Engine ID:', transactionEngine.quantumEngine.getQuantumState('transaction_engine')?.engineId);
  console.log('');

  try {
    // 1. Process Payment Transaction
    console.log('💰 Processing Payment Transaction...');
    const paymentResult = await transactionEngine.processTransaction({
      type: 'payment',
      amount: 299.99,
      from: 'oscar.broome@jpmorgan.com',
      to: 'quantum_merchant_luxury',
      description: 'Luxury watch purchase'
    });
    console.log('✅ Payment Processed:');
    console.log('   Transaction ID:', paymentResult.transactionId);
    console.log('   Amount: $299.99');
    console.log('   Payment ID:', paymentResult.result.details.paymentId);
    console.log('   Processing Time:', paymentResult.result.processingTime, 'ms');
    console.log('');

    // 2. Process Transfer Transaction
    console.log('🔄 Processing Transfer Transaction...');
    const transferResult = await transactionEngine.processTransaction({
      type: 'transfer',
      amount: 50000.00,
      from: 'jpmorgan_checking_oscar',
      to: 'jpmorgan_investment_oscar',
      description: 'Monthly investment transfer'
    });
    console.log('✅ Transfer Processed:');
    console.log('   Transaction ID:', transferResult.transactionId);
    console.log('   Amount: $50,000.00');
    console.log('   Transfer ID:', transferResult.result.details.transferId);
    console.log('');

    // 3. Process Withdrawal Transaction
    console.log('🏦 Processing Withdrawal Transaction...');
    const withdrawalResult = await transactionEngine.processTransaction({
      type: 'withdrawal',
      amount: 1000.00,
      from: 'jpmorgan_checking_oscar',
      destination: 'external_bank_account',
      description: 'Cash withdrawal for business expenses'
    });
    console.log('✅ Withdrawal Processed:');
    console.log('   Transaction ID:', withdrawalResult.transactionId);
    console.log('   Amount: $1,000.00');
    console.log('   Withdrawal ID:', withdrawalResult.result.details.withdrawalId);
    console.log('');

    // 4. Process Deposit Transaction
    console.log('💳 Processing Deposit Transaction...');
    const depositResult = await transactionEngine.processTransaction({
      type: 'deposit',
      amount: 75000.00,
      to: 'jpmorgan_checking_oscar',
      source: 'salary_deposit_jpmorgan',
      description: 'Monthly salary deposit'
    });
    console.log('✅ Deposit Processed:');
    console.log('   Transaction ID:', depositResult.transactionId);
    console.log('   Amount: $75,000.00');
    console.log('   Deposit ID:', depositResult.result.details.depositId);
    console.log('');

    // 5. Process Refund Transaction
    console.log('🔙 Processing Refund Transaction...');
    const refundResult = await transactionEngine.processTransaction({
      type: 'refund',
      amount: 299.99,
      to: 'oscar.broome@jpmorgan.com',
      originalTransactionId: paymentResult.transactionId,
      description: 'Refund for luxury watch purchase'
    });
    console.log('✅ Refund Processed:');
    console.log('   Transaction ID:', refundResult.transactionId);
    console.log('   Amount: $299.99');
    console.log('   Refund ID:', refundResult.result.details.refundId);
    console.log('   Original Transaction:', refundResult.result.details.originalTransaction);
    console.log('');

    // 6. Process Currency Exchange Transaction
    console.log('💱 Processing Currency Exchange Transaction...');
    const exchangeResult = await transactionEngine.processTransaction({
      type: 'exchange',
      amount: 10000.00,
      fromCurrency: 'USD',
      toCurrency: 'EUR',
      exchangeRate: 0.85,
      from: 'jpmorgan_trading_oscar',
      to: 'european_bank_account',
      description: 'Business trip currency exchange'
    });
    console.log('✅ Exchange Processed:');
    console.log('   Transaction ID:', exchangeResult.transactionId);
    console.log('   Amount: $10,000.00');
    console.log('   Exchange Rate: 0.85');
    console.log('   Converted Amount: €8,500.00');
    console.log('   Exchange ID:', exchangeResult.result.details.exchangeId);
    console.log('');

    // 7. Display Transaction Metrics
    console.log('📊 Transaction Engine Metrics:');
    const metrics = transactionEngine.getTransactionMetrics();
    console.log(JSON.stringify(metrics, null, 2));
    console.log('');

    // 8. Display Recent Transaction History
    console.log('📈 Recent Transaction History:');
    const history = transactionEngine.getTransactionHistory(5);
    history.forEach((txn, index) => {
      console.log(`${index + 1}. ${txn.type.toUpperCase()}: $${txn.amount.toLocaleString()} - ${txn.description}`);
      console.log(`   ID: ${txn.id} | Status: ${txn.status} | Time: ${txn.createdAt}`);
      console.log('');
    });

    // 9. Display Engine Status
    console.log('🔧 Quantum Transaction Engine Status:');
    const status = transactionEngine.getEngineStatus();
    console.log(JSON.stringify(status, null, 2));
    console.log('');

    // 10. Test Transaction Validation
    console.log('✅ Testing Transaction Validation...');
    const validAmount = transactionEngine.validateAmount(500);
    const invalidAmount = transactionEngine.validateAmount(-100);
    const validType = transactionEngine.validateTransactionType('payment');
    const invalidType = transactionEngine.validateTransactionType('invalid');

    console.log('Amount $500 validation:', validAmount.valid ? '✅ Valid' : '❌ Invalid');
    console.log('Amount -$100 validation:', invalidAmount.valid ? '✅ Valid' : '❌ Invalid');
    console.log('Type "payment" validation:', validType.valid ? '✅ Valid' : '❌ Invalid');
    console.log('Type "invalid" validation:', invalidType.valid ? '✅ Valid' : '❌ Invalid');
    console.log('');

    console.log('🎉 Quantum Transaction Engine Demo Complete!');
    console.log('✨ Features Demonstrated:');
    console.log('   • Payment processing with quantum security');
    console.log('   • Account transfers and withdrawals');
    console.log('   • Deposit and refund transactions');
    console.log('   • Currency exchange operations');
    console.log('   • Real-time transaction metrics');
    console.log('   • Comprehensive transaction history');
    console.log('   • Quantum validation and integrity checks');
    console.log('   • Engine status monitoring');

  } catch (error) {
    console.error('❌ Demo failed:', error.message);
    console.error(error.stack);
  }
}

export { demonstrateQuantumTransactions };

if (import.meta.url === `file://${process.argv[1]}`) {
  demonstrateQuantumTransactions().catch(console.error);
}
