/**
 * OSCAR BROOME QUANTUM AI WALLET DEMO
 * Demonstrates the quantum AI withdrawal digital tap to pay wallet
 */

const { QuantumAIWallet } = require('./quantum/quantumAIWallet.js');

async function demonstrateOscarBroomeQuantumWallet() {
  console.log('🚀 Initializing Oscar Broome\'s Quantum AI Wallet...');

  // Create Oscar Broome's quantum AI wallet
  const oscarWallet = new QuantumAIWallet(
    'USER_1759425133168_851683FD',
    'oscar.broome@jpmorgan.com'
  );

  console.log('✅ Quantum AI Wallet initialized for Oscar Broome');
  console.log('Wallet ID:', oscarWallet.walletId);
  console.log('User ID:', oscarWallet.userId);
  console.log('Email:', oscarWallet.userEmail);
  console.log('Initial Balance:', oscarWallet.balance);
  console.log('AI Engine Status:', JSON.stringify(oscarWallet.aiEngine.getStatus(), null, 2));
  console.log('');

  try {
    // 1. AI-Powered Instant Withdrawal
    console.log('💰 Testing AI-Powered Instant Withdrawal...');
    const withdrawalResult = await oscarWallet.instantWithdrawal(5000, 'jpmorgan_investment_account');
    console.log('✅ Instant Withdrawal Successful:');
    console.log('   Transaction ID:', withdrawalResult.transactionId);
    console.log('   Amount:', withdrawalResult.amount);
    console.log('   Balance:', withdrawalResult.balance);
    console.log('   AI Insights:', JSON.stringify(withdrawalResult.aiInsights, null, 2));
    console.log('');

    // 2. Digital Tap to Pay
    console.log('📱 Testing Digital Tap to Pay...');
    const tapResult = await oscarWallet.tapToPay('quantum_coffee_shop', 12.99, {
      nfcId: 'nfc_oscar_device_001',
      deviceId: 'iphone_15_pro_max',
      location: 'quantum_cafe_downtown'
    });
    console.log('✅ Tap Payment Successful:');
    console.log('   Transaction ID:', tapResult.transactionId);
    console.log('   Amount:', tapResult.amount);
    console.log('   Merchant:', tapResult.merchant);
    console.log('   Balance:', tapResult.balance);
    console.log('');

    // 3. AI-Powered Deposit
    console.log('🤖 Testing AI-Powered Deposit...');
    const depositResult = await oscarWallet.aiDeposit(25000, 'jpmorgan_salary_deposit');
    console.log('✅ AI-Optimized Deposit Successful:');
    console.log('   Transaction ID:', depositResult.transactionId);
    console.log('   Amount:', depositResult.amount);
    console.log('   Balance:', depositResult.balance);
    console.log('   AI Optimization:', JSON.stringify(depositResult.aiOptimization, null, 2));
    console.log('');

    // 4. AI Finance Sync
    console.log('🔄 Testing AI Finance Sync...');
    const syncResult = await oscarWallet.syncFinances();
    console.log('✅ Finance Sync Successful:');
    console.log('   Synced Accounts:', syncResult.syncedData.accounts.length);
    console.log('   Total Synced Balance:', syncResult.syncedData.totalSynced);
    console.log('   AI Predictions:', JSON.stringify(syncResult.predictions, null, 2));
    console.log('');

    // 5. Wallet Status
    console.log('📊 Current Wallet Status:');
    const status = oscarWallet.getWalletStatus();
    console.log(JSON.stringify(status, null, 2));
    console.log('');

    // 6. Transaction History
    console.log('📈 Recent Transaction History:');
    const history = oscarWallet.getTransactionHistory(5);
    history.forEach((txn, index) => {
      console.log(`${index + 1}. ${txn.type.toUpperCase()}: $${txn.amount} - ${txn.description}`);
      console.log(`   ID: ${txn.id} | Time: ${txn.timestamp}`);
      if (txn.aiApproval) {
        console.log(`   AI Risk Score: ${txn.aiApproval.riskScore}`);
      }
      console.log('');
    });

    // 7. Test High-Risk Transaction (should be rejected)
    console.log('🚨 Testing High-Risk Transaction (should be rejected)...');
    try {
      await oscarWallet.instantWithdrawal(100000, 'crypto_exchange_xyz');
      console.log('❌ ERROR: High-risk transaction was approved!');
    } catch (error) {
      console.log('✅ High-risk transaction correctly rejected:');
      console.log('   Error:', error.message);
    }
    console.log('');

    console.log('🎉 Oscar Broome\'s Quantum AI Wallet Demo Complete!');
    console.log('✨ Features Demonstrated:');
    console.log('   • AI-powered instant withdrawals');
    console.log('   • Digital tap-to-pay with quantum security');
    console.log('   • AI-optimized deposits');
    console.log('   • Real-time finance synchronization');
    console.log('   • Quantum-level security and risk assessment');
    console.log('   • Predictive financial intelligence');

  } catch (error) {
    console.error('❌ Demo failed:', error.message);
    console.error(error.stack);
  }
}

// Run the demo
if (require.main === module) {
  demonstrateOscarBroomeQuantumWallet().catch(console.error);
}

module.exports = { demonstrateOscarBroomeQuantumWallet };
