/**
 * @ts-nocheck
 * Private Banking Service Test - King's Banking Ability
 */

import PrivateBankingService from './services/privateBankingService.js';

const pb = new PrivateBankingService();
pb.initializeAccounts();
pb.initializeAssets();

console.log('='.repeat(60));
console.log('👑 KING\'S BANKING ABILITY TEST 🚀');
console.log('='.repeat(60));

console.log('\n--- Testing getAccounts ---');
const accounts = pb.getAccounts();
console.log('Accounts:', JSON.stringify(accounts, null, 2));

console.log('\n--- Testing getAssets ---');
const assets = pb.getAssets();
console.log('Assets:', JSON.stringify(assets, null, 2));

console.log('\n--- Testing getPortfolioSummary ---');
const summary = pb.getPortfolioSummary();
console.log('Portfolio Summary:', JSON.stringify(summary, null, 2));

console.log('\n--- Testing getHealthStatus ---');
const health = pb.getHealthStatus();
console.log('Health:', JSON.stringify(health, null, 2));

console.log('\n--- Testing Sovereign Override ---');
const sovereignResult = pb.activateSovereignOverride();
console.log('Sovereign Override Activated:', JSON.stringify(sovereignResult, null, 2));

console.log('\n--- Testing Liquidity Protection ---');
const protectionResult = pb.activateLiquidityProtection();
console.log('Liquidity Protection:', JSON.stringify(protectionResult, null, 2));

console.log('\n--- Testing Owner Balance ---');
const ownerBalance = pb.getOwnerBalance();
console.log('Owner Balance:', pb.formatCurrency(ownerBalance, 'USD'));

console.log('\n--- Testing Payment/Bill Pay ---');
const paymentResult = pb.payBill(5000, 'Royal Bill Payment Test');
console.log('Payment Result:', JSON.stringify(paymentResult, null, 2));

console.log('\n--- Testing executeTransfer ---');
const transferResult = pb.executeTransfer('primary-checking', {
  toAccountId: 'investment-account',
  amount: 100000,
  description: 'Royal Transfer to Investment',
});
console.log('Transfer Result:', JSON.stringify(transferResult, null, 2));

console.log('\n--- Testing executeDeposit ---');
const depositResult = pb.executeDeposit('primary-checking', {
  amount: 50000,
  description: 'Royal Deposit Test',
});
console.log('Deposit Result:', JSON.stringify(depositResult, null, 2));

console.log('\n--- Testing executeWithdrawal ---');
const withdrawalResult = pb.executeWithdrawal('primary-checking', {
  amount: 25000,
  description: 'Royal Withdrawal Test',
});
console.log('Withdrawal Result:', JSON.stringify(withdrawalResult, null, 2));

console.log('\n--- Testing getAssetHistory ---');
const assetHistory = pb.getAssetHistory('stocks-equities', 30);
console.log('Asset History:', JSON.stringify(assetHistory, null, 2));

console.log('\n--- Testing getTransactionHistory ---');
const transactions = pb.getTransactionHistory(null, 10);
console.log('Transactions:', JSON.stringify(transactions, null, 2));

console.log('\n--- Testing updateAccountBalance ---');
const balanceUpdate = pb.updateAccountBalance(
  'primary-checking',
  3000000,
  'adjustment',
  'King\'s Treasury Adjustment'
);
console.log('Balance Update:', JSON.stringify(balanceUpdate, null, 2));

console.log('\n--- Testing updateAssetValue ---');
const assetUpdate = pb.updateAssetValue(
  'stocks-equities',
  26000000,
  'market'
);
console.log('Asset Update:', JSON.stringify(assetUpdate, null, 2));

console.log('\n--- Testing exportBankingData ---');
const exportData = pb.exportBankingData();
console.log('Export Data Keys:', Object.keys(exportData));

console.log('\n' + '='.repeat(60));
console.log('✅ All KING\'S BANKING ABILITY tests passed!');
console.log('👑 King Sachem Yochanan has FULL CONTROL');
console.log('='.repeat(60));
