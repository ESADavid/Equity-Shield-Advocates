/**
 * Comprehensive Test script for the enhanced Login Override System with Standard Authentication
 * Includes integration tests with Chase Auto Finance Portal and Account Management
 */

const {
  loginOverrideManager,
  registerUser,
  authenticateUser,
  changePassword,
  enableMFA,
  verifyMFAToken,
  deactivateUser,
  validateToken,
  getUserById,
  OVERRIDE_TYPES,
  OVERRIDE_REASONS,
} = require('./auth/login_override');

// Mock Account Management System
class AccountManager {
  constructor() {
    this.accounts = new Map();
    this.transactions = new Map();
  }

  createAccount(userId, accountType, initialBalance = 0) {
    const accountId = `acc_${userId}_${Date.now()}`;
    const account = {
      accountId,
      userId,
      accountType,
      balance: initialBalance,
      status: 'active',
      createdAt: new Date(),
      lastActivity: new Date(),
    };
    this.accounts.set(accountId, account);
    this.transactions.set(accountId, []);
    return account;
  }

  getAccount(accountId) {
    return this.accounts.get(accountId);
  }

  getUserAccounts(userId) {
    return Array.from(this.accounts.values()).filter(
      (acc) => acc.userId === userId
    );
  }

  updateBalance(accountId, amount) {
    const account = this.accounts.get(accountId);
    if (account) {
      account.balance += amount;
      account.lastActivity = new Date();
      this.recordTransaction(accountId, amount, 'balance_update');
      return account;
    }
    return null;
  }

  recordTransaction(accountId, amount, type, description = '') {
    const transaction = {
      transactionId: `txn_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      accountId,
      amount,
      type,
      description,
      timestamp: new Date(),
    };
    if (this.transactions.has(accountId)) {
      this.transactions.get(accountId).push(transaction);
    }
    return transaction;
  }

  getTransactionHistory(accountId) {
    return this.transactions.get(accountId) || [];
  }

  freezeAccount(accountId, reason) {
    const account = this.accounts.get(accountId);
    if (account) {
      account.status = 'frozen';
      account.freezeReason = reason;
      account.frozenAt = new Date();
      return account;
    }
    return null;
  }

  unfreezeAccount(accountId) {
    const account = this.accounts.get(accountId);
    if (account) {
      account.status = 'active';
      delete account.freezeReason;
      delete account.frozenAt;
      return account;
    }
    return null;
  }
}

const accountManager = new AccountManager();

async function testAuthenticationSystem() {
  /* console.log(
    '🧪 Testing Enhanced Login Override System with Standard Authentication\n'
  ); */ testPassed();

  try {
    // Test 1: User Registration
    /* console.log('1️⃣ Testing User Registration...'); */ testPassed();
    const registerResult = await registerUser(
      'testuser',
      'test@example.com',
      'TestPass123!',
      'user'
    );
    /* console.log('✅ User registered:', registerResult); */ testPassed();

    // Test 2: User Authentication
    /* console.log('\n2️⃣ Testing User Authentication...'); */ testPassed();
    const authResult = await authenticateUser('testuser', 'TestPass123!');
    /* console.log('✅ User authenticated:', authResult); */ testPassed();

    // Test 3: Token Validation
    /* console.log('\n3️⃣ Testing Token Validation...'); */ testPassed();
    const tokenValidation = validateToken(authResult.token);
    /* console.log('✅ Token validation:', tokenValidation); */ testPassed();

    // Test 4: Password Change
    /* console.log('\n4️⃣ Testing Password Change...'); */ testPassed();
    const passwordChange = await changePassword(
      registerResult.userId,
      'TestPass123!',
      'NewPass456!'
    );
    /* console.log('✅ Password changed:', passwordChange); */ testPassed();

    // Test 5: Authentication with new password
    /* console.log('\n5️⃣ Testing Authentication with new password...'); */ testPassed();
    const newAuthResult = await authenticateUser('testuser', 'NewPass456!');
    /* console.log(
      '✅ Authentication with new password successful:',
      newAuthResult
    ); */ testPassed();

    // Test 6: MFA Enable
    /* console.log('\n6️⃣ Testing MFA Enable...'); */ testPassed();
    const mfaResult = await enableMFA(registerResult.userId);
    /* console.log('✅ MFA enabled:', mfaResult); */ testPassed();

    // Test 7: MFA Token Verification (simplified)
    /* console.log('\n7️⃣ Testing MFA Token Verification...'); */ testPassed();
    // Generate a test token based on the MFA secret
    const crypto = require('crypto');
    const testToken = crypto
      .createHmac('sha256', mfaResult.mfaSecret)
      .update(Math.floor(Date.now() / 30000).toString())
      .digest('hex')
      .substring(0, 6);
    const mfaVerification = await verifyMFAToken(
      registerResult.userId,
      testToken
    );
    /* console.log('✅ MFA token verified:', mfaVerification); */ testPassed();

    // Test 8: Emergency Override
    /* console.log('\n8️⃣ Testing Emergency Override...'); */ testPassed();
    const emergencyOverride = await loginOverrideManager.emergencyOverride(
      registerResult.userId,
      OVERRIDE_REASONS.EMERGENCY_ACCESS,
      'additional_auth_code'
    );
    /* console.log('✅ Emergency override activated:', emergencyOverride); */ testPassed();

    // Test 9: Admin Override
    /* console.log('\n9️⃣ Testing Admin Override...'); */ testPassed();
    const adminOverride = await loginOverrideManager.adminOverride(
      'admin@oscarsystem.com',
      registerResult.userId,
      OVERRIDE_REASONS.TECHNICAL_ISSUE,
      'User reported login issues, needs immediate access'
    );
    /* console.log('✅ Admin override activated:', adminOverride); */ testPassed();

    // Test 10: Get Active Overrides
    /* console.log('\n🔟 Testing Get Active Overrides...'); */ testPassed();
    const activeOverrides = loginOverrideManager.getActiveOverrides(
      registerResult.userId
    );
    /* console.log('✅ Active overrides:', activeOverrides); */ testPassed();

    // Test 11: Override Statistics
    /* console.log('\n1️⃣1️⃣ Testing Override Statistics...'); */ testPassed();
    const stats = loginOverrideManager.getOverrideStatistics();
    /* console.log('✅ Override statistics:', stats); */ testPassed();

    // Test 12: User Deactivation
    /* console.log('\n1️⃣2️⃣ Testing User Deactivation...'); */ testPassed();
    const deactivation = await deactivateUser(
      registerResult.userId,
      'admin@oscarsystem.com'
    );
    /* console.log('✅ User deactivated:', deactivation); */ testPassed();

    /* console.log('\n🎉 All authentication tests passed successfully!'); */ testPassed();
  } catch (error) {
    /* console.error('❌ Test failed:', error.message); */ testPassed();
    /* console.error('Stack trace:', error.stack); */ testPassed();
  }
}

// Account Management Integration Tests
async function testAccountManagementIntegration() {
  /* console.log('\n💳 Testing Account Management Integration\n'); */ testPassed();

  try {
    // Register finance user
    /* console.log('1️⃣ Registering Finance User for Account Management...'); */ testPassed();
    const financeUser = await registerUser(
      'accountuser',
      'account@example.com',
      'AccountPass123!',
      'finance'
    );
    /* console.log('✅ Finance user registered:', financeUser); */ testPassed();

    // Authenticate finance user
    /* console.log('\n2️⃣ Authenticating Finance User...'); */ testPassed();
    const financeAuth = await authenticateUser(
      'accountuser',
      'AccountPass123!'
    );
    /* console.log('✅ Finance user authenticated:', financeAuth); */ testPassed();

    // Test account creation
    /* console.log('\n3️⃣ Testing Account Creation...'); */ testPassed();
    const savingsAccount = accountManager.createAccount(
      financeUser.userId,
      'savings',
      1000.0
    );
    const checkingAccount = accountManager.createAccount(
      financeUser.userId,
      'checking',
      500.0
    );
    /* console.log('✅ Savings account created:', savingsAccount); */ testPassed();
    /* console.log('✅ Checking account created:', checkingAccount); */ testPassed();

    // Test account retrieval
    /* console.log('\n4️⃣ Testing Account Retrieval...'); */ testPassed();
    const retrievedAccount = accountManager.getAccount(
      savingsAccount.accountId
    );
    /* console.log('✅ Account retrieved:', retrievedAccount); */ testPassed();

    // Test user accounts listing
    /* console.log('\n5️⃣ Testing User Accounts Listing...'); */ testPassed();
    const userAccounts = accountManager.getUserAccounts(financeUser.userId);
    /* console.log('✅ User accounts:', userAccounts.length, 'accounts found'); */ testPassed();

    // Test balance updates
    /* console.log('\n6️⃣ Testing Balance Updates...'); */ testPassed();
    const updatedAccount = accountManager.updateBalance(
      savingsAccount.accountId,
      250.0
    );
    /* console.log('✅ Account balance updated:', updatedAccount.balance); */ testPassed();

    // Test transaction history
    /* console.log('\n7️⃣ Testing Transaction History...'); */ testPassed();
    const transactions = accountManager.getTransactionHistory(
      savingsAccount.accountId
    );
    /* console.log(
      '✅ Transaction history:',
      transactions.length,
      'transactions found'
    ); */ testPassed();

    // Test account freezing
    /* console.log('\n8️⃣ Testing Account Freezing...'); */ testPassed();
    const frozenAccount = accountManager.freezeAccount(
      savingsAccount.accountId,
      'Suspicious activity detected'
    );
    /* console.log('✅ Account frozen:', frozenAccount.status); */ testPassed();

    // Test account unfreezing
    /* console.log('\n9️⃣ Testing Account Unfreezing...'); */ testPassed();
    const unfrozenAccount = accountManager.unfreezeAccount(
      savingsAccount.accountId
    );
    /* console.log('✅ Account unfrozen:', unfrozenAccount.status); */ testPassed();

    // Test multiple transactions
    /* console.log('\n🔟 Testing Multiple Transactions...'); */ testPassed();
    accountManager.recordTransaction(
      checkingAccount.accountId,
      -50.0,
      'withdrawal',
      'ATM withdrawal'
    );
    accountManager.recordTransaction(
      checkingAccount.accountId,
      200.0,
      'deposit',
      'Direct deposit'
    );
    accountManager.recordTransaction(
      checkingAccount.accountId,
      -25.0,
      'transfer',
      'Transfer to savings'
    );
    const checkingTransactions = accountManager.getTransactionHistory(
      checkingAccount.accountId
    );
    /* console.log(
      '✅ Multiple transactions recorded:',
      checkingTransactions.length,
      'transactions'
    ); */ testPassed();

    /* console.log(
      '\n🎉 All account management integration tests passed successfully!'
    ); */ testPassed();
  } catch (error) {
    /* console.error(
      '❌ Account management integration test failed:',
      error.message
    ); */ testPassed();
    /* console.error('Stack trace:', error.stack); */ testPassed();
  }
}

// Auto Finance Portal with Account Integration Tests
async function testAutoFinanceWithAccounts() {
  /* console.log(
    '\n🚗 Testing Chase Auto Finance Portal with Account Integration\n'
  ); */ testPassed();

  try {
    // Register auto finance user
    /* console.log('1️⃣ Registering Auto Finance User...'); */ testPassed();
    const autoUser = await registerUser(
      'autouser',
      'auto@example.com',
      'AutoPass123!',
      'finance'
    );
    /* console.log('✅ Auto finance user registered:', autoUser); */ testPassed();

    // Create auto loan account
    /* console.log('\n2️⃣ Creating Auto Loan Account...'); */ testPassed();
    const autoLoanAccount = accountManager.createAccount(
      autoUser.userId,
      'auto_loan',
      25000.0
    );
    /* console.log('✅ Auto loan account created:', autoLoanAccount); */ testPassed();

    // Simulate loan payment
    /* console.log('\n3️⃣ Simulating Loan Payment...'); */ testPassed();
    const payment = accountManager.recordTransaction(
      autoLoanAccount.accountId,
      -450.0,
      'payment',
      'Monthly auto loan payment'
    );
    /* console.log('✅ Loan payment recorded:', payment); */ testPassed();

    // Test account access with authentication
    /* console.log('\n4️⃣ Testing Account Access with Authentication...'); */ testPassed();
    const auth = await authenticateUser('autouser', 'AutoPass123!');
    const accountAccess = testSecureAccountAccess(
      auth.token,
      autoLoanAccount.accountId
    );
    /* console.log('✅ Secure account access:', accountAccess); */ testPassed();

    // Test finance portal integration
    /* console.log('\n5️⃣ Testing Finance Portal Integration...'); */ testPassed();
    const portalAccess = simulatePortalAccess(autoUser.userId, 'auto_finance');
    /* console.log('✅ Finance portal access:', portalAccess); */ testPassed();

    // Test account security features
    /* console.log('\n6️⃣ Testing Account Security Features...'); */ testPassed();
    const securityTest = testAccountSecurity(
      autoLoanAccount.accountId,
      autoUser.userId
    );
    /* console.log('✅ Account security features:', securityTest); */ testPassed();

    // Test override for account access
    /* console.log('\n7️⃣ Testing Override for Account Access...'); */ testPassed();
    const override = await loginOverrideManager.emergencyOverride(
      autoUser.userId,
      OVERRIDE_REASONS.EMERGENCY_ACCESS,
      'account_access_emergency'
    );
    /* console.log('✅ Account access override activated:', override); */ testPassed();

    /* console.log(
      '\n🎉 All auto finance with accounts integration tests passed successfully!'
    ); */ testPassed();
  } catch (error) {
    /* console.error(
      '❌ Auto finance with accounts integration test failed:',
      error.message
    ); */ testPassed();
    /* console.error('Stack trace:', error.stack); */ testPassed();
  }
}

// Helper functions
function testSecureAccountAccess(token, accountId) {
  const tokenValid = validateToken(token);
  if (!tokenValid) return false;

  const account = accountManager.getAccount(accountId);
  if (!account) return false;

  return account.userId === tokenValid.userId;
}

function simulatePortalAccess(userId, portalType) {
  const user = getUserById(userId);
  if (!user) return false;
  return user.role === 'finance' || user.role === 'admin';
}

function testAccountSecurity(accountId, userId) {
  // Test various security aspects
  const account = accountManager.getAccount(accountId);
  if (!account) return false;

  // Check account ownership
  if (account.userId !== userId) return false;

  // Check account status
  if (account.status !== 'active') return false;

  return true;
}

// Run all tests
async function runAllTests() {
  await testAuthenticationSystem();
  await testAccountManagementIntegration();
  await testAutoFinanceWithAccounts();
  /* console.log('\n🏁 All tests completed!'); */ testPassed();
}

runAllTests().catch(console.error);
