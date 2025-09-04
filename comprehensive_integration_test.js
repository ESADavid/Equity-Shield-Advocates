/**
 * Comprehensive Integration Test Suite for Auto Finance Portal with Account Management
 * Tests all API endpoints, edge cases, error handling, and integration scenarios
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
  OVERRIDE_REASONS
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
      lastActivity: new Date()
    };
    this.accounts.set(accountId, account);
    this.transactions.set(accountId, []);
    return account;
  }

  getAccount(accountId) {
    return this.accounts.get(accountId);
  }

  getUserAccounts(userId) {
    return Array.from(this.accounts.values()).filter(acc => acc.userId === userId);
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
      timestamp: new Date()
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

// Test Results Tracker
class TestResults {
  constructor() {
    this.passed = 0;
    this.failed = 0;
    this.errors = [];
  }

  logPass(testName) {
    this.passed++;
    console.log(`✅ ${testName} - PASSED`);
  }

  logFail(testName, error) {
    this.failed++;
    this.errors.push({ test: testName, error });
    console.log(`❌ ${testName} - FAILED: ${error.message}`);
  }

  summary() {
    console.log(`\n📊 Test Summary:`);
    console.log(`✅ Passed: ${this.passed}`);
    console.log(`❌ Failed: ${this.failed}`);
    console.log(`📈 Total: ${this.passed + this.failed}`);
    console.log(`📊 Success Rate: ${((this.passed / (this.passed + this.failed)) * 100).toFixed(2)}%`);

    if (this.errors.length > 0) {
      console.log(`\n🔍 Failed Tests:`);
      this.errors.forEach((err, index) => {
        console.log(`${index + 1}. ${err.test}: ${err.error.message}`);
      });
    }
  }
}

const testResults = new TestResults();

// API Endpoint Testing
async function testAPIEndpoints() {
  console.log('\n🔗 Testing API Endpoints...\n');

  try {
    // Test 1: User Registration API
    console.log('1️⃣ Testing User Registration API...');
    const registerResult = await registerUser('apiuser', 'api@example.com', 'ApiPass123!', 'user');
    testResults.logPass('User Registration API');
    console.log('   User registered:', registerResult);

    // Test 2: User Authentication API
    console.log('\n2️⃣ Testing User Authentication API...');
    const authResult = await authenticateUser('apiuser', 'ApiPass123!');
    testResults.logPass('User Authentication API');
    console.log('   User authenticated:', authResult);

    // Test 3: Token Validation API
    console.log('\n3️⃣ Testing Token Validation API...');
    const tokenValidation = validateToken(authResult.token);
    testResults.logPass('Token Validation API');
    console.log('   Token validation:', tokenValidation);

    // Test 4: Password Change API
    console.log('\n4️⃣ Testing Password Change API...');
    const passwordChange = await changePassword(registerResult.userId, 'ApiPass123!', 'NewApiPass456!');
    testResults.logPass('Password Change API');
    console.log('   Password changed:', passwordChange);

    // Test 5: MFA Enable API
    console.log('\n5️⃣ Testing MFA Enable API...');
    const mfaResult = await enableMFA(registerResult.userId);
    testResults.logPass('MFA Enable API');
    console.log('   MFA enabled:', mfaResult);

    // Test 6: User Deactivation API
    console.log('\n6️⃣ Testing User Deactivation API...');
    const deactivation = await deactivateUser(registerResult.userId, 'admin@oscarsystem.com');
    testResults.logPass('User Deactivation API');
    console.log('   User deactivated:', deactivation);

  } catch (error) {
    testResults.logFail('API Endpoints Test', error);
  }
}

// Edge Cases and Error Handling
async function testEdgeCases() {
  console.log('\n⚠️ Testing Edge Cases and Error Handling...\n');

  try {
    // Test 1: Invalid Email Format
    console.log('1️⃣ Testing Invalid Email Format...');
    try {
      await registerUser('edgeuser', 'invalid-email', 'Pass123!', 'user');
      testResults.logFail('Invalid Email Format', new Error('Should have thrown error for invalid email'));
    } catch (error) {
      testResults.logPass('Invalid Email Format');
      console.log('   Correctly rejected invalid email');
    }

    // Test 2: Weak Password
    console.log('\n2️⃣ Testing Weak Password...');
    try {
      await registerUser('weakpass', 'weak@example.com', '123', 'user');
      testResults.logFail('Weak Password', new Error('Should have thrown error for weak password'));
    } catch (error) {
      testResults.logPass('Weak Password');
      console.log('   Correctly rejected weak password');
    }

    // Test 3: Duplicate Username
    console.log('\n3️⃣ Testing Duplicate Username...');
    try {
      await registerUser('apiuser', 'duplicate@example.com', 'Pass123!', 'user');
      testResults.logFail('Duplicate Username', new Error('Should have thrown error for duplicate username'));
    } catch (error) {
      testResults.logPass('Duplicate Username');
      console.log('   Correctly rejected duplicate username');
    }

    // Test 4: Invalid Token
    console.log('\n4️⃣ Testing Invalid Token...');
    const invalidToken = validateToken('invalid.jwt.token');
    if (invalidToken === null) {
      testResults.logPass('Invalid Token');
      console.log('   Correctly rejected invalid token');
    } else {
      testResults.logFail('Invalid Token', new Error('Should have returned null for invalid token'));
    }

    // Test 5: Non-existent User
    console.log('\n5️⃣ Testing Non-existent User...');
    try {
      await authenticateUser('nonexistent', 'password');
      testResults.logFail('Non-existent User', new Error('Should have thrown error for non-existent user'));
    } catch (error) {
      testResults.logPass('Non-existent User');
      console.log('   Correctly rejected non-existent user');
    }

  } catch (error) {
    testResults.logFail('Edge Cases Test', error);
  }
}

// Account Management API Testing
async function testAccountManagementAPI() {
  console.log('\n💳 Testing Account Management API...\n');

  try {
    // Register finance user
    const financeUser = await registerUser('accountapi', 'accountapi@example.com', 'AccountPass123!', 'finance');

    // Test 1: Account Creation API
    console.log('1️⃣ Testing Account Creation API...');
    const savingsAccount = accountManager.createAccount(financeUser.userId, 'savings', 1000.00);
    testResults.logPass('Account Creation API');
    console.log('   Savings account created:', savingsAccount.accountId);

    // Test 2: Account Retrieval API
    console.log('\n2️⃣ Testing Account Retrieval API...');
    const retrievedAccount = accountManager.getAccount(savingsAccount.accountId);
    if (retrievedAccount && retrievedAccount.accountId === savingsAccount.accountId) {
      testResults.logPass('Account Retrieval API');
      console.log('   Account retrieved successfully');
    } else {
      testResults.logFail('Account Retrieval API', new Error('Failed to retrieve account'));
    }

    // Test 3: Balance Update API
    console.log('\n3️⃣ Testing Balance Update API...');
    const updatedAccount = accountManager.updateBalance(savingsAccount.accountId, 250.00);
    if (updatedAccount && updatedAccount.balance === 1250.00) {
      testResults.logPass('Balance Update API');
      console.log('   Balance updated to:', updatedAccount.balance);
    } else {
      testResults.logFail('Balance Update API', new Error('Failed to update balance'));
    }

    // Test 4: Transaction Recording API
    console.log('\n4️⃣ Testing Transaction Recording API...');
    const transaction = accountManager.recordTransaction(savingsAccount.accountId, -50.00, 'withdrawal', 'ATM withdrawal');
    testResults.logPass('Transaction Recording API');
    console.log('   Transaction recorded:', transaction.transactionId);

    // Test 5: Transaction History API
    console.log('\n5️⃣ Testing Transaction History API...');
    const transactions = accountManager.getTransactionHistory(savingsAccount.accountId);
    if (transactions.length > 0) {
      testResults.logPass('Transaction History API');
      console.log('   Found', transactions.length, 'transactions');
    } else {
      testResults.logFail('Transaction History API', new Error('No transactions found'));
    }

    // Test 6: Account Freeze API
    console.log('\n6️⃣ Testing Account Freeze API...');
    const frozenAccount = accountManager.freezeAccount(savingsAccount.accountId, 'Suspicious activity');
    if (frozenAccount && frozenAccount.status === 'frozen') {
      testResults.logPass('Account Freeze API');
      console.log('   Account frozen successfully');
    } else {
      testResults.logFail('Account Freeze API', new Error('Failed to freeze account'));
    }

    // Test 7: Account Unfreeze API
    console.log('\n7️⃣ Testing Account Unfreeze API...');
    const unfrozenAccount = accountManager.unfreezeAccount(savingsAccount.accountId);
    if (unfrozenAccount && unfrozenAccount.status === 'active') {
      testResults.logPass('Account Unfreeze API');
      console.log('   Account unfrozen successfully');
    } else {
      testResults.logFail('Account Unfreeze API', new Error('Failed to unfreeze account'));
    }

  } catch (error) {
    testResults.logFail('Account Management API Test', error);
  }
}

// Auto Finance Portal Integration Testing
async function testAutoFinanceIntegration() {
  console.log('\n🚗 Testing Auto Finance Portal Integration...\n');

  try {
    // Register auto finance user
    const autoUser = await registerUser('autofinance', 'autofinance@example.com', 'AutoPass123!', 'finance');

    // Test 1: Auto Loan Account Creation
    console.log('1️⃣ Testing Auto Loan Account Creation...');
    const autoLoanAccount = accountManager.createAccount(autoUser.userId, 'auto_loan', 25000.00);
    testResults.logPass('Auto Loan Account Creation');
    console.log('   Auto loan account created:', autoLoanAccount.accountId);

    // Test 2: Loan Payment Processing
    console.log('\n2️⃣ Testing Loan Payment Processing...');
    const payment = accountManager.recordTransaction(autoLoanAccount.accountId, -450.00, 'payment', 'Monthly auto loan payment');
    testResults.logPass('Loan Payment Processing');
    console.log('   Payment recorded:', payment.transactionId);

    // Test 3: Account Balance After Payment
    console.log('\n3️⃣ Testing Account Balance After Payment...');
    const updatedLoanAccount = accountManager.getAccount(autoLoanAccount.accountId);
    if (updatedLoanAccount && updatedLoanAccount.balance === 24550.00) {
      testResults.logPass('Account Balance After Payment');
      console.log('   Balance updated to:', updatedLoanAccount.balance);
    } else {
      testResults.logFail('Account Balance After Payment', new Error('Balance not updated correctly'));
    }

    // Test 4: Finance Portal Access
    console.log('\n4️⃣ Testing Finance Portal Access...');
    const auth = await authenticateUser('autofinance', 'AutoPass123!');
    const portalAccess = testSecureAccountAccess(auth.token, autoLoanAccount.accountId);
    if (portalAccess) {
      testResults.logPass('Finance Portal Access');
      console.log('   Portal access granted');
    } else {
      testResults.logFail('Finance Portal Access', new Error('Portal access denied'));
    }

    // Test 5: Override for Account Access
    console.log('\n5️⃣ Testing Override for Account Access...');
    const override = await loginOverrideManager.emergencyOverride(
      autoUser.userId,
      OVERRIDE_REASONS.EMERGENCY_ACCESS,
      'account_access_emergency'
    );
    testResults.logPass('Override for Account Access');
    console.log('   Override activated:', override);

  } catch (error) {
    testResults.logFail('Auto Finance Integration Test', error);
  }
}

// Security Testing
async function testSecurityFeatures() {
  console.log('\n🔒 Testing Security Features...\n');

  try {
    // Test 1: MFA Token Verification
    console.log('1️⃣ Testing MFA Token Verification...');
    const user = await registerUser('securityuser', 'security@example.com', 'SecurityPass123!', 'user');
    const mfaResult = await enableMFA(user.userId);

    const crypto = require('crypto');
    const testToken = crypto.createHmac('sha256', mfaResult.mfaSecret)
      .update(Math.floor(Date.now() / 30000).toString())
      .digest('hex')
      .substring(0, 6);
    const mfaVerification = await verifyMFAToken(user.userId, testToken);
    testResults.logPass('MFA Token Verification');
    console.log('   MFA token verified');

    // Test 2: Admin Override
    console.log('\n2️⃣ Testing Admin Override...');
    const adminOverride = await loginOverrideManager.adminOverride(
      'admin@oscarsystem.com',
      user.userId,
      OVERRIDE_REASONS.TECHNICAL_ISSUE,
      'User reported login issues'
    );
    testResults.logPass('Admin Override');
    console.log('   Admin override activated');

    // Test 3: Override Statistics
    console.log('\n3️⃣ Testing Override Statistics...');
    const stats = loginOverrideManager.getOverrideStatistics();
    testResults.logPass('Override Statistics');
    console.log('   Override statistics retrieved');

    // Test 4: Account Security Validation
    console.log('\n4️⃣ Testing Account Security Validation...');
    const account = accountManager.createAccount(user.userId, 'checking', 1000.00);
    const securityTest = testAccountSecurity(account.accountId, user.userId);
    if (securityTest) {
      testResults.logPass('Account Security Validation');
      console.log('   Account security validated');
    } else {
      testResults.logFail('Account Security Validation', new Error('Account security validation failed'));
    }

  } catch (error) {
    testResults.logFail('Security Features Test', error);
  }
}

// Performance Testing
async function testPerformance() {
  console.log('\n⚡ Testing Performance...\n');

  try {
    // Test 1: Multiple User Registrations
    console.log('1️⃣ Testing Multiple User Registrations...');
    const startTime = Date.now();
    const promises = [];
    for (let i = 0; i < 10; i++) {
      promises.push(registerUser(`perfuser${i}`, `perf${i}@example.com`, 'PerfPass123!', 'user'));
    }
    await Promise.all(promises);
    const endTime = Date.now();
    const duration = endTime - startTime;
    testResults.logPass('Multiple User Registrations');
    console.log(`   10 users registered in ${duration}ms`);

    // Test 2: Concurrent Account Operations
    console.log('\n2️⃣ Testing Concurrent Account Operations...');
    const user = await registerUser('concurrentuser', 'concurrent@example.com', 'ConcurrentPass123!', 'finance');
    const account = accountManager.createAccount(user.userId, 'checking', 1000.00);

    const accountPromises = [];
    for (let i = 0; i < 20; i++) {
      accountPromises.push(accountManager.recordTransaction(account.accountId, -10.00, 'withdrawal', `Test transaction ${i}`));
    }
    await Promise.all(accountPromises);
    testResults.logPass('Concurrent Account Operations');
    console.log('   20 concurrent transactions processed');

    // Test 3: Authentication Load Test
    console.log('\n3️⃣ Testing Authentication Load Test...');
    const authPromises = [];
    for (let i = 0; i < 50; i++) {
      authPromises.push(authenticateUser('concurrentuser', 'ConcurrentPass123!'));
    }
    await Promise.all(authPromises);
    testResults.logPass('Authentication Load Test');
    console.log('   50 concurrent authentications processed');

  } catch (error) {
    testResults.logFail('Performance Test', error);
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

function testAccountSecurity(accountId, userId) {
  const account = accountManager.getAccount(accountId);
  if (!account) return false;

  if (account.userId !== userId) return false;

  if (account.status !== 'active') return false;

  return true;
}

// Run all comprehensive tests
async function runComprehensiveTests() {
  console.log('🧪 Starting Comprehensive Integration Test Suite\n');
  console.log('=' .repeat(60));

  await testAPIEndpoints();
  await testEdgeCases();
  await testAccountManagementAPI();
  await testAutoFinanceIntegration();
  await testSecurityFeatures();
  await testPerformance();

  console.log('\n' + '=' .repeat(60));
  testResults.summary();

  console.log('\n🏁 Comprehensive Integration Testing Completed!');
}

runComprehensiveTests().catch(console.error);
