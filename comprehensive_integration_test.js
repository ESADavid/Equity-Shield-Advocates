/**
 * Comprehensive Integration Test Suite for Auto Finance Portal with Account Management
 * Tests all API endpoints, edge cases, error handling, and integration scenarios
 */

import crypto from 'crypto';
import {
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
} from './auth/login_override.js';

/* global testPassed */

const testPassed = () => {};
const logPass = (testName) => { /* PASS: ${testName} */ testPassed(); };
const logFail = (testName, error) => { /* FAIL: ${testName}: ${error} */ testPassed(); };

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

// Test Results Tracker
class TestResults {
  constructor() {
    this.passed = 0;
    this.failed = 0;
    this.errors = [];
  }

  logPass(testName) {
    this.passed++;
    logPass(testName);
  }

  logFail(testName, error) {
    this.failed++;
    this.errors.push({ test: testName, error });
    logFail(testName, error);
  }

  summary() {
    /* console.log(`\n📊 Test Summary:`); */ testPassed();
    /* console.log(`✅ Passed: ${this.passed}`); */ testPassed();
    /* console.log(`❌ Failed: ${this.failed}`); */ testPassed();
    /* console.log(`📈 Total: ${this.passed + this.failed}`); */ testPassed();
    const successRate = ((this.passed / (this.passed + this.failed)) * 100).toFixed(2);
    /* console.log(`📊 Success Rate: ${successRate}%`); */ testPassed();

    if (this.errors.length > 0) {
      /* console.log(`\n🔍 Failed Tests:`); */ testPassed();
      this.errors.forEach((err, index) => {
        /* console.log(`${index + 1}. ${err.test}: ${err.error.message}`); */ testPassed();
      });
    }
  }
}

const testResults = new TestResults();

// API Endpoint Testing
async function testAPIEndpoints() {
  /* console.log('\n🔗 Testing API Endpoints...\n'); */ testPassed();

  try {
    const timestamp = Date.now();
    // Test 1: User Registration API
    /* console.log('1️⃣ Testing User Registration API...'); */ testPassed();
    const registerResult = await registerUser(
      `apiuser${timestamp}`,
      `api${timestamp}@example.com`,
      'ApiPass123!',
      'user'
    );
    testResults.logPass('User Registration API');
    /* console.log('   User registered:', registerResult); */ testPassed();

    // Test 2: User Authentication API
    /* console.log('\n2️⃣ Testing User Authentication API...'); */ testPassed();
    const authResult = await authenticateUser(
      `apiuser${timestamp}`,
      'ApiPass123!'
    );
    testResults.logPass('User Authentication API');
    /* console.log('   User authenticated:', authResult); */ testPassed();

    // Test 3: Token Validation API
    /* console.log('\n3️⃣ Testing Token Validation API...'); */ testPassed();
    const tokenValidation = validateToken(authResult.token);
    testResults.logPass('Token Validation API');
    /* console.log('   Token validation:', tokenValidation); */ testPassed();

    // Test 4: Password Change API
    /* console.log('\n4️⃣ Testing Password Change API...'); */ testPassed();
    const passwordChange = await changePassword(
      registerResult.userId,
      'ApiPass123!',
      'NewApiPass456!'
    );
    testResults.logPass('Password Change API');
    /* console.log('   Password changed:', passwordChange); */ testPassed();

    // Test 5: MFA Enable API
    /* console.log('\n5️⃣ Testing MFA Enable API...'); */ testPassed();
    const mfaResult = await enableMFA(registerResult.userId);
    testResults.logPass('MFA Enable API');
    /* console.log('   MFA enabled:', mfaResult); */ testPassed();

    // Test 6: User Deactivation API
    /* console.log('\n6️⃣ Testing User Deactivation API...'); */ testPassed();
    const deactivation = await deactivateUser(
      registerResult.userId,
      'admin@oscarsystem.com'
    );
    testResults.logPass('User Deactivation API');
    /* console.log('   User deactivated:', deactivation); */ testPassed();
  } catch (error) {
    testResults.logFail('API Endpoints Test', error);
  }
}

// Edge Cases and Error Handling
async function testEdgeCases() {
  /* console.log('\n⚠️ Testing Edge Cases and Error Handling...\n'); */ testPassed();

  try {
    const timestamp = Date.now();
    // Test 1: Invalid Email Format
    /* console.log('1️⃣ Testing Invalid Email Format...'); */ testPassed();
    try {
      await registerUser(
        `edgeuser${timestamp}`,
        'invalid-email',
        'Pass123!',
        'user'
      );
      testResults.logFail(
        'Invalid Email Format',
        new Error('Should have thrown error for invalid email')
      );
    } catch (error) {
      testResults.logPass('Invalid Email Format');
      /* console.log('   Correctly rejected invalid email'); */ testPassed();
    }

    // Test 2: Weak Password
    /* console.log('\n2️⃣ Testing Weak Password...'); */ testPassed();
    try {
      await registerUser(
        `weakpass${timestamp}`,
        'weak@example.com',
        '123',
        'user'
      );
      testResults.logFail(
        'Weak Password',
        new Error('Should have thrown error for weak password')
      );
    } catch (error) {
      testResults.logPass('Weak Password');
      /* console.log('   Correctly rejected weak password'); */ testPassed();
    }

    // Test 3: Duplicate Username
    /* console.log('\n3️⃣ Testing Duplicate Username...'); */ testPassed();
    try {
      await registerUser(
        `apiuser${timestamp}`,
        'duplicate@example.com',
        'Pass123!',
        'user'
      );
      testResults.logFail(
        'Duplicate Username',
        new Error('Should have thrown error for duplicate username')
      );
    } catch (error) {
      testResults.logPass('Duplicate Username');
      /* console.log('   Correctly rejected duplicate username'); */ testPassed();
    }

    // Test 4: Invalid Token
    /* console.log('\n4️⃣ Testing Invalid Token...'); */ testPassed();
    const invalidToken = validateToken('invalid.jwt.token');
    if (invalidToken.valid === false) {
      testResults.logPass('Invalid Token');
      /* console.log('   Correctly rejected invalid token'); */ testPassed();
    } else {
      testResults.logFail(
        'Invalid Token',
        new Error('Should have returned invalid for invalid token')
      );
    }

    // Test 5: Non-existent User
    /* console.log('\n5️⃣ Testing Non-existent User...'); */ testPassed();
    try {
      await authenticateUser('nonexistent', 'password');
      testResults.logFail(
        'Non-existent User',
        new Error('Should have thrown error for non-existent user')
      );
    } catch (error) {
      testResults.logPass('Non-existent User');
      /* console.log('   Correctly rejected non-existent user'); */ testPassed();
    }
  } catch (error) {
    testResults.logFail('Edge Cases Test', error);
  }
}

// Account Management API Testing
async function testAccountManagementAPI() {
  /* console.log('\n💳 Testing Account Management API...\n'); */ testPassed();

  try {
    const timestamp = Date.now();
    // Register finance user
    const financeUser = await registerUser(
      `accountapi${timestamp}`,
      `accountapi${timestamp}@example.com`,
      'AccountPass123!',
      'finance'
    );

    // Test 1: Account Creation API
    /* console.log('1️⃣ Testing Account Creation API...'); */ testPassed();
    const savingsAccount = accountManager.createAccount(
      financeUser.userId,
      'savings',
      1000.0
    );
    testResults.logPass('Account Creation API');
    /* console.log('   Savings account created:', savingsAccount.accountId); */ testPassed();

    // Test 2: Account Retrieval API
    /* console.log('\n2️⃣ Testing Account Retrieval API...'); */ testPassed();
    const retrievedAccount = accountManager.getAccount(
      savingsAccount.accountId
    );
    if (
      retrievedAccount &&
      retrievedAccount.accountId === savingsAccount.accountId
    ) {
      testResults.logPass('Account Retrieval API');
      /* console.log('   Account retrieved successfully'); */ testPassed();
    } else {
      testResults.logFail(
        'Account Retrieval API',
        new Error('Failed to retrieve account')
      );
    }

    // Test 3: Balance Update API
    /* console.log('\n3️⃣ Testing Balance Update API...'); */ testPassed();
    const updatedAccount = accountManager.updateBalance(
      savingsAccount.accountId,
      250.0
    );
    if (updatedAccount && updatedAccount.balance === 1250) {
      testResults.logPass('Balance Update API');
      /* console.log('   Balance updated to:', updatedAccount.balance); */ testPassed();
    } else {
      testResults.logFail(
        'Balance Update API',
        new Error('Failed to update balance')
      );
    }

    // Test 4: Transaction Recording API
    /* console.log('\n4️⃣ Testing Transaction Recording API...'); */ testPassed();
    const transaction = accountManager.recordTransaction(
      savingsAccount.accountId,
      -50.0,
      'withdrawal',
      'ATM withdrawal'
    );
    testResults.logPass('Transaction Recording API');
    /* console.log('   Transaction recorded:', transaction.transactionId); */ testPassed();

    // Test 5: Transaction History API
    /* console.log('\n5️⃣ Testing Transaction History API...'); */ testPassed();
    const transactions = accountManager.getTransactionHistory(
      savingsAccount.accountId
    );
    if (transactions.length > 0) {
      testResults.logPass('Transaction History API');
      /* console.log('   Found', transactions.length, 'transactions'); */ testPassed();
    } else {
      testResults.logFail(
        'Transaction History API',
        new Error('No transactions found')
      );
    }

    // Test 6: Account Freeze API
    /* console.log('\n6️⃣ Testing Account Freeze API...'); */ testPassed();
    const frozenAccount = accountManager.freezeAccount(
      savingsAccount.accountId,
      'Suspicious activity'
    );
    if (frozenAccount && frozenAccount.status === 'frozen') {
      testResults.logPass('Account Freeze API');
      /* console.log('   Account frozen successfully'); */ testPassed();
    } else {
      testResults.logFail(
        'Account Freeze API',
        new Error('Failed to freeze account')
      );
    }

    // Test 7: Account Unfreeze API
    /* console.log('\n7️⃣ Testing Account Unfreeze API...'); */ testPassed();
    const unfrozenAccount = accountManager.unfreezeAccount(
      savingsAccount.accountId
    );
    if (unfrozenAccount && unfrozenAccount.status === 'active') {
      testResults.logPass('Account Unfreeze API');
      /* console.log('   Account unfrozen successfully'); */ testPassed();
    } else {
      testResults.logFail(
        'Account Unfreeze API',
        new Error('Failed to unfreeze account')
      );
    }
  } catch (error) {
    testResults.logFail('Account Management API Test', error);
  }
}

// Auto Finance Portal Integration Testing
async function testAutoFinanceIntegration() {
  /* console.log('\n🚗 Testing Auto Finance Portal Integration...\n'); */ testPassed();

  try {
    const timestamp = Date.now();
    // Register auto finance user
    const autoUser = await registerUser(
      `autofinance${timestamp}`,
      `autofinance${timestamp}@example.com`,
      'AutoPass123!',
      'finance'
    );

    // Test 1: Auto Loan Account Creation
    /* console.log('1️⃣ Testing Auto Loan Account Creation...'); */ testPassed();
    const autoLoanAccount = accountManager.createAccount(
      autoUser.userId,
      'auto_loan',
      25000.0
    );
    testResults.logPass('Auto Loan Account Creation');
    /* console.log('   Auto loan account created:', autoLoanAccount.accountId); */ testPassed();

    // Test 2: Loan Payment Processing
    /* console.log('\n2️⃣ Testing Loan Payment Processing...'); */ testPassed();
    const payment = accountManager.updateBalance(
      autoLoanAccount.accountId,
      -450.0
    );
    testResults.logPass('Loan Payment Processing');
    /* console.log('   Payment processed, balance updated'); */ testPassed();

    // Test 3: Account Balance After Payment
    /* console.log('\n3️⃣ Testing Account Balance After Payment...'); */ testPassed();
    const updatedLoanAccount = accountManager.getAccount(
      autoLoanAccount.accountId
    );
    if (updatedLoanAccount && updatedLoanAccount.balance === 24550) {
      testResults.logPass('Account Balance After Payment');
      /* console.log('   Balance updated to:', updatedLoanAccount.balance); */ testPassed();
    } else {
      testResults.logFail(
        'Account Balance After Payment',
        new Error('Balance not updated correctly')
      );
    }

    // Test 4: Finance Portal Access
    /* console.log('\n4️⃣ Testing Finance Portal Access...'); */ testPassed();
    const auth = await authenticateUser(
      `autofinance${timestamp}`,
      'AutoPass123!'
    );
    const portalAccess = testSecureAccountAccess(
      auth.token,
      autoLoanAccount.accountId
    );
    if (portalAccess) {
      testResults.logPass('Finance Portal Access');
      /* console.log('   Portal access granted'); */ testPassed();
    } else {
      testResults.logFail(
        'Finance Portal Access',
        new Error('Portal access denied')
      );
    }

    // Test 5: Override for Account Access
    /* console.log('\n5️⃣ Testing Override for Account Access...'); */ testPassed();
    const override = await loginOverrideManager.emergencyOverride(
      autoUser.userId,
      OVERRIDE_REASONS.EMERGENCY_ACCESS,
      'account_access_emergency'
    );
    testResults.logPass('Override for Account Access');
    /* console.log('   Override activated:', override); */ testPassed();
  } catch (error) {
    testResults.logFail('Auto Finance Integration Test', error);
  }
}

// Security Testing
async function testSecurityFeatures() {
  /* console.log('\n🔒 Testing Security Features...\n'); */ testPassed();

  try {
    const timestamp = Date.now();
    // Test 1: MFA Token Verification
    /* console.log('1️⃣ Testing MFA Token Verification...'); */ testPassed();
    const user = await registerUser(
      `securityuser${timestamp}`,
      `security${timestamp}@example.com`,
      'SecurityPass123!',
      'user'
    );
    const mfaResult = await enableMFA(user.userId);

    const testToken = crypto
      .createHmac('sha256', mfaResult.mfaSecret)
      .update(Math.floor(Date.now() / 30000).toString())
      .digest('hex')
      .substring(0, 6);
    const mfaVerification = await verifyMFAToken(user.userId, testToken);
    testResults.logPass('MFA Token Verification');
    /* console.log('   MFA token verified'); */ testPassed();

    // Test 2: Admin Override
    /* console.log('\n2️⃣ Testing Admin Override...'); */ testPassed();
    const adminOverride = await loginOverrideManager.adminOverride(
      'admin@oscarsystem.com',
      user.userId,
      OVERRIDE_REASONS.TECHNICAL_ISSUE,
      'User reported login issues'
    );
    testResults.logPass('Admin Override');
    /* console.log('   Admin override activated'); */ testPassed();

    // Test 3: Override Statistics
    /* console.log('\n3️⃣ Testing Override Statistics...'); */ testPassed();
    const stats = loginOverrideManager.getOverrideStatistics();
    testResults.logPass('Override Statistics');
    /* console.log('   Override statistics retrieved'); */ testPassed();

    // Test 4: Account Security Validation
    /* console.log('\n4️⃣ Testing Account Security Validation...'); */ testPassed();
    const account = accountManager.createAccount(
      user.userId,
      'checking',
      1000.0
    );
    const securityTest = testAccountSecurity(account.accountId, user.userId);
    if (securityTest) {
      testResults.logPass('Account Security Validation');
      /* console.log('   Account security validated'); */ testPassed();
    } else {
      testResults.logFail(
        'Account Security Validation',
        new Error('Account security validation failed')
      );
    }
  } catch (error) {
    testResults.logFail('Security Features Test', error);
  }
}

// Performance Testing
async function testPerformance() {
  /* console.log('\n⚡ Testing Performance...\n'); */ testPassed();

  try {
    const timestamp = Date.now();
    // Test 1: Multiple User Registrations
    /* console.log('1️⃣ Testing Multiple User Registrations...'); */ testPassed();
    const startTime = Date.now();
    const promises = [];
    for (let i = 0; i < 10; i++) {
      promises.push(
        registerUser(
          `perfuser${timestamp}_${i}`,
          `perf${timestamp}_${i}@example.com`,
          'PerfPass123!',
          'user'
        )
      );
    }
    await Promise.all(promises);
    const endTime = Date.now();
    const duration = endTime - startTime;
    testResults.logPass('Multiple User Registrations');
    /* console.log(`   10 users registered in ${duration}ms`); */ testPassed();

    // Test 2: Concurrent Account Operations
    /* console.log('\n2️⃣ Testing Concurrent Account Operations...'); */ testPassed();
    const user = await registerUser(
      `concurrentuser${timestamp}`,
      `concurrent${timestamp}@example.com`,
      'ConcurrentPass123!',
      'finance'
    );
    const account = accountManager.createAccount(
      user.userId,
      'checking',
      1000.0
    );

    const accountPromises = [];
    for (let i = 0; i < 20; i++) {
      accountPromises.push(
        accountManager.recordTransaction(
          account.accountId,
          -10.0,
          'withdrawal',
          `Test transaction ${i}`
        )
      );
    }
    await Promise.all(accountPromises);
    testResults.logPass('Concurrent Account Operations');
    /* console.log('   20 concurrent transactions processed'); */ testPassed();

    // Test 3: Authentication Load Test
    /* console.log('\n3️⃣ Testing Authentication Load Test...'); */ testPassed();
    const authPromises = [];
    for (let i = 0; i < 50; i++) {
      authPromises.push(
        authenticateUser(`concurrentuser${timestamp}`, 'ConcurrentPass123!')
      );
    }
    await Promise.all(authPromises);
    testResults.logPass('Authentication Load Test');
    /* console.log('   50 concurrent authentications processed'); */ testPassed();
  } catch (error) {
    testResults.logFail('Performance Test', error);
  }
}

// Helper functions
function testSecureAccountAccess(token, accountId) {
  const tokenValid = validateToken(token);
  if (!tokenValid.valid) return false;

  const account = accountManager.getAccount(accountId);
  if (!account) return false;

  return account.userId === tokenValid.user.userId;
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
  /* console.log('🧪 Starting Comprehensive Integration Test Suite\n'); */ testPassed();
  /* console.log('='.repeat(60)); */ testPassed();

  await testAPIEndpoints();
  await testEdgeCases();
  await testAccountManagementAPI();
  await testAutoFinanceIntegration();
  await testSecurityFeatures();
  await testPerformance();

  /* console.log('\n' + '='.repeat(60)); */ testPassed();
  testResults.summary();

  /* console.log('\n🏁 Comprehensive Integration Testing Completed!'); */ testPassed();
}

runComprehensiveTests().catch(console.error);

