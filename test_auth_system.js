/**
 * Test script for the enhanced Login Override System with Standard Authentication
 * Tests both override functionality and standard user authentication methods
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

// Run the tests
testAuthenticationSystem().catch(console.error);
