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
  console.log(
    '🧪 Testing Enhanced Login Override System with Standard Authentication\n'
  );

  try {
    // Test 1: User Registration
    console.log('1️⃣ Testing User Registration...');
    const registerResult = await registerUser(
      'testuser',
      'test@example.com',
      'TestPass123!',
      'user'
    );
    console.log('✅ User registered:', registerResult);

    // Test 2: User Authentication
    console.log('\n2️⃣ Testing User Authentication...');
    const authResult = await authenticateUser('testuser', 'TestPass123!');
    console.log('✅ User authenticated:', authResult);

    // Test 3: Token Validation
    console.log('\n3️⃣ Testing Token Validation...');
    const tokenValidation = validateToken(authResult.token);
    console.log('✅ Token validation:', tokenValidation);

    // Test 4: Password Change
    console.log('\n4️⃣ Testing Password Change...');
    const passwordChange = await changePassword(
      registerResult.userId,
      'TestPass123!',
      'NewPass456!'
    );
    console.log('✅ Password changed:', passwordChange);

    // Test 5: Authentication with new password
    console.log('\n5️⃣ Testing Authentication with new password...');
    const newAuthResult = await authenticateUser('testuser', 'NewPass456!');
    console.log(
      '✅ Authentication with new password successful:',
      newAuthResult
    );

    // Test 6: MFA Enable
    console.log('\n6️⃣ Testing MFA Enable...');
    const mfaResult = await enableMFA(registerResult.userId);
    console.log('✅ MFA enabled:', mfaResult);

    // Test 7: MFA Token Verification (simplified)
    console.log('\n7️⃣ Testing MFA Token Verification...');
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
    console.log('✅ MFA token verified:', mfaVerification);

    // Test 8: Emergency Override
    console.log('\n8️⃣ Testing Emergency Override...');
    const emergencyOverride = await loginOverrideManager.emergencyOverride(
      registerResult.userId,
      OVERRIDE_REASONS.EMERGENCY_ACCESS,
      'additional_auth_code'
    );
    console.log('✅ Emergency override activated:', emergencyOverride);

    // Test 9: Admin Override
    console.log('\n9️⃣ Testing Admin Override...');
    const adminOverride = await loginOverrideManager.adminOverride(
      'admin@oscarsystem.com',
      registerResult.userId,
      OVERRIDE_REASONS.TECHNICAL_ISSUE,
      'User reported login issues, needs immediate access'
    );
    console.log('✅ Admin override activated:', adminOverride);

    // Test 10: Get Active Overrides
    console.log('\n🔟 Testing Get Active Overrides...');
    const activeOverrides = loginOverrideManager.getActiveOverrides(
      registerResult.userId
    );
    console.log('✅ Active overrides:', activeOverrides);

    // Test 11: Override Statistics
    console.log('\n1️⃣1️⃣ Testing Override Statistics...');
    const stats = loginOverrideManager.getOverrideStatistics();
    console.log('✅ Override statistics:', stats);

    // Test 12: User Deactivation
    console.log('\n1️⃣2️⃣ Testing User Deactivation...');
    const deactivation = await deactivateUser(
      registerResult.userId,
      'admin@oscarsystem.com'
    );
    console.log('✅ User deactivated:', deactivation);

    console.log('\n🎉 All authentication tests passed successfully!');
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error('Stack trace:', error.stack);
  }
}

// Run the tests
testAuthenticationSystem().catch(console.error);
