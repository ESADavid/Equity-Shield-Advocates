#!/usr/bin/env node

/**
 * Test Oscar Broome Login
 *
 * Tests the login functionality for oscar.broome@jpmorgan.com
 */

import { authenticateUser } from './auth/login_override.js';

async function testOscarBroomeLogin() {
  try {
    console.log('🧪 Testing Oscar Broome Login');
    console.log('='.repeat(40));

    const username = 'oscar.broome';
    const password = 'SecurePass2024!';

    console.log('👤 Attempting login...');
    console.log('   Username:', username);
    console.log('   Email: oscar.broome@jpmorgan.com');

    const result = await authenticateUser(username, password);

    if (result.success) {
      console.log('✅ Login successful!');
      console.log('📋 User details:');
      console.log('   - User ID:', result.user.id);
      console.log('   - Username:', result.user.username);
      console.log('   - Email:', result.user.email);
      console.log('   - Role:', result.user.role);
      console.log('   - Last Login:', result.user.lastLogin);

      console.log('\n🔑 JWT Token generated:');
      console.log('   - Token:', result.token.substring(0, 50) + '...');

      console.log('\n🎉 Oscar Broome login test PASSED!');
      console.log('💡 The login system is working correctly.');
    } else {
      console.log('❌ Login failed');
      process.exit(1);
    }
  } catch (error) {
    console.error('❌ Login test failed:', error.message);
    process.exit(1);
  }
}

// Run the test
testOscarBroomeLogin();
