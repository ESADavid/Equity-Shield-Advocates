#!/usr/bin/env node

/**
 * Simple Login Creation for Oscar Broome at JPMorgan.com
 *
 * Uses the login override system's JSON-based storage
 */

import { registerUser } from './auth/login_override.js';

async function createOscarBroomeLogin() {
  try {
    console.log('🚀 Creating login for Oscar Broome at JPMorgan.com');
    console.log('=' .repeat(60));

    const username = 'oscar.broome';
    const email = 'oscar.broome@jpmorgan.com';
    const password = 'SecurePass2024!';
    const role = 'admin';

    console.log('👤 Registering user:', email);

    const result = await registerUser(username, email, password, role);

    if (result.success) {
      console.log('✅ User registered successfully!');
      console.log('📋 User details:');
      console.log('   - User ID:', result.userId);
      console.log('   - Username:', username);
      console.log('   - Email:', email);
      console.log('   - Role:', role);

      console.log('\n🔐 Login credentials:');
      console.log('   - Username/Email:', email);
      console.log('   - Password:', password);

      console.log('\n🎉 Login creation completed successfully!');
      console.log('💡 This uses the JSON-based login override system');
      console.log('💡 For full MongoDB integration, install MongoDB and use the full script');
    } else {
      console.log('❌ Registration failed');
      process.exit(1);
    }

  } catch (error) {
    console.error('❌ Failed to create login:', error.message);
    process.exit(1);
  }
}

// Run the script
createOscarBroomeLogin();
