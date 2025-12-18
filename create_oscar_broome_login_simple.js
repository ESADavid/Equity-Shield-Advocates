#!/usr/bin/env node

/**
 * Simple Login Creation for Oscar Broome at JPMorgan.com
 *
 * Uses the login override system's JSON-based storage
 */

import { registerUser } from './auth/login_override.js';

async function createOscarBroomeLogin() {
  try {
    logger.info('🚀 Creating login for Oscar Broome at JPMorgan.com');
    logger.info('=' .repeat(60));

    const username = 'oscar.broome';
    const email = 'oscar.broome@jpmorgan.com';
    const password = 'SecurePass2024!';
    const role = 'admin';

    logger.info('👤 Registering user:', email);

    const result = await registerUser(username, email, password, role);

    if (result.success) {
      logger.info('✅ User registered successfully!');
      logger.info('📋 User details:');
      logger.info('   - User ID:', result.userId);
      logger.info('   - Username:', username);
      logger.info('   - Email:', email);
      logger.info('   - Role:', role);

      logger.info('\n🔐 Login credentials:');
      logger.info('   - Username/Email:', email);
      logger.info('   - Password:', password);

      logger.info('\n🎉 Login creation completed successfully!');
      logger.info('💡 This uses the JSON-based login override system');
      logger.info('💡 For full MongoDB integration, install MongoDB and use the full script');
    } else {
      logger.info('❌ Registration failed');
      process.exit(1);
    }

  } catch (error) {
    logger.error('❌ Failed to create login:', error.message);
    process.exit(1);
  }
}

// Run the script
createOscarBroomeLogin();
