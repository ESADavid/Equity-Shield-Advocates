#!/usr/bin/env node

/**
 * Create Login for Oscar Broome at JPMorgan.com
 *
 * This script registers Oscar Broome as a user in the system
 * with email oscar.broome@jpmorgan.com
 */

import mongoose from 'mongoose';
import authService from './services/authService.js';
import Tenant from './models/Tenant.js';
import winston from 'winston';

// Logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'create-oscar-broome-login' },
  transports: [
    new winston.transports.File({
      filename: 'logs/create_oscar_broome_login.log',
    }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
  ],
});

async function createOscarBroomeLogin() {
  try {
    console.log('🚀 Creating login for Oscar Broome at JPMorgan.com');
    console.log('='.repeat(60));

    // Connect to database
    const dbUri =
      process.env.MONGODB_URI ||
      process.env.DATABASE_URL ||
      'mongodb://localhost:27017/oscar-broome-revenue';
    await mongoose.connect(dbUri);
    console.log('✅ Connected to database');

    // Ensure default tenant exists
    let tenant = await Tenant.findOne({ tenantId: 'default' });
    if (!tenant) {
      console.log('📝 Creating default tenant...');
      tenant = await Tenant.createDefaultTenant();
      console.log('✅ Default tenant created');
    }

    // User data for Oscar Broome
    const userData = {
      tenantId: tenant.tenantId,
      username: 'oscar.broome',
      email: 'oscar.broome@jpmorgan.com',
      password: 'SecurePass2024!', // Strong password
      firstName: 'Oscar',
      lastName: 'Broome',
      role: 'admin', // Admin role for JPMorgan access
    };

    console.log('👤 Registering user:', userData.email);

    // Check if user already exists
    const existingUser = await mongoose.model('User').findOne({
      tenantId: userData.tenantId,
      $or: [{ email: userData.email }, { username: userData.username }],
    });

    if (existingUser) {
      console.log('⚠️  User already exists:', existingUser.email);
      console.log('📋 User details:');
      console.log('   - ID:', existingUser._id);
      console.log('   - Username:', existingUser.username);
      console.log('   - Email:', existingUser.email);
      console.log('   - Role:', existingUser.role);
      console.log('   - Active:', existingUser.isActive);
      return;
    }

    // Register the user
    const result = await authService.register(userData);

    console.log('✅ User registered successfully!');
    console.log('📋 User details:');
    console.log('   - ID:', result.user._id);
    console.log('   - Username:', result.user.username);
    console.log('   - Email:', result.user.email);
    console.log('   - Role:', result.user.role);
    console.log('   - Full Name:', result.user.fullName);

    console.log('\n🔐 Login credentials:');
    console.log('   - Username/Email:', userData.email);
    console.log('   - Password:', userData.password);
    console.log('   - Role:', userData.role);

    console.log('\n🔑 JWT Tokens generated:');
    console.log(
      '   - Access Token:',
      result.tokens.accessToken.substring(0, 50) + '...'
    );
    console.log(
      '   - Refresh Token:',
      result.tokens.refreshToken.substring(0, 50) + '...'
    );
    console.log('   - Expires In:', result.tokens.expiresIn);

    // Log success
    logger.info('Oscar Broome login created successfully', {
      userId: result.user._id,
      email: userData.email,
      tenantId: userData.tenantId,
    });

    console.log('\n🎉 Login creation completed successfully!');
    console.log('💡 Next steps:');
    console.log('   1. Use the credentials above to login');
    console.log('   2. Change the password after first login');
    console.log('   3. Configure additional security settings if needed');
  } catch (error) {
    console.error('❌ Failed to create Oscar Broome login:', error.message);
    logger.error('Login creation failed', {
      error: error.message,
      stack: error.stack,
    });
    process.exit(1);
  } finally {
    await mongoose.disconnect();
    console.log('📪 Database connection closed');
  }
}

// Run the script
createOscarBroomeLogin().catch((error) => {
  console.error('Script execution failed:', error);
  process.exit(1);
});

export { createOscarBroomeLogin };
