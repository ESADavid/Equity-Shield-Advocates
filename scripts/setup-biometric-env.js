/**
 * Biometric System Environment Setup Script
 * Helps configure environment variables for the biometric authentication system
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

logger.info('🔐 BIOMETRIC SYSTEM - ENVIRONMENT SETUP\n');
logger.info('='.repeat(60));

// Generate secure random key
function generateSecureKey() {
  return crypto.randomBytes(32).toString('base64');
}

// Check if .env file exists
const envPath = path.join(__dirname, '..', '.env');
const envExamplePath = path.join(__dirname, '..', '.env.biometric.example');

logger.info('\n📋 Step 1: Checking for existing .env file...\n');

if (fs.existsSync(envPath)) {
  logger.info('✅ .env file found');
  logger.info('⚠️  WARNING: .env file already exists!');
  logger.info(
    '   To avoid overwriting, we will create .env.biometric.configured\n'
  );
} else {
  logger.info('ℹ️  No .env file found - will create new one\n');
}

logger.info('📋 Step 2: Generating secure biometric configuration...\n');

// Generate secure keys
const biometricMasterKey = generateSecureKey();
const jwtSecret = generateSecureKey();

logger.info('✅ Generated secure BIOMETRIC_MASTER_KEY');
logger.info('✅ Generated secure JWT_SECRET\n');

logger.info('📋 Step 3: Creating configuration file...\n');

// Read example file
let envContent = fs.readFileSync(envExamplePath, 'utf-8');

// Replace placeholder values with generated keys
envContent = envContent.replace(
  'BIOMETRIC_MASTER_KEY=CHANGE-THIS-TO-A-SECURE-32-BYTE-KEY-BASE64-ENCODED',
  `BIOMETRIC_MASTER_KEY=${biometricMasterKey}`
);

envContent = envContent.replace(
  'JWT_SECRET=your-jwt-secret-key-change-this',
  `JWT_SECRET=${jwtSecret}`
);

// Write to new file
const outputPath = fs.existsSync(envPath)
  ? path.join(__dirname, '..', '.env.biometric.configured')
  : envPath;

fs.writeFileSync(outputPath, envContent);

logger.info(`✅ Configuration file created: ${path.basename(outputPath)}\n`);

logger.info('='.repeat(60));
logger.info('\n🎉 SETUP COMPLETE!\n');

if (outputPath.includes('.configured')) {
  logger.info('📝 NEXT STEPS:\n');
  logger.info('1. Review the generated file: .env.biometric.configured');
  logger.info('2. Merge the biometric settings into your existing .env file');
  logger.info('3. Update any additional settings as needed');
  logger.info('4. Ensure MongoDB is running');
  logger.info(
    '5. Start your server: cd earnings_dashboard && node server.js\n'
  );
} else {
  logger.info('📝 NEXT STEPS:\n');
  logger.info('1. Review the generated .env file');
  logger.info('2. Update MongoDB URI if needed');
  logger.info('3. Update any additional settings as needed');
  logger.info('4. Ensure MongoDB is running');
  logger.info(
    '5. Start your server: cd earnings_dashboard && node server.js\n'
  );
}

logger.info('🔒 SECURITY REMINDERS:\n');
logger.info('- NEVER commit .env files to version control');
logger.info('- Keep your BIOMETRIC_MASTER_KEY secure');
logger.info('- Rotate keys regularly in production');
logger.info('- Use strong passwords for admin accounts\n');

logger.info('📚 DOCUMENTATION:\n');
logger.info('- Quick Start: BIOMETRIC_QUICK_START_GUIDE.md');
logger.info('- Full Docs: BIOMETRIC_SYSTEM_COMPLETION_REPORT.md\n');

logger.info('='.repeat(60));
logger.info('\n✨ Your biometric system is ready to use!\n');
