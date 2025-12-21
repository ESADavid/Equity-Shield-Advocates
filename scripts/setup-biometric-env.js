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

console.log('🔐 BIOMETRIC SYSTEM - ENVIRONMENT SETUP\n');
console.log('=' .repeat(60));

// Generate secure random key
function generateSecureKey() {
  return crypto.randomBytes(32).toString('base64');
}

// Check if .env file exists
const envPath = path.join(__dirname, '..', '.env');
const envExamplePath = path.join(__dirname, '..', '.env.biometric.example');

console.log('\n📋 Step 1: Checking for existing .env file...\n');

if (fs.existsSync(envPath)) {
  console.log('✅ .env file found');
  console.log('⚠️  WARNING: .env file already exists!');
  console.log('   To avoid overwriting, we will create .env.biometric.configured\n');
} else {
  console.log('ℹ️  No .env file found - will create new one\n');
}

console.log('📋 Step 2: Generating secure biometric configuration...\n');

// Generate secure keys
const biometricMasterKey = generateSecureKey();
const jwtSecret = generateSecureKey();

console.log('✅ Generated secure BIOMETRIC_MASTER_KEY');
console.log('✅ Generated secure JWT_SECRET\n');

console.log('📋 Step 3: Creating configuration file...\n');

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

console.log(`✅ Configuration file created: ${path.basename(outputPath)}\n`);

console.log('=' .repeat(60));
console.log('\n🎉 SETUP COMPLETE!\n');

if (outputPath.includes('.configured')) {
  console.log('📝 NEXT STEPS:\n');
  console.log('1. Review the generated file: .env.biometric.configured');
  console.log('2. Merge the biometric settings into your existing .env file');
  console.log('3. Update any additional settings as needed');
  console.log('4. Ensure MongoDB is running');
  console.log('5. Start your server: cd earnings_dashboard && node server.js\n');
} else {
  console.log('📝 NEXT STEPS:\n');
  console.log('1. Review the generated .env file');
  console.log('2. Update MongoDB URI if needed');
  console.log('3. Update any additional settings as needed');
  console.log('4. Ensure MongoDB is running');
  console.log('5. Start your server: cd earnings_dashboard && node server.js\n');
}

console.log('🔒 SECURITY REMINDERS:\n');
console.log('- NEVER commit .env files to version control');
console.log('- Keep your BIOMETRIC_MASTER_KEY secure');
console.log('- Rotate keys regularly in production');
console.log('- Use strong passwords for admin accounts\n');

console.log('📚 DOCUMENTATION:\n');
console.log('- Quick Start: BIOMETRIC_QUICK_START_GUIDE.md');
console.log('- Full Docs: BIOMETRIC_SYSTEM_COMPLETION_REPORT.md\n');

console.log('=' .repeat(60));
console.log('\n✨ Your biometric system is ready to use!\n');
