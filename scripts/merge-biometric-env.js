/**
 * Merge Biometric Configuration into .env
 * Safely adds biometric environment variables to existing .env file
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

logger.info('🔧 MERGING BIOMETRIC CONFIGURATION INTO .ENV\n');
logger.info('='.repeat(60));

const envPath = path.join(__dirname, '..', '.env');
const biometricConfigPath = path.join(
  __dirname,
  '..',
  '.env.biometric.configured'
);

// Check if files exist
if (!fs.existsSync(biometricConfigPath)) {
  logger.info('❌ ERROR: .env.biometric.configured not found!');
  logger.info('   Run: node scripts/setup-biometric-env.js first\n');
  process.exit(1);
}

logger.info('✅ Found .env.biometric.configured\n');

// Read biometric configuration
const biometricConfig = fs.readFileSync(biometricConfigPath, 'utf-8');

// Extract only the biometric-specific variables
const biometricVars = [];
const lines = biometricConfig.split('\n');
let inBiometricSection = false;

for (const line of lines) {
  if (
    line.includes('MONGODB CONFIGURATION') ||
    line.includes('BIOMETRIC SECURITY CONFIGURATION') ||
    line.includes('BLOCKCHAIN CONFIGURATION')
  ) {
    inBiometricSection = true;
  }

  if (line.includes('SERVER CONFIGURATION')) {
    inBiometricSection = false;
  }

  if (inBiometricSection && line.trim() && !line.startsWith('#')) {
    biometricVars.push(line);
  }
}

logger.info(
  `📋 Found ${biometricVars.length} biometric configuration variables\n`
);

// Read existing .env or create new one
let existingEnv = '';
if (fs.existsSync(envPath)) {
  existingEnv = fs.readFileSync(envPath, 'utf-8');
  logger.info('✅ Existing .env file found\n');
} else {
  logger.info('ℹ️  No existing .env file - creating new one\n');
}

// Check which variables already exist
const existingVarNames = new Set();
for (const line of existingEnv.split('\n')) {
  if (line.trim() && !line.startsWith('#')) {
    const varName = line.split('=')[0].trim();
    existingVarNames.add(varName);
  }
}

// Prepare new variables to add
const varsToAdd = [];
const varsToSkip = [];

for (const varLine of biometricVars) {
  const varName = varLine.split('=')[0].trim();
  if (existingVarNames.has(varName)) {
    varsToSkip.push(varName);
  } else {
    varsToAdd.push(varLine);
  }
}

logger.info('📊 Merge Analysis:\n');
logger.info(`   Variables to add: ${varsToAdd.length}`);
logger.info(`   Variables to skip (already exist): ${varsToSkip.length}\n`);

if (varsToSkip.length > 0) {
  logger.info('⚠️  Skipping existing variables:');
  varsToSkip.forEach((v) => logger.info(`   - ${v}`));
  logger.info('');
}

// Build new .env content
let newEnvContent = existingEnv;

if (!newEnvContent.endsWith('\n')) {
  newEnvContent += '\n';
}

newEnvContent += '\n';
newEnvContent +=
  '# ============================================================\n';
newEnvContent += '# BIOMETRIC AUTHENTICATION SYSTEM CONFIGURATION\n';
newEnvContent += '# Added by: scripts/merge-biometric-env.js\n';
newEnvContent += `# Date: ${new Date().toISOString()}\n`;
newEnvContent +=
  '# ============================================================\n';
newEnvContent += '\n';

varsToAdd.forEach((varLine) => {
  newEnvContent += varLine + '\n';
});

// Create backup of existing .env
if (fs.existsSync(envPath)) {
  const backupPath = path.join(__dirname, '..', '.env.backup');
  fs.copyFileSync(envPath, backupPath);
  logger.info('✅ Created backup: .env.backup\n');
}

// Write merged configuration
fs.writeFileSync(envPath, newEnvContent);

logger.info('✅ Successfully merged biometric configuration into .env\n');
logger.info('='.repeat(60));
logger.info('\n🎉 CONFIGURATION MERGE COMPLETE!\n');

logger.info('📝 WHAT WAS ADDED:\n');
varsToAdd.forEach((varLine) => {
  const varName = varLine.split('=')[0];
  logger.info(`   ✅ ${varName}`);
});

if (varsToSkip.length > 0) {
  logger.info('\n⚠️  VARIABLES SKIPPED (already in .env):\n');
  varsToSkip.forEach((v) => logger.info(`   - ${v}`));
}

logger.info('\n📋 NEXT STEPS:\n');
logger.info('1. Review your .env file');
logger.info('2. Update MONGODB_URI if needed');
logger.info('3. Verify all biometric settings');
logger.info('4. Start MongoDB: mongod');
logger.info('5. Start server: cd earnings_dashboard && node server.js\n');

logger.info('🔒 SECURITY REMINDER:\n');
logger.info('- Your .env file now contains secure biometric keys');
logger.info('- NEVER commit .env to version control');
logger.info('- Backup created at: .env.backup\n');

logger.info('='.repeat(60));
logger.info('\n✨ Your biometric system is configured and ready!\n');
