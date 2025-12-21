/**
 * Merge Biometric Configuration into .env
 * Safely adds biometric environment variables to existing .env file
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('🔧 MERGING BIOMETRIC CONFIGURATION INTO .ENV\n');
console.log('=' .repeat(60));

const envPath = path.join(__dirname, '..', '.env');
const biometricConfigPath = path.join(__dirname, '..', '.env.biometric.configured');

// Check if files exist
if (!fs.existsSync(biometricConfigPath)) {
  console.log('❌ ERROR: .env.biometric.configured not found!');
  console.log('   Run: node scripts/setup-biometric-env.js first\n');
  process.exit(1);
}

console.log('✅ Found .env.biometric.configured\n');

// Read biometric configuration
const biometricConfig = fs.readFileSync(biometricConfigPath, 'utf-8');

// Extract only the biometric-specific variables
const biometricVars = [];
const lines = biometricConfig.split('\n');
let inBiometricSection = false;

for (const line of lines) {
  if (line.includes('MONGODB CONFIGURATION') || 
      line.includes('BIOMETRIC SECURITY CONFIGURATION') ||
      line.includes('BLOCKCHAIN CONFIGURATION')) {
    inBiometricSection = true;
  }
  
  if (line.includes('SERVER CONFIGURATION')) {
    inBiometricSection = false;
  }
  
  if (inBiometricSection && line.trim() && !line.startsWith('#')) {
    biometricVars.push(line);
  }
}

console.log(`📋 Found ${biometricVars.length} biometric configuration variables\n`);

// Read existing .env or create new one
let existingEnv = '';
if (fs.existsSync(envPath)) {
  existingEnv = fs.readFileSync(envPath, 'utf-8');
  console.log('✅ Existing .env file found\n');
} else {
  console.log('ℹ️  No existing .env file - creating new one\n');
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

console.log('📊 Merge Analysis:\n');
console.log(`   Variables to add: ${varsToAdd.length}`);
console.log(`   Variables to skip (already exist): ${varsToSkip.length}\n`);

if (varsToSkip.length > 0) {
  console.log('⚠️  Skipping existing variables:');
  varsToSkip.forEach(v => console.log(`   - ${v}`));
  console.log('');
}

// Build new .env content
let newEnvContent = existingEnv;

if (!newEnvContent.endsWith('\n')) {
  newEnvContent += '\n';
}

newEnvContent += '\n';
newEnvContent += '# ============================================================\n';
newEnvContent += '# BIOMETRIC AUTHENTICATION SYSTEM CONFIGURATION\n';
newEnvContent += '# Added by: scripts/merge-biometric-env.js\n';
newEnvContent += `# Date: ${new Date().toISOString()}\n`;
newEnvContent += '# ============================================================\n';
newEnvContent += '\n';

varsToAdd.forEach(varLine => {
  newEnvContent += varLine + '\n';
});

// Create backup of existing .env
if (fs.existsSync(envPath)) {
  const backupPath = path.join(__dirname, '..', '.env.backup');
  fs.copyFileSync(envPath, backupPath);
  console.log('✅ Created backup: .env.backup\n');
}

// Write merged configuration
fs.writeFileSync(envPath, newEnvContent);

console.log('✅ Successfully merged biometric configuration into .env\n');
console.log('=' .repeat(60));
console.log('\n🎉 CONFIGURATION MERGE COMPLETE!\n');

console.log('📝 WHAT WAS ADDED:\n');
varsToAdd.forEach(varLine => {
  const varName = varLine.split('=')[0];
  console.log(`   ✅ ${varName}`);
});

if (varsToSkip.length > 0) {
  console.log('\n⚠️  VARIABLES SKIPPED (already in .env):\n');
  varsToSkip.forEach(v => console.log(`   - ${v}`));
}

console.log('\n📋 NEXT STEPS:\n');
console.log('1. Review your .env file');
console.log('2. Update MONGODB_URI if needed');
console.log('3. Verify all biometric settings');
console.log('4. Start MongoDB: mongod');
console.log('5. Start server: cd earnings_dashboard && node server.js\n');

console.log('🔒 SECURITY REMINDER:\n');
console.log('- Your .env file now contains secure biometric keys');
console.log('- NEVER commit .env to version control');
console.log('- Backup created at: .env.backup\n');

console.log('=' .repeat(60));
console.log('\n✨ Your biometric system is configured and ready!\n');
