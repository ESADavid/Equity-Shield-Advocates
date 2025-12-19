#!/usr/bin/env node

/**
 * Fix .env File Encoding
 * Converts .env from UTF-16 to UTF-8
 *
 * OSCAR BROOME REVENUE - OWLBAN GROUP
 */

const fs = require('fs');
const path = require('path');

console.log('🔧 OSCAR BROOME REVENUE - Fix .env Encoding');
console.log('='.repeat(50));

const envPath = path.join(process.cwd(), '.env');
const backupPath = path.join(process.cwd(), '.env.backup');

try {
  // Check if .env exists
  if (!fs.existsSync(envPath)) {
    console.error('❌ Error: .env file not found');
    process.exit(1);
  }

  console.log('📄 Reading .env file...');

  // Read the file with UTF-16 encoding
  let content;
  try {
    content = fs.readFileSync(envPath, 'utf16le');
  } catch (err) {
    // If UTF-16 fails, try UTF-8 (maybe already fixed)
    content = fs.readFileSync(envPath, 'utf8');
    console.log('✅ File is already UTF-8 encoded');
    process.exit(0);
  }

  // Create backup
  console.log('💾 Creating backup at .env.backup...');
  fs.copyFileSync(envPath, backupPath);

  // Write with UTF-8 encoding
  console.log('✍️  Writing UTF-8 encoded file...');
  fs.writeFileSync(envPath, content, 'utf8');

  // Verify
  console.log('🔍 Verifying encoding...');
  const verifyContent = fs.readFileSync(envPath, 'utf8');

  if (verifyContent === content) {
    console.log('✅ SUCCESS: .env file converted to UTF-8');
    console.log('📦 Backup saved at: .env.backup');
    console.log('');
    console.log('Next steps:');
    console.log('1. Test deployment: node scripts/execute-phase5-staging.cjs');
    console.log('2. If successful, delete backup: del .env.backup');
  } else {
    console.error('❌ Verification failed - restoring backup');
    fs.copyFileSync(backupPath, envPath);
    process.exit(1);
  }
} catch (error) {
  console.error('❌ Error:', error.message);

  // Restore backup if it exists
  if (fs.existsSync(backupPath)) {
    console.log('🔄 Restoring backup...');
    fs.copyFileSync(backupPath, envPath);
  }

  process.exit(1);
}
