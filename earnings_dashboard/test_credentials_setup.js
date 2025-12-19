// Test credentials setup for development - DO NOT USE IN PRODUCTION
// This creates sample JPMorgan credentials for testing the wallet system

import { execSync } from 'node:child_process';
import os from 'node:os';

console.log('Setting up TEST JPMorgan credentials for development...');
console.log('⚠️  WARNING: These are SAMPLE credentials for testing only!');
console.log('   Replace with real credentials for production use.\n');

// Sample test credentials (replace with real ones)
const testCredentials = {
  clientId: 'test-client-id-12345',
  clientSecret: 'test-client-secret-abcdef123456',
  merchantId: 'test-merchant-67890',
  terminalId: 'test-terminal-99999',
  organizationId: 'test-org-11111',
  projectId: 'test-project-22222',
};

try {
  // Set environment variables based on OS
  if (os.platform() === 'win32') {
    // Windows
    execSync(`setx JPMORGAN_CLIENT_ID "${testCredentials.clientId}"`, {
      stdio: 'inherit',
    });
    execSync(`setx JPMORGAN_CLIENT_SECRET "${testCredentials.clientSecret}"`, {
      stdio: 'inherit',
    });
    execSync(`setx JPMORGAN_MERCHANT_ID "${testCredentials.merchantId}"`, {
      stdio: 'inherit',
    });
    execSync(`setx JPMORGAN_TERMINAL_ID "${testCredentials.terminalId}"`, {
      stdio: 'inherit',
    });
    execSync(
      `setx JPMORGAN_ORGANIZATION_ID "${testCredentials.organizationId}"`,
      { stdio: 'inherit' }
    );
    execSync(`setx JPMORGAN_PROJECT_ID "${testCredentials.projectId}"`, {
      stdio: 'inherit',
    });
  } else {
    // Linux/macOS
    execSync(`export JPMORGAN_CLIENT_ID="${testCredentials.clientId}"`, {
      stdio: 'inherit',
    });
    execSync(
      `export JPMORGAN_CLIENT_SECRET="${testCredentials.clientSecret}"`,
      { stdio: 'inherit' }
    );
    execSync(`export JPMORGAN_MERCHANT_ID="${testCredentials.merchantId}"`, {
      stdio: 'inherit',
    });
    execSync(`export JPMORGAN_TERMINAL_ID="${testCredentials.terminalId}"`, {
      stdio: 'inherit',
    });
    execSync(
      `export JPMORGAN_ORGANIZATION_ID="${testCredentials.organizationId}"`,
      { stdio: 'inherit' }
    );
    execSync(`export JPMORGAN_PROJECT_ID="${testCredentials.projectId}"`, {
      stdio: 'inherit',
    });
  }

  console.log('✅ Test credentials configured successfully!');
  console.log('\nConfigured TEST credentials:');
  console.log(`  JPMORGAN_CLIENT_ID: ${testCredentials.clientId}`);
  console.log(`  JPMORGAN_CLIENT_SECRET: [HIDDEN]`);
  console.log(`  JPMORGAN_MERCHANT_ID: ${testCredentials.merchantId}`);
  console.log(`  JPMORGAN_TERMINAL_ID: ${testCredentials.terminalId}`);
  console.log(`  JPMORGAN_ORGANIZATION_ID: ${testCredentials.organizationId}`);
  console.log(`  JPMORGAN_PROJECT_ID: ${testCredentials.projectId}`);
  console.log(
    '\n⚠️  REMINDER: Replace these with real JPMorgan credentials for production!'
  );
  console.log('\n🔄 Restart your server/IDE to apply the changes.');
} catch (error) {
  console.error('❌ Failed to set test credentials:', error.message);
  process.exit(1);
}
