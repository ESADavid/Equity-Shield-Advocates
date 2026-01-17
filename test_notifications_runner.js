#!/usr/bin/env node

const { execSync } = require('child_process');
const path = require('path');

console.log('🧪 Running Merchant Notification System Tests...\n');

try {
  // Run the Jest tests
  const testCommand =
    'npx jest test_merchant_notifications.js --verbose --no-coverage';
  console.log(`Executing: ${testCommand}\n`);

  const output = execSync(testCommand, {
    cwd: __dirname,
    encoding: 'utf8',
    stdio: 'inherit',
  });

  console.log('\n✅ Tests completed successfully!');
} catch (error) {
  console.error('\n❌ Test execution failed:');
  console.error(error.message);

  if (error.stdout) {
    console.log('\nSTDOUT:');
    console.log(error.stdout);
  }

  if (error.stderr) {
    console.log('\nSTDERR:');
    console.log(error.stderr);
  }

  process.exit(1);
}
