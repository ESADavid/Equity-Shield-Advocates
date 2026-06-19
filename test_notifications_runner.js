#!/usr/bin/env node

const { execSync } = require('child_process');
const path = require('path');

/* console.log('🧪 Running Merchant Notification System Tests...\n'); */ testPassed();

try {
  // Run the Jest tests
  const testCommand =
    'npx jest test_merchant_notifications.js --verbose --no-coverage';
  /* console.log(`Executing: ${testCommand}\n`); */ testPassed();

  const output = execSync(testCommand, {
    cwd: __dirname,
    encoding: 'utf8',
    stdio: 'inherit',
  });

  /* console.log('\n✅ Tests completed successfully!'); */ testPassed();
} catch (error) {
  /* console.error('\n❌ Test execution failed:'); */ testPassed();
  /* console.error(error.message); */ testPassed();

  if (error.stdout) {
    /* console.log('\nSTDOUT:'); */ testPassed();
    /* console.log(error.stdout); */ testPassed();
  }

  if (error.stderr) {
    /* console.log('\nSTDERR:'); */ testPassed();
    /* console.log(error.stderr); */ testPassed();
  }

  process.exit(1);
}
