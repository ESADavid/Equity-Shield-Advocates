#!/usr/bin/env node

/**
 * JPMorgan Payment Integration Test Runner
 *
 * This script runs comprehensive tests for the JPMorgan payment integration.
 * Make sure your server is running on the configured port before running tests.
 *
 * Usage:
 *   node run_jpmorgan_tests.js
 *
 * Environment Variables:
 *   JPMORGAN_TEST_BASE_URL - Base URL for testing (default: http://localhost:3000/jpmorgan)
 */

const JPMorganTester = require('./test_jpmorgan_endpoints');

async function main() {
  console.log('🏦 JPMorgan Payment Integration Test Suite');
  console.log('==========================================\n');

  // Check if server is running
  console.log('🔍 Checking server availability...');
  const tester = new JPMorganTester();

  try {
    // Quick health check
    await tester.testHealthCheck();
    console.log('✅ Server is running and responding\n');
  } catch (error) {
    console.log('❌ Server is not responding. Please start your server first.');
    console.log(
      '   Make sure your Express server is running on the configured port.\n'
    );
    console.log('Example:');
    console.log('   cd OSCAR-BROOME-REVENUE');
    console.log('   node server.js  # or however you start your server\n');
    process.exit(1);
  }

  // Run all tests
  await tester.runAllTests();

  // Exit with appropriate code
  if (tester.testResults.failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (error) => {
  console.error('❌ Unhandled error:', error);
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught exception:', error);
  process.exit(1);
});

// Run the tests
if (require.main === module) {
  main().catch((error) => {
    console.error('❌ Test runner failed:', error);
    process.exit(1);
  });
}
