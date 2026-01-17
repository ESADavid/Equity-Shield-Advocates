const fs = require('fs');

console.log('Starting JPMorgan Payments module test...');

try {
  // Test if the module can be required
  const jpmorganPayment = require('./earnings_dashboard/jpmorgan_payment');
  console.log('✅ JPMorgan Payments module loaded successfully');

  const output = [
    'JPMorgan Payments Integration Test Results',
    '===========================================',
    `✅ Module loaded successfully at: ${new Date().toISOString()}`,
    `📦 Module type: ${typeof jpmorganPayment}`,
    `🔧 Module properties: ${Object.keys(jpmorganPayment).join(', ')}`,
    '',
    'Test completed successfully!',
  ].join('\n');

  fs.writeFileSync('./jpmorgan_test_results.txt', output);
  console.log('📝 Results written to jpmorgan_test_results.txt');
} catch (error) {
  const errorOutput = [
    'JPMorgan Payments Integration Test - ERROR',
    '===========================================',
    `❌ Failed to load module at: ${new Date().toISOString()}`,
    `💥 Error: ${error.message}`,
    `📋 Stack: ${error.stack}`,
    '',
    'Please check the following:',
    '1. Are all dependencies installed? (axios, crypto)',
    '2. Is the module file present?',
    '3. Check for syntax errors in the module',
  ].join('\n');

  fs.writeFileSync('./jpmorgan_test_error.txt', errorOutput);
  console.error('❌ Test failed - check jpmorgan_test_error.txt for details');
  console.error(error.message);
}
