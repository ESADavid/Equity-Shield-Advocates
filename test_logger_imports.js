/**
 * Test script to verify logger imports work correctly
 */

console.log('🧪 Testing Logger Imports...\n');

// Test 1: Import logger wrapper
console.log('Test 1: Importing logger wrapper...');
try {
  const loggerModule = await import('./utils/loggerWrapper.js');
  console.log('✅ Logger wrapper imported successfully');
  console.log(
    '   Available methods:',
    Object.keys(loggerModule)
      .filter((k) => k !== 'default')
      .join(', ')
  );
} catch (error) {
  console.error('❌ Failed to import logger wrapper:', error.message);
  process.exit(1);
}

// Test 2: Import and test modified services
console.log('\nTest 2: Testing modified service imports...');
const servicesToTest = [
  './services/plaidService.js',
  './services/nvidiaBlackwellService.js',
  './services/privateBankingService.js',
  './services/assetManagementService.js',
  './services/debtAcquisitionService.js',
  './services/haitiStrategicService.js',
];

let passCount = 0;
let failCount = 0;

for (const service of servicesToTest) {
  try {
    await import(service);
    console.log(`✅ ${service}`);
    passCount++;
  } catch (error) {
    console.error(`❌ ${service}: ${error.message}`);
    failCount++;
  }
}

// Test 3: Test logger functionality
console.log('\nTest 3: Testing logger functionality...');
try {
  const { info, error, warn, debug } = await import('./utils/loggerWrapper.js');

  info('Test info message', { test: true });
  warn('Test warning message', { test: true });
  error('Test error message', new Error('Test error'));
  debug('Test debug message', { test: true });

  console.log('✅ Logger methods executed successfully');
} catch (err) {
  console.error('❌ Logger functionality test failed:', err.message);
  failCount++;
}

// Test 4: Check if log files are created
console.log('\nTest 4: Checking log file creation...');
try {
  const fs = await import('fs');
  const path = await import('path');

  const logsDir = path.default.join(process.cwd(), 'logs');

  if (fs.default.existsSync(logsDir)) {
    const files = fs.default.readdirSync(logsDir);
    console.log(`✅ Logs directory exists with ${files.length} file(s)`);
    if (files.length > 0) {
      console.log('   Files:', files.join(', '));
    }
  } else {
    console.log(
      '⚠️  Logs directory does not exist yet (will be created on first log)'
    );
  }
} catch (err) {
  console.error('❌ Log file check failed:', err.message);
}

// Summary
console.log('\n' + '='.repeat(60));
console.log('📊 Test Summary:');
console.log(`   Passed: ${passCount}`);
console.log(`   Failed: ${failCount}`);
console.log(
  `   Status: ${failCount === 0 ? '✅ ALL TESTS PASSED' : '❌ SOME TESTS FAILED'}`
);
console.log('='.repeat(60));

process.exit(failCount > 0 ? 1 : 0);
