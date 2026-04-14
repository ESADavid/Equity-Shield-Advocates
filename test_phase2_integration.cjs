#!/usr/bin/env node

/**
 * Phase 2 Integration Test
 * Tests that all Phase 2 routes are properly integrated
 */

const { spawn } = require('child_process');

console.log('🧪 PHASE 2 INTEGRATION TEST\n');
console.log('='.repeat(60));

console.log('\n📋 Starting server to verify Phase 2 integration...\n');

const serverProcess = spawn('node', ['server-enhanced.js'], {
  env: { ...process.env, SKIP_DATABASE: 'true' },
});

let output = '';
let foundPhase2Routes = {
  partner: false,
  citizen: false,
  ubiPayment: false,
  notification: false,
};

serverProcess.stdout.on('data', (data) => {
  const text = data.toString();
  output += text;

  // Check for Phase 2 route confirmations
  if (text.includes('Partner coordination system loaded')) {
    foundPhase2Routes.partner = true;
    console.log('✅ Partner system loaded');
  }
  if (text.includes('Citizen portal system loaded')) {
    foundPhase2Routes.citizen = true;
    console.log('✅ Citizen portal loaded');
  }
  if (text.includes('UBI payment system loaded')) {
    foundPhase2Routes.ubiPayment = true;
    console.log('✅ UBI payment system loaded');
  }
  if (text.includes('Multi-channel notification routes loaded')) {
    foundPhase2Routes.notification = true;
    console.log('✅ Multi-channel notifications loaded');
  }

  // Check if server started
  if (text.includes('Server running on port')) {
    console.log('\n✅ Server started successfully!\n');

    // Give it a moment then check results
    setTimeout(() => {
      console.log('='.repeat(60));
      console.log('\n📊 PHASE 2 INTEGRATION RESULTS\n');

      const allLoaded = Object.values(foundPhase2Routes).every((v) => v);

      console.log('Phase 2 Routes Status:');
      console.log(
        `  Partner System: ${foundPhase2Routes.partner ? '✅' : '❌'}`
      );
      console.log(
        `  Citizen Portal: ${foundPhase2Routes.citizen ? '✅' : '❌'}`
      );
      console.log(
        `  UBI Payments: ${foundPhase2Routes.ubiPayment ? '✅' : '❌'}`
      );
      console.log(
        `  Notifications: ${foundPhase2Routes.notification ? '✅' : '❌'}`
      );

      console.log('\n' + '='.repeat(60));

      if (allLoaded) {
        console.log('\n🎉 PHASE 2 INTEGRATION: COMPLETE ✅');
        console.log('   All Phase 2 routes successfully integrated!\n');
      } else {
        console.log('\n⚠️  PHASE 2 INTEGRATION: INCOMPLETE');
        console.log('   Some routes failed to load.\n');
      }

      // Kill the server
      serverProcess.kill();
      process.exit(allLoaded ? 0 : 1);
    }, 3000);
  }
});

serverProcess.stderr.on('data', (data) => {
  const text = data.toString();
  if (!text.includes('ExperimentalWarning')) {
    console.error('Error:', text);
  }
});

serverProcess.on('error', (error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});

// Timeout after 15 seconds
setTimeout(() => {
  console.log('\n⏱️  Test timeout - killing server');
  serverProcess.kill();
  process.exit(1);
}, 15000);
