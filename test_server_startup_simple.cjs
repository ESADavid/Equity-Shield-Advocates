#!/usr/bin/env node

/**
 * Simple Server Startup Test
 * Just tries to start the server and reports what happens
 */

const { spawn } = require('child_process');

console.log('🧪 SIMPLE SERVER STARTUP TEST\n');
console.log('='.repeat(60));

const serverProcess = spawn('node', ['server-enhanced.js'], {
  env: { ...process.env, SKIP_DATABASE: 'true' },
  stdio: 'pipe'
});

let hasStarted = false;
let hasError = false;

serverProcess.stdout.on('data', (data) => {
  const text = data.toString();
  console.log(text);
  
  if (text.includes('Server running on port')) {
    hasStarted = true;
    console.log('\n✅ SERVER STARTED SUCCESSFULLY!\n');
    
    // Kill after confirming startup
    setTimeout(() => {
      serverProcess.kill();
      process.exit(0);
    }, 2000);
  }
});

serverProcess.stderr.on('data', (data) => {
  const text = data.toString();
  if (!text.includes('ExperimentalWarning') && !text.includes('punycode')) {
    console.error('ERROR:', text);
    hasError = true;
  }
});

serverProcess.on('error', (error) => {
  console.error('❌ Failed to start server:', error.message);
  process.exit(1);
});

serverProcess.on('exit', (code) => {
  if (!hasStarted && !hasError) {
    console.log('\n⚠️  Server exited without starting (code:', code, ')');
  }
});

// Timeout after 15 seconds
setTimeout(() => {
  if (!hasStarted) {
    console.log('\n⏱️  Timeout - server did not start within 15 seconds');
    serverProcess.kill();
    process.exit(1);
  }
}, 15000);
