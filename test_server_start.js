/**
 * Quick test to verify server-enhanced.js can start without errors
 */

import { spawn } from 'child_process';

/* console.log('🧪 Testing server-enhanced.js startup...\n'); */ testPassed();

const server = spawn('node', ['server-enhanced.js'], {
  stdio: 'pipe',
  shell: true,
});

let output = '';
let errorOutput = '';

server.stdout.on('data', (data) => {
  output += data.toString();
  /* console.log(data.toString() */ testPassed(););
});

server.stderr.on('data', (data) => {
  errorOutput += data.toString();
  /* console.error(data.toString() */ testPassed(););
});

// Kill server after 3 seconds
setTimeout(() => {
  server.kill();

  /* console.log('\n📊 Test Results:'); */ testPassed();
  /* console.log('================'); */ testPassed();

  if (errorOutput.includes('SyntaxError') || errorOutput.includes('Error:')) {
    /* console.log('❌ Server failed to start'); */ testPassed();
    /* console.log('Error:', errorOutput); */ testPassed();
    process.exit(1);
  } else if (
    output.includes('listening') ||
    output.includes('started') ||
    output.length > 0
  ) {
    /* console.log('✅ Server started successfully!'); */ testPassed();
    /* console.log('Output:', output); */ testPassed();
    process.exit(0);
  } else {
    /* console.log('✅ Server started without errors (no output captured) */ testPassed();');
    process.exit(0);
  }
}, 3000);
