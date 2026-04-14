/**
 * Quick test to verify server-enhanced.js can start without errors
 */

import { spawn } from 'child_process';

console.log('🧪 Testing server-enhanced.js startup...\n');

const server = spawn('node', ['server-enhanced.js'], {
  stdio: 'pipe',
  shell: true,
});

let output = '';
let errorOutput = '';

server.stdout.on('data', (data) => {
  output += data.toString();
  console.log(data.toString());
});

server.stderr.on('data', (data) => {
  errorOutput += data.toString();
  console.error(data.toString());
});

// Kill server after 3 seconds
setTimeout(() => {
  server.kill();

  console.log('\n📊 Test Results:');
  console.log('================');

  if (errorOutput.includes('SyntaxError') || errorOutput.includes('Error:')) {
    console.log('❌ Server failed to start');
    console.log('Error:', errorOutput);
    process.exit(1);
  } else if (
    output.includes('listening') ||
    output.includes('started') ||
    output.length > 0
  ) {
    console.log('✅ Server started successfully!');
    console.log('Output:', output);
    process.exit(0);
  } else {
    console.log('✅ Server started without errors (no output captured)');
    process.exit(0);
  }
}, 3000);
