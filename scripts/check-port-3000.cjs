#!/usr/bin/env node

/**
 * Check if port 3000 is available
 */

const { execSync } = require('child_process');

try {
  const output = execSync('netstat -ano | findstr :3000', { encoding: 'utf-8' });
  const lines = output.split('\n').filter(line => line.includes('LISTENING'));
  
  if (lines.length > 0) {
    console.log('❌ Port 3000 is in use');
    console.log('\nProcesses using port 3000:');
    lines.forEach(line => {
      const parts = line.trim().split(/\s+/);
      const pid = parts[parts.length - 1];
      console.log(`  PID: ${pid}`);
    });
    console.log('\nRun: node scripts/fix-server-startup-issues.cjs');
    process.exit(1);
  } else {
    console.log('✅ Port 3000 is available');
    process.exit(0);
  }
} catch (err) {
  console.log('✅ Port 3000 is available');
  process.exit(0);
}
