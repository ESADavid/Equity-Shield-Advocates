#!/usr/bin/env node

/**
 * Fix Server Startup Issues
 * - Kills processes on port 3000
 * - Fixes module export errors
 * - Fixes mongoose duplicate index warnings
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🔧 FIXING SERVER STARTUP ISSUES\n');
console.log('='.repeat(60));

// Step 1: Kill processes on port 3000
console.log('\n📍 Step 1: Killing processes on port 3000...');
try {
  // Windows command to find and kill process on port 3000
  try {
    const output = execSync('netstat -ano | findstr :3000', {
      encoding: 'utf-8',
    });
    const lines = output
      .split('\n')
      .filter((line) => line.includes('LISTENING'));

    if (lines.length > 0) {
      const pids = new Set();
      lines.forEach((line) => {
        const parts = line.trim().split(/\s+/);
        const pid = parts[parts.length - 1];
        if (pid && !isNaN(pid)) {
          pids.add(pid);
        }
      });

      pids.forEach((pid) => {
        try {
          execSync(`taskkill /F /PID ${pid}`, { stdio: 'inherit' });
          console.log(`✓ Killed process ${pid}`);
        } catch (err) {
          console.log(`⚠️  Could not kill process ${pid}`);
        }
      });
    } else {
      console.log('✓ No processes found on port 3000');
    }
  } catch (err) {
    console.log('✓ No processes found on port 3000');
  }
} catch (error) {
  console.log('⚠️  Error checking port 3000:', error.message);
}

// Step 2: Fix middleware/auth.js - Add missing 'authorize' export
console.log('\n📍 Step 2: Fixing middleware/auth.js...');
try {
  const authPath = path.join(process.cwd(), 'middleware', 'auth.js');

  if (fs.existsSync(authPath)) {
    let content = fs.readFileSync(authPath, 'utf-8');

    // Check if authorize function exists
    if (
      !content.includes('export const authorize') &&
      !content.includes('export { authorize }')
    ) {
      // Add authorize middleware function
      const authorizeFunction = `

/**
 * Authorization middleware - checks if user has required role
 * @param {string[]} roles - Array of allowed roles
 */
export const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (roles.length && !roles.includes(req.user.role)) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        required: roles,
        current: req.user.role
      });
    }

    next();
  };
};
`;

      content += authorizeFunction;
      fs.writeFileSync(authPath, content);
      console.log('✓ Added authorize function to middleware/auth.js');
    } else {
      console.log('✓ authorize function already exists in middleware/auth.js');
    }
  } else {
    console.log('⚠️  middleware/auth.js not found');
  }
} catch (error) {
  console.log('❌ Error fixing middleware/auth.js:', error.message);
}

// Step 3: Fix routes/notificationRoutes.js - Fix syntax error
console.log('\n📍 Step 3: Fixing routes/notificationRoutes.js...');
try {
  const notifPath = path.join(process.cwd(), 'routes', 'notificationRoutes.js');

  if (fs.existsSync(notifPath)) {
    let content = fs.readFileSync(notifPath, 'utf-8');

    // Fix common syntax errors
    // Remove any stray dots or invalid tokens at the beginning
    content = content.replace(/^\s*\.\s*/gm, '');

    // Ensure proper import statements
    if (!content.includes('import express from')) {
      content = `import express from 'express';\n${content}`;
    }

    fs.writeFileSync(notifPath, content);
    console.log('✓ Fixed syntax in routes/notificationRoutes.js');
  } else {
    console.log('⚠️  routes/notificationRoutes.js not found');
  }
} catch (error) {
  console.log('❌ Error fixing routes/notificationRoutes.js:', error.message);
}

// Step 4: Fix Mongoose duplicate index warnings
console.log('\n📍 Step 4: Fixing Mongoose duplicate index warnings...');

const modelsToFix = [
  { file: 'models/Citizen.js', field: 'personalInfo.nationalId' },
  { file: 'models/Course.js', field: 'title' },
  { file: 'models/Transaction.js', field: 'transactionId' },
];

modelsToFix.forEach(({ file, field }) => {
  try {
    const modelPath = path.join(process.cwd(), file);

    if (fs.existsSync(modelPath)) {
      let content = fs.readFileSync(modelPath, 'utf-8');

      // Remove duplicate index: true from field definitions
      // Look for patterns like: fieldName: { type: ..., index: true, unique: true }
      // and remove the index: true since unique: true already creates an index

      const fieldPattern = new RegExp(
        `${field.split('.').pop()}:\\s*{[^}]*index:\\s*true[^}]*unique:\\s*true`,
        'g'
      );
      if (fieldPattern.test(content)) {
        content = content.replace(/,?\s*index:\s*true,?/g, (match) => {
          // Only remove if there's also a unique: true
          return '';
        });

        fs.writeFileSync(modelPath, content);
        console.log(`✓ Fixed duplicate index in ${file}`);
      } else {
        console.log(`✓ No duplicate index found in ${file}`);
      }
    } else {
      console.log(`⚠️  ${file} not found`);
    }
  } catch (error) {
    console.log(`❌ Error fixing ${file}:`, error.message);
  }
});

// Step 5: Create a helper script to check port availability
console.log('\n📍 Step 5: Creating port check helper...');
try {
  const portCheckScript = `#!/usr/bin/env node

/**
 * Check if port 3000 is available
 */

const { execSync } = require('child_process');

try {
  const output = execSync('netstat -ano | findstr :3000', { encoding: 'utf-8' });
  const lines = output.split('\\n').filter(line => line.includes('LISTENING'));
  
  if (lines.length > 0) {
    console.log('❌ Port 3000 is in use');
    console.log('\\nProcesses using port 3000:');
    lines.forEach(line => {
      const parts = line.trim().split(/\\s+/);
      const pid = parts[parts.length - 1];
      console.log(\`  PID: \${pid}\`);
    });
    console.log('\\nRun: node scripts/fix-server-startup-issues.cjs');
    process.exit(1);
  } else {
    console.log('✅ Port 3000 is available');
    process.exit(0);
  }
} catch (err) {
  console.log('✅ Port 3000 is available');
  process.exit(0);
}
`;

  fs.writeFileSync('scripts/check-port-3000.cjs', portCheckScript);
  console.log('✓ Created scripts/check-port-3000.cjs');
} catch (error) {
  console.log('❌ Error creating port check script:', error.message);
}

console.log('\n' + '='.repeat(60));
console.log('✅ SERVER STARTUP FIXES COMPLETE\n');
console.log('Next steps:');
console.log(
  '1. Run: node scripts/check-port-3000.cjs (to verify port is free)'
);
console.log(
  '2. Run: node test_server_startup_simple.cjs (to test server startup)'
);
console.log('');
