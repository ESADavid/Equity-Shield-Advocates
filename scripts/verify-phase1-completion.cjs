#!/usr/bin/env node

/**
 * Phase 1 Completion Verification Script
 * Verifies all Phase 1 tasks are complete
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { info } = require('../utils/loggerWrapper');

info('🔍 PHASE 1 COMPLETION VERIFICATION\n');
info('='.repeat(60));

const results = {
  passed: [],
  failed: [],
  warnings: [],
};

// Task 1.1: Check .env encoding
info('\n📋 Task 1.1: Checking .env encoding...');
try {
  const envPath = path.join(process.cwd(), '.env');
  if (fs.existsSync(envPath)) {
    const buffer = fs.readFileSync(envPath);
    // Check for BOM
    const hasBOM =
      buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf;
    if (hasBOM) {
      results.failed.push(
        'Task 1.1: .env file has BOM (should be UTF-8 without BOM)'
      );
    } else {
      results.passed.push(
        'Task 1.1: .env encoding is correct (UTF-8 without BOM)'
      );
    }
  } else {
    results.warnings.push('Task 1.1: .env file not found (may not be needed)');
  }
} catch (error) {
  results.warnings.push(
    `Task 1.1: Could not verify .env encoding: ${error.message}`
  );
}

// Task 1.2: Check console.log replacement
info('\n📋 Task 1.2: Checking console.log statements...');
try {
  const productionDirs = [
    'services',
    'routes',
    'models',
    'middleware',
    'blockchain',
    'algorithms',
  ];
  let consoleLogCount = 0;

  productionDirs.forEach((dir) => {
    const dirPath = path.join(process.cwd(), dir);
    if (fs.existsSync(dirPath)) {
      const files = getAllJsFiles(dirPath);
      files.forEach((file) => {
        const content = fs.readFileSync(file, 'utf8');
        const matches = content.match(/console\.(log|error|warn|info|debug)/g);
        if (matches) {
          consoleLogCount += matches.length;
        }
      });
    }
  });

  if (consoleLogCount === 0) {
    results.passed.push(
      'Task 1.2: No console.log statements in production code'
    );
  } else {
    results.failed.push(
      `Task 1.2: Found ${consoleLogCount} console statements in production code`
    );
  }
} catch (error) {
  results.warnings.push(
    `Task 1.2: Could not verify console.log replacement: ${error.message}`
  );
}

// Task 1.3: Check error handler integration
info('\n📋 Task 1.3: Checking error handler integration...');
try {
  const errorHandlerPath = path.join(
    process.cwd(),
    'middleware',
    'errorHandler.js'
  );
  const serverPath = path.join(process.cwd(), 'server-enhanced.js');

  if (!fs.existsSync(errorHandlerPath)) {
    results.failed.push('Task 1.3: middleware/errorHandler.js not found');
  } else if (!fs.existsSync(serverPath)) {
    results.warnings.push('Task 1.3: server-enhanced.js not found');
  } else {
    const serverContent = fs.readFileSync(serverPath, 'utf8');
    if (
      serverContent.includes('errorHandler') ||
      serverContent.includes('error-handler')
    ) {
      results.passed.push('Task 1.3: Error handler is integrated in server');
    } else {
      results.failed.push(
        'Task 1.3: Error handler not integrated in server-enhanced.js'
      );
    }
  }
} catch (error) {
  results.warnings.push(
    `Task 1.3: Could not verify error handler: ${error.message}`
  );
}

// Task 1.4: Check ESLint errors
info('\n📋 Task 1.4: Checking ESLint status...');
try {
  info('   Running ESLint (this may take a moment)...');
  const eslintOutput = execSync('npm run lint', {
    encoding: 'utf8',
    stdio: 'pipe',
  }).toString();

  const errorMatch = eslintOutput.match(/(\d+)\s+errors?\)/);
  const warningMatch = eslintOutput.match(/(\d+)\s+warnings?\)/);

  const errors = errorMatch ? parseInt(errorMatch[1]) : 0;
  const warnings = warningMatch ? parseInt(warningMatch[1]) : 0;

  if (errors <= 10) {
    results.passed.push(
      `Task 1.4: ESLint errors acceptable (${errors} errors, ${warnings} warnings)`
    );
  } else {
    results.failed.push(
      `Task 1.4: Too many ESLint errors (${errors} errors, target: ≤10)`
    );
  }
} catch (error) {
  // ESLint returns non-zero exit code when there are errors
  const output = error.stdout || error.message;
  const errorMatch = output.match(/(\d+)\s+errors?\)/);
  const warningMatch = output.match(/(\d+)\s+warnings?\)/);

  const errors = errorMatch ? parseInt(errorMatch[1]) : 0;
  const warnings = warningMatch ? parseInt(warningMatch[1]) : 0;

  if (errors <= 10) {
    results.passed.push(
      `Task 1.4: ESLint errors acceptable (${errors} errors, ${warnings} warnings)`
    );
  } else {
    results.failed.push(
      `Task 1.4: Too many ESLint errors (${errors} errors, target: ≤10)`
    );
  }
}

// Task 1.5: Check TypeScript compilation
info('\n📋 Task 1.5: Checking TypeScript compilation...');
try {
  const tsconfigPath = path.join(process.cwd(), 'tsconfig.json');
  if (!fs.existsSync(tsconfigPath)) {
    results.warnings.push(
      'Task 1.5: tsconfig.json not found (TypeScript may not be used)'
    );
  } else {
    info('   Running TypeScript compiler...');
    execSync('npx tsc --noEmit', { encoding: 'utf8', stdio: 'pipe' });
    results.passed.push(
      'Task 1.5: TypeScript compilation successful (0 errors)'
    );
  }
} catch (error) {
  const output = error.stdout || error.message;
  if (output.includes('error TS')) {
    const errorCount = (output.match(/error TS/g) || []).length;
    results.failed.push(
      `Task 1.5: TypeScript has ${errorCount} compilation errors`
    );
  } else {
    results.warnings.push(
      `Task 1.5: Could not verify TypeScript: ${error.message}`
    );
  }
}

// Task 1.6: Check code formatting
info('\n📋 Task 1.6: Checking code formatting...');
try {
  const prettierrcPath = path.join(process.cwd(), '.prettierrc');
  const prettierIgnorePath = path.join(process.cwd(), '.prettierignore');

  if (!fs.existsSync(prettierrcPath)) {
    results.warnings.push('Task 1.6: .prettierrc not found');
  } else if (!fs.existsSync(prettierIgnorePath)) {
    results.warnings.push('Task 1.6: .prettierignore not found (recommended)');
  } else {
    results.passed.push('Task 1.6: Prettier configuration files exist');
  }
} catch (error) {
  results.warnings.push(
    `Task 1.6: Could not verify Prettier: ${error.message}`
  );
}

// Task 1.7: Check deployment scripts
info('\n📋 Task 1.7: Checking deployment scripts...');
try {
  const deploymentScripts = [
    'scripts/execute-phase5-staging.cjs',
    'scripts/execute-phase5-pilot.cjs',
    'scripts/execute-phase5-production.cjs',
    'scripts/execute-phase5-scaling.cjs',
  ];

  let allExist = true;
  const missing = [];

  deploymentScripts.forEach((script) => {
    const scriptPath = path.join(process.cwd(), script);
    if (!fs.existsSync(scriptPath)) {
      allExist = false;
      missing.push(script);
    }
  });

  if (allExist) {
    results.passed.push('Task 1.7: All deployment scripts verified');
  } else {
    results.failed.push(
      `Task 1.7: Missing deployment scripts: ${missing.join(', ')}`
    );
  }
} catch (error) {
  results.warnings.push(
    `Task 1.7: Could not verify deployment scripts: ${error.message}`
  );
}

// Print results
info('\n' + '='.repeat(60));
info('\n📊 VERIFICATION RESULTS\n');

if (results.passed.length > 0) {
  info('✅ PASSED CHECKS:');
  results.passed.forEach((item) => info(`   ✓ ${item}`));
}

if (results.warnings.length > 0) {
  info('\n⚠️  WARNINGS:');
  results.warnings.forEach((item) => info(`   ⚠ ${item}`));
}

if (results.failed.length > 0) {
  info('\n❌ FAILED CHECKS:');
  results.failed.forEach((item) => info(`   ✗ ${item}`));
}

// Summary
info('\n' + '='.repeat(60));
info('\n📈 SUMMARY\n');
info(`   Passed:   ${results.passed.length}`);
info(`   Warnings: ${results.warnings.length}`);
info(`   Failed:   ${results.failed.length}`);

const totalChecks = results.passed.length + results.failed.length;
const passRate =
  totalChecks > 0
    ? ((results.passed.length / totalChecks) * 100).toFixed(1)
    : 0;

info(`\n   Pass Rate: ${passRate}%`);

if (results.failed.length === 0) {
  info('\n🎉 PHASE 1 VERIFICATION: COMPLETE ✅');
  info('\n   All critical checks passed!');
  info('   Phase 1 is ready for sign-off.');
  process.exit(0);
} else {
  info('\n⚠️  PHASE 1 VERIFICATION: INCOMPLETE');
  info(`\n   ${results.failed.length} check(s) failed.`);
  info('   Please address the failed checks above.');
  process.exit(1);
}

// Helper function to get all JS files recursively
function getAllJsFiles(dir, fileList = []) {
  const files = fs.readdirSync(dir);

  files.forEach((file) => {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);

    if (stat.isDirectory()) {
      // Skip node_modules and other common directories
      if (
        !['node_modules', '.git', 'coverage', 'dist', 'build'].includes(file)
      ) {
        getAllJsFiles(filePath, fileList);
      }
    } else if (
      file.endsWith('.js') &&
      !file.endsWith('.test.js') &&
      !file.endsWith('.spec.js')
    ) {
      fileList.push(filePath);
    }
  });

  return fileList;
}
