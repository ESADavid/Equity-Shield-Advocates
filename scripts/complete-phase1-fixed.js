#!/usr/bin/env node

/**
 * Script to complete remaining Phase 1 tasks
 * - Fix ESLint configuration
 * - Validate TypeScript
 * - Run Prettier formatting
 */

import fs from 'fs';
import { execSync } from 'child_process';
import { info, error } from 'utils/loggerWrapper.js';

info('🚀 Completing Phase 1: Code Quality Perfection');
info('='.repeat(80));

// Task #6: Fix ESLint Configuration
info('\n📝 Task #6: Fixing ESLint Configuration');
info('-'.repeat(80));

try {
  const eslintConfig = fs.readFileSync('.eslintrc.cjs', 'utf8');

  // Remove the conflicting *.js override
  const fixedConfig = eslintConfig.replace(
    / {4}\\{\n {6}files: \\['\\*\\.js'\\],\\n {6}parser: 'espree',\\n {6}parserOptions: \\{\\n {8}sourceType: 'script', \\/\\/ Allow require\\(\\) in \\.js files\\n {6}\\},\\n {6}rules: \\{\\n {8}'@typescript-eslint\\/no-unused-vars': 'off',\\n {8}'no-unused-vars': 'off',\\n {6}\\},\\n {4}\\},\\n/g,
    ''
  );

  if (fixedConfig !== eslintConfig) {
    fs.writeFileSync('.eslintrc.cjs', fixedConfig, 'utf8');
    info('✅ Removed conflicting *.js override from .eslintrc.cjs');
  } else {
    info('ℹ️  No conflicting override found (may already be fixed)');
  }

  // Verify the fix
  info('\n🔍 Verifying ESLint configuration...');
  try {
    execSync(
      'npx eslint algorithms/divineWisdom.js algorithms/sacredGeometry.js app.js check_credentials.js',
      {
        stdio: 'pipe',
        encoding: 'utf8',
      }
    );
    info('✅ ESLint parsing errors fixed!');
  } catch (err) {
    const output = err.stdout || err.stderr || '';
    if (output.includes('Parsing error')) {
      error('❌ ESLint parsing errors still present');
    } else {
      info('✅ No parsing errors (warnings acceptable)');
    }
  }
} catch (err) {
  const errorMsg = err instanceof Error ? err.message : String(err);
  error('❌ Error fixing ESLint configuration:', errorMsg);
}

// Task #7: Validate TypeScript
info('\n📝 Task #7: Validating TypeScript Compilation');
info('-'.repeat(80));

try {
  execSync('tsc --noEmit', { stdio: 'inherit' });
  info('✅ TypeScript compilation validated - no errors!');
} catch (err) {
  const errorMsg = err instanceof Error ? err.message : String(err);
  error('❌ TypeScript compilation has errors - manual fix required');
  info('ℹ️  Run: tsc --noEmit to see errors');
}

// Task #8: Run Prettier Formatting
info('\n📝 Task #8: Running Prettier Code Formatting');
info('-'.repeat(80));

try {
  info('🔍 Checking code formatting...');
  try {
    execSync('npx prettier --check .', { stdio: 'pipe' });
    info('✅ Code is already formatted correctly!');
  } catch (checkErr) {
    info('📝 Formatting code...');
    execSync('npx prettier --write .', { stdio: 'inherit' });
    info('✅ Code formatted successfully!');
  }
} catch (err) {
  const errorMsg = err instanceof Error ? err.message : String(err);
  error('❌ Error running Prettier:', errorMsg);
  info('ℹ️  You may need to install prettier: npm install --save-dev prettier');
}

// Final Summary
info('\n' + '='.repeat(80));
info('🎉 Phase 1 Completion Attempt Finished!');
info('='.repeat(80));
info('\n📊 Final Verification:');
info('   Run: npm run lint');
info('   Run: tsc --noEmit');
info('   Check: Code formatting');
info('\nIf all checks pass, Phase 1 is 100% complete! 🎯');

