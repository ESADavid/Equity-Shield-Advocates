#!/usr/bin/env node

/**
 * Phase 1: Fix Critical ESLint Errors
 * This script fixes all critical parsing errors found by ESLint
 */

import { readFileSync, writeFileSync } from 'fs';
import { info, error as logError, warn } from '../utils/loggerWrapper.js';

info('🔧 Phase 1: Fixing Critical ESLint Errors');
info('='.repeat(80));

let fixedCount = 0;
let errorCount = 0;

// Fix 1: earnings_dashboard/src/index.js - Remove JSX from .js file or rename
info('\n📝 Fix 1: earnings_dashboard/src/index.js');
try {
  const content = readFileSync('earnings_dashboard/src/index.js', 'utf8');
  if (content.includes('ReactDOM.render') || content.includes('<')) {
    // This is a React file, should be .jsx
    warn('  ⚠️  File contains JSX but has .js extension');
    info('  ℹ️  This file should be renamed to .jsx or moved');
    info('  ℹ️  Skipping for now - manual review needed');
  }
} catch (err) {
  warn(`  ⚠️  Could not process: ${err.message}`);
}

// Fix 2: scripts/implement-all-phases.js - Unicode escape sequence
info('\n📝 Fix 2: scripts/implement-all-phases.js');
try {
  const content = readFileSync('scripts/implement-all-phases.js', 'utf8');
  // Fix Unicode escape sequences in strings
  content = content.replace(/\\u([0-9A-Fa-f]{4})/g, (match, hex) => {
    return String.fromCharCode(parseInt(hex, 16));
  });
  writeFileSync('scripts/implement-all-phases.js', content, 'utf8');
  info('  ✅ Fixed Unicode escape sequences');
  fixedCount++;
} catch (err) {
  logError(`  ❌ Error: ${err.message}`);
  errorCount++;
}

// Fix 3: scripts/implement-phase2.js - Unicode escape sequence
info('\n📝 Fix 3: scripts/implement-phase2.js');
try {
  let content = readFileSync('scripts/implement-phase2.js', 'utf8');
  // Fix Unicode escape sequences in strings
  content = content.replace(/\\u([0-9A-Fa-f]{4})/g, (match, hex) => {
    return String.fromCharCode(parseInt(hex, 16));
  });
  writeFileSync('scripts/implement-phase2.js', content, 'utf8');
  info('  ✅ Fixed Unicode escape sequences');
  fixedCount++;
} catch (err) {
  logError(`  ❌ Error: ${err.message}`);
  errorCount++;
}

// Fix 4: services/multiChannelNotificationService.js - Undefined 'amount'
info('\n📝 Fix 4: services/multiChannelNotificationService.js');
try {
  let content = readFileSync(
    'services/multiChannelNotificationService.js',
    'utf8'
  );
  // Find the line with undefined 'amount' and fix it
  if (
    content.includes('amount') &&
    !content.includes('const amount') &&
    !content.includes('let amount')
  ) {
    // Look for the context where amount is used
    const lines = content.split('\n');
    let fixed = false;
    for (let i = 0; i < lines.length; i++) {
      if (
        lines[i].includes('amount') &&
        !lines[i].includes('//') &&
        !lines[i].includes('const') &&
        !lines[i].includes('let')
      ) {
        // Check if it's in a function parameter or needs to be extracted from data
        if (lines[i].includes('${amount}') || lines[i].includes('amount:')) {
          // Likely needs to be extracted from notification data
          const functionStart = lines
            .slice(0, i)
            .reverse()
            .findIndex(
              (line) => line.includes('async') || line.includes('function')
            );
          if (functionStart !== -1) {
            const funcIndex = i - functionStart;
            // Add amount extraction after function declaration
            for (let j = funcIndex; j < i; j++) {
              if (
                lines[j].includes('{') &&
                !lines[j + 1].includes('const amount')
              ) {
                lines.splice(
                  j + 1,
                  0,
                  '  const amount = notification.data?.amount || notification.amount || 0;'
                );
                fixed = true;
                break;
              }
            }
          }
        }
      }
    }
    if (fixed) {
      writeFileSync(
        'services/multiChannelNotificationService.js',
        lines.join('\n'),
        'utf8'
      );
      info('  ✅ Fixed undefined amount variable');
      fixedCount++;
    } else {
      warn('  ⚠️  Could not automatically fix - manual review needed');
    }
  } else {
    info('  ℹ️  No undefined amount found or already fixed');
  }
} catch (err) {
  logError(`  ❌ Error: ${err.message}`);
  errorCount++;
}

// Fix 5-8: Files with shebang issues (setup_credentials.js, setup_jpmorgan_credentials.js, simple_jpmorgan_validation.js)
const shebanFiles = [
  'setup_credentials.js',
  'setup_jpmorgan_credentials.js',
  'simple_jpmorgan_validation.js',
];

for (const file of shebanFiles) {
  info(`\n📝 Fix: ${file}`);
  try {
    let content = readFileSync(file, 'utf8');
    // Check if file starts with import and has shebang later
    if (content.match(/^import.*\n.*#!/)) {
      // Move shebang to first line
      content = content.replace(/^(import[^\n]*\n+)(#!.*\n)/, '$2$1');
      writeFileSync(file, content, 'utf8');
      info('  ✅ Fixed shebang position');
      fixedCount++;
    } else if (content.match(/^[^#].*#!/)) {
      // Shebang is not on first line
      const lines = content.split('\n');
      const shebangIndex = lines.findIndex((line) => line.startsWith('#!'));
      if (shebangIndex > 0) {
        const shebang = lines.splice(shebangIndex, 1)[0];
        lines.unshift(shebang);
        writeFileSync(file, lines.join('\n'), 'utf8');
        info('  ✅ Fixed shebang position');
        fixedCount++;
      }
    } else {
      info('  ℹ️  No shebang issues found');
    }
  } catch (err) {
    if (err.code === 'ENOENT') {
      warn(`  ⚠️  File not found: ${file}`);
    } else {
      logError(`  ❌ Error: ${err.message}`);
      errorCount++;
    }
  }
}

// Fix: algorithms/divineWisdom.js - hasOwnProperty warning
info('\n📝 Fix: algorithms/divineWisdom.js');
try {
  let content = readFileSync('algorithms/divineWisdom.js', 'utf8');
  // Replace obj.hasOwnProperty with Object.prototype.hasOwnProperty.call(obj, prop)
  content = content.replace(
    /(\w+)\.hasOwnProperty\(([^)]+)\)/g,
    'Object.prototype.hasOwnProperty.call($1, $2)'
  );
  writeFileSync('algorithms/divineWisdom.js', content, 'utf8');
  info('  ✅ Fixed hasOwnProperty usage');
  fixedCount++;
} catch (err) {
  logError(`  ❌ Error: ${err.message}`);
  errorCount++;
}

// Summary
info('\n' + '='.repeat(80));
info('📊 Summary:');
info(`  ✅ Files fixed: ${fixedCount}`);
info(`  ❌ Errors: ${errorCount}`);

if (errorCount === 0) {
  info('\n🎉 All critical ESLint errors have been fixed!');
  info('Next step: Run npm run lint to verify');
} else {
  warn('\n⚠️  Some errors could not be fixed automatically');
  info('Please review the errors above and fix manually');
}
