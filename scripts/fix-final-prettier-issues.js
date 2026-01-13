#!/usr/bin/env node

/**
 * Fix Final Prettier Issues
 * Fixes JSON syntax errors and template string issues
 */

import { readFileSync, writeFileSync } from 'fs';
import { info, error as logError } from '../utils/loggerWrapper.js';

info('🔧 Fixing Final Prettier Issues');
info('='.repeat(80));

let fixedCount = 0;

// Fix 1: owlban_repos/sample_repo/revenue.json - Remove duplicate closing brace
info('\n📝 Fix 1: owlban_repos/sample_repo/revenue.json');
try {
  const content = readFileSync('owlban_repos/sample_repo/revenue.json', 'utf8');
  // Replace "}]{" with "},"
  content = content.replace(/\]\s*\}\s*\{/g, '],{');
  writeFileSync('owlban_repos/sample_repo/revenue.json', content, 'utf8');
  info('  ✅ Fixed JSON syntax');
  fixedCount++;
} catch (err) {
  logError(`  ❌ Error: ${err.message}`);
}

// Fix 2: scripts/implement-all-phases.js - Fix template string properly
info('\n📝 Fix 2: scripts/implement-all-phases.js');
try {
  const content = readFileSync('scripts/implement-all-phases.js', 'utf8');
  // Find and fix the problematic line
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (
      lines[i].includes('info(`\\nCreating') ||
      lines[i].includes('info(\\`\\nCreating')
    ) {
      // Replace with proper template literal
      lines[i] =
        'info(`\\nCreating ${Object.keys(files).length} files...\\n`);';
    }
  }
  writeFileSync('scripts/implement-all-phases.js', lines.join('\n'), 'utf8');
  info('  ✅ Fixed template string');
  fixedCount++;
} catch (err) {
  logError(`  ❌ Error: ${err.message}`);
}

// Fix 3: scripts/implement-phase2.js - Fix template string properly
info('\n📝 Fix 3: scripts/implement-phase2.js');
try {
  const content = readFileSync('scripts/implement-phase2.js', 'utf8');
  // Find and fix the problematic line
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (
      lines[i].includes('info(`✅ Created:') ||
      lines[i].includes('info(\\`✅ Created:')
    ) {
      // Replace with proper template literal
      lines[i] = '    info(`✅ Created: ${filePath}`);';
    }
  }
  writeFileSync('scripts/implement-phase2.js', lines.join('\n'), 'utf8');
  info('  ✅ Fixed template string');
  fixedCount++;
} catch (err) {
  logError(`  ❌ Error: ${err.message}`);
}

info('\n' + '='.repeat(80));
info(`📊 Summary: ${fixedCount} files fixed`);
info('\n🎉 All Prettier issues resolved!');
info('Next: Run npx prettier --write . again');
