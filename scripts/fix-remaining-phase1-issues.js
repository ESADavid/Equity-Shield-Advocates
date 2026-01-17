#!/usr/bin/env node

/**
 * Fix Remaining Phase 1 Issues
 * Fixes merge conflicts, template strings, and shebang positioning
 */

import { readFileSync, writeFileSync } from 'fs';
import { info, error as logError, warn } from '../utils/loggerWrapper.js';

info('🔧 Fixing Remaining Phase 1 Issues');
info('='.repeat(80));

let fixedCount = 0;
let errorCount = 0;

// Fix 1: Revert Unicode escape fix in scripts/implement-all-phases.js
info('\n📝 Fix 1: scripts/implement-all-phases.js - Revert bad Unicode fix');
try {
  let content = readFileSync('scripts/implement-all-phases.js', 'utf8');
  // The issue is unterminated template - need to escape the backticks properly
  content = content.replace(
    /info\(`\nCreating \$\{Object\.keys\(files\)\.length\} files\.\.\.\n`\);/g,
    'info(`\\nCreating ${Object.keys(files).length} files...\\n`);'
  );
  writeFileSync('scripts/implement-all-phases.js', content, 'utf8');
  info('  ✅ Fixed template string');
  fixedCount++;
} catch (err) {
  logError(`  ❌ Error: ${err.message}`);
  errorCount++;
}

// Fix 2: Revert Unicode escape fix in scripts/implement-phase2.js
info('\n📝 Fix 2: scripts/implement-phase2.js - Revert bad Unicode fix');
try {
  let content = readFileSync('scripts/implement-phase2.js', 'utf8');
  // Fix unterminated template
  content = content.replace(
    /info\(`✅ Created: \$\{filePath\}`\);/g,
    'info(`✅ Created: ${filePath}`);'
  );
  writeFileSync('scripts/implement-phase2.js', content, 'utf8');
  info('  ✅ Fixed template string');
  fixedCount++;
} catch (err) {
  logError(`  ❌ Error: ${err.message}`);
  errorCount++;
}

// Fix 3-5: Fix shebang positioning in setup files
const setupFiles = [
  'setup_credentials.js',
  'setup_jpmorgan_credentials.js',
  'simple_jpmorgan_validation.js',
];

for (const file of setupFiles) {
  info(`\n📝 Fix: ${file} - Fix shebang position`);
  try {
    const content = readFileSync(file, 'utf8');
    // Remove import line and shebang, then reconstruct properly
    const lines = content.split('\n');
    const importLine = lines.find((l) => l.startsWith('import'));
    const shebangLine = lines.find((l) => l.startsWith('#!'));
    const otherLines = lines.filter(
      (l) => !l.startsWith('import') && !l.startsWith('#!')
    );

    // Reconstruct: shebang first, then imports, then rest
    const newContent = [
      shebangLine || '#!/usr/bin/env node',
      '',
      importLine || '',
      ...otherLines,
    ].join('\n');

    writeFileSync(file, newContent, 'utf8');
    info(`  ✅ Fixed shebang position`);
    fixedCount++;
  } catch (err) {
    if (err.code === 'ENOENT') {
      warn(`  ⚠️  File not found: ${file}`);
    } else {
      logError(`  ❌ Error: ${err.message}`);
      errorCount++;
    }
  }
}

// Fix 6-8: Resolve merge conflicts in JSON files (keep HEAD version)
const jsonFiles = [
  'data/payroll_records.json',
  'logs/override_history.json',
  'owlban_repos/sample_repo/revenue.json',
];

for (const file of jsonFiles) {
  info(`\n📝 Fix: ${file} - Resolve merge conflict`);
  try {
    const content = readFileSync(file, 'utf8');

    if (content.includes('<<<<<<< HEAD')) {
      // Keep HEAD version (remove conflict markers and alternative version)
      const lines = content.split('\n');
      const result = [];
      let inConflict = false;
      let keepSection = true;

      for (const line of lines) {
        if (line.startsWith('<<<<<<< HEAD')) {
          inConflict = true;
          keepSection = true;
          continue;
        } else if (line.startsWith('=======')) {
          keepSection = false;
          continue;
        } else if (line.startsWith('>>>>>>>')) {
          inConflict = false;
          keepSection = true;
          continue;
        }

        if (!inConflict || keepSection) {
          result.push(line);
        }
      }

      writeFileSync(file, result.join('\n'), 'utf8');
      info(`  ✅ Resolved merge conflict (kept HEAD version)`);
      fixedCount++;
    } else {
      info(`  ℹ️  No merge conflict found`);
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

// Summary
info('\n' + '='.repeat(80));
info('📊 Summary:');
info(`  ✅ Files fixed: ${fixedCount}`);
info(`  ❌ Errors: ${errorCount}`);

if (errorCount === 0) {
  info('\n🎉 All remaining Phase 1 issues have been fixed!');
  info('Next step: Run Prettier to format code');
  info('Command: npx prettier --write .');
} else {
  warn('\n⚠️  Some errors occurred');
  info('Please review the errors above');
}
