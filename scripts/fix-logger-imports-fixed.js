/**
 * Bulk Fix Logger Imports - ESM (ESLint Compliant)
 * Replaces all relative loggerWrapper.js imports with absolute 'utils/loggerWrapper.js'
 * Fixed: Console replaced with loggerWrapper
 */

import { readdir, readFile, writeFile, stat } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import logger from 'utils/loggerWrapper.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = resolve(__dirname, '..');

/**
 * WalkResult interface for type checking
 * @typedef {Object} WalkResult
 * @property {string} file - Relative file path
 * @property {number} [changes] - Number of import changes
 * @property {string} [error] - Error message
 */

/**
 * Recursively walk directory yielding .js files
 * @param {string} dir - Directory path
 * @yields {string} File path
 */
async function* walk(dir: string): AsyncGenerator<string> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    const statEntry = await stat(fullPath);
    if (statEntry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      yield* walk(fullPath);
    } else if (entry.name.endsWith('.js')) {
      yield fullPath;
    }
  }
}

/**
 * Fix logger imports in single file
 * @param {string} filePath - Full file path
 * @returns {Object|null} Result or null if no changes
 */
async function fixFile(filePath: string): Promise<FixResult | null> {
  try {
    const relativePath = './' + filePath.substring(rootDir.length + 1).replace(/\\/g, '/');
    const content = await readFile(filePath, 'utf8');
    const originalContent = content;

    // Regex: Capture quotes around relative paths to loggerWrapper.js
    const regex = /(['"])(?:\.\.?\/)+.*?loggerWrapper\.js\1/g;
    const newContent = content.replace(regex, '$1utils/loggerWrapper.js$1');

    if (newContent !== originalContent) {
      await writeFile(filePath, newContent, 'utf8');
      const changes = (content.match(regex) || []).length;
      return { file: relativePath, changes };
    }
    return null;
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    return { file: filePath.substring(rootDir.length + 1), error: errorMessage };
  }
}

/**
 * Main execution function
 */
async function main() {
  logger.info('🔧 BULK FIXING LOGGER IMPORTS...');
  logger.info('Target: All *.js files -> utils/loggerWrapper.js');
  
  const results = [];
  let totalChanges = 0;

  for await (const filePath of walk(rootDir)) {
    const result = await fixFile(filePath);
    if (result) {
      results.push(result);
      if ('changes' in result) {
        totalChanges += result.changes;
      }
    }
  }

  logger.info('📊 RESULTS');
  logger.info(`Processed files: ${results.length}`);
  logger.info(`Import paths fixed: ${totalChanges}`);

  const success = results.filter((r) => 'changes' in r && r.changes > 0);
  const errors = results.filter((r) => 'error' in r);

  if (success.length > 0) {
    logger.info(`✅ Fixed ${success.length} files`);
    success.forEach((r) => logger.info(`  ✓ ${r.file} (${r.changes} changes)`));
  }
  
  if (errors.length > 0) {
    logger.error(`❌ Errors: ${errors.length}`);
    errors.forEach((r) => logger.error(`  ✗ ${r.file}: ${r.error}`));
  }
  
  if (totalChanges === 0) {
    logger.info('ℹ️ No changes needed');
  }

  logger.info('🎉 Bulk logger import fix complete!');
}

// Execute with proper error handling
main().catch((error) => {
  logger.error('Fatal error during execution:', error);
  process.exit(1);
});

