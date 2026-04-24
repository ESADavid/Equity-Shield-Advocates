/**
 * Bulk Fix Logger Imports - ESM
 * Replaces all relative loggerWrapper.js imports with absolute 'utils/loggerWrapper.js'
 */

import { readdir, readFile, writeFile, stat } from 'fs/promises';
import { dirname, join, resolve } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = resolve(__dirname, '..');

async function* walk(dir) {
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

async function fixFile(filePath) {
  try {
    const relativePath = './' + filePath.substring(rootDir.length + 1).replace(/\\/g, '/');
    let content = await readFile(filePath, 'utf8');
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
    return { file: filePath.substring(rootDir.length + 1), error: err.message };
  }
}

async function main() {
  console.log('🔧 BULK FIXING LOGGER IMPORTS...');
  console.log('Target: All *.js files -> utils/loggerWrapper.js');
  const results = [];
  let totalChanges = 0;

  for await (const filePath of walk(rootDir)) {
    const result = await fixFile(filePath);
    if (result) {
      results.push(result);
      if (result.changes !== undefined) totalChanges += result.changes;
    }
  }

  console.log('\\n📊 RESULTS');
  console.log(`Processed files: ${results.length}`);
  console.log(`Import paths fixed: ${totalChanges}`);

  const success = results.filter(r => r.changes > 0);
  const errors = results.filter(r => r.error);

  if (success.length > 0) {
    console.log(`✅ Fixed ${success.length} files`);
    success.forEach(r => console.log(`  ✓ ${r.file} (${r.changes} changes)`));
  }
  if (errors.length > 0) {
    console.log(`❌ Errors: ${errors.length}`);
    errors.forEach(r => console.log(`  ✗ ${r.file}: ${r.error}`));
  }
  if (totalChanges === 0) console.log('ℹ️ No changes needed');

  console.log('\\n🎉 Bulk logger import fix complete!');
}

main().catch(console.error);
