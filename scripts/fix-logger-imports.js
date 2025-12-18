/**
 * Script to add missing logger imports to files that were modified by replace-console-logs.js
 * 
 * Usage: node scripts/fix-logger-imports.js
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Files that need logger imports (from the replace-console-logs.js output)
const filesToFix = [
  'scripts/security-audit.js',
  'server-enhanced.js',
  'server-quantum.js',
  'server-simple.js',
  'server_with_auth.js',
  'services/assetManagementService.js',
  'services/debtAcquisitionService.js',
  'services/haitiStrategicService.js',
  'services/nvidiaBlackwellService.js',
  'services/plaidService.js',
  'services/privateBankingService.js',
  'setup_credentials.js',
  'setup_jpmorgan_credentials.js',
  'simple_jpmorgan_validation.js',
  'staging_deployment.js'
];

const stats = {
  filesProcessed: 0,
  filesFixed: 0,
  filesSkipped: 0,
  errors: 0
};

/**
 * Determine the correct import path based on file location
 */
function getLoggerImportPath(filePath) {
  const depth = filePath.split('/').length - 1;
  const prefix = depth === 0 ? './' : '../'.repeat(depth);
  return `${prefix}utils/loggerWrapper.js`;
}

/**
 * Check if file already has logger import
 */
function hasLoggerImport(content) {
  return content.includes('from \'./utils/loggerWrapper.js\'') ||
         content.includes('from \'../utils/loggerWrapper.js\'') ||
         content.includes('from \'../../utils/loggerWrapper.js\'') ||
         content.includes('from \'../../../utils/loggerWrapper.js\'') ||
         content.includes('import logger from') ||
         content.includes('import { info, error, warn, debug } from');
}

/**
 * Check if file uses logger methods
 */
function usesLogger(content) {
  return content.includes('logger.info(') ||
         content.includes('logger.error(') ||
         content.includes('logger.warn(') ||
         content.includes('logger.debug(');
}

/**
 * Add logger import to file
 */
function addLoggerImport(content, importPath) {
  // Find the best place to add the import
  const lines = content.split('\n');
  let insertIndex = 0;
  let foundImports = false;

  // Skip shebang if present
  if (lines[0].startsWith('#!')) {
    insertIndex = 1;
  }

  // Find the last import statement
  for (let i = insertIndex; i < lines.length; i++) {
    if (lines[i].trim().startsWith('import ') || lines[i].trim().startsWith('const ') && lines[i].includes('require(')) {
      foundImports = true;
      insertIndex = i + 1;
    } else if (foundImports && lines[i].trim() === '') {
      // Found empty line after imports
      break;
    } else if (foundImports && !lines[i].trim().startsWith('import ') && !lines[i].trim().startsWith('//')) {
      // Found non-import, non-comment line
      break;
    }
  }

  // Create the import statement
  const importStatement = `import logger from '${importPath}';`;

  // Insert the import
  lines.splice(insertIndex, 0, importStatement);

  // Add empty line after imports if not present
  if (lines[insertIndex + 1] && lines[insertIndex + 1].trim() !== '') {
    lines.splice(insertIndex + 1, 0, '');
  }

  return lines.join('\n');
}

/**
 * Process a single file
 */
function processFile(filePath) {
  const fullPath = path.resolve(process.cwd(), filePath);
  
  if (!fs.existsSync(fullPath)) {
    console.log(`⚠️  File not found: ${filePath}`);
    stats.filesSkipped++;
    return;
  }

  stats.filesProcessed++;

  try {
    const content = fs.readFileSync(fullPath, 'utf8');

    // Check if file uses logger
    if (!usesLogger(content)) {
      console.log(`⏭️  ${filePath} - No logger usage found`);
      stats.filesSkipped++;
      return;
    }

    // Check if import already exists
    if (hasLoggerImport(content)) {
      console.log(`✅ ${filePath} - Already has logger import`);
      stats.filesSkipped++;
      return;
    }

    // Add logger import
    const importPath = getLoggerImportPath(filePath);
    const newContent = addLoggerImport(content, importPath);

    // Write the file
    fs.writeFileSync(fullPath, newContent, 'utf8');
    console.log(`✅ ${filePath} - Added logger import`);
    stats.filesFixed++;

  } catch (error) {
    console.error(`❌ Error processing ${filePath}:`, error.message);
    stats.errors++;
  }
}

/**
 * Main execution
 */
function main() {
  console.log('🔧 Logger Import Fix Script\n');
  console.log('Adding missing logger imports to modified files...\n');
  console.log('='.repeat(80));

  const startTime = Date.now();

  for (const file of filesToFix) {
    processFile(file);
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);

  console.log('\n' + '='.repeat(80));
  console.log('\n📊 Summary:');
  console.log(`   Files processed: ${stats.filesProcessed}`);
  console.log(`   Files fixed: ${stats.filesFixed}`);
  console.log(`   Files skipped: ${stats.filesSkipped}`);
  console.log(`   Errors: ${stats.errors}`);
  console.log(`\n⏱️  Completed in ${duration}s`);

  if (stats.filesFixed > 0) {
    console.log('\n✅ Logger imports have been added successfully!');
    console.log('\n📝 Next Steps:');
    console.log('   1. Review the changes');
    console.log('   2. Run tests to verify everything works');
    console.log('   3. Run ESLint to check for any issues');
  }
}

// Run the script
main();
