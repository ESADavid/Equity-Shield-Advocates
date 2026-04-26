/* eslint-disable no-console */
/**
 * Script to identify and help replace console.log statements with proper logging
 *
 * Usage: node scripts/replace-console-logs.js [--dry-run] [--path=<directory>]
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const config = {
  dryRun: process.argv.includes('--dry-run'),
  targetPath: (
    process.argv.find((arg) => arg.startsWith('--path=')) || '--path=.'
  ).split('=')[1],
  excludeDirs: [
    'node_modules',
    '.git',
    'dist',
    'build',
    'coverage',
    'logs',
    'owlban_repos',
    'David-Leeper-Jr-Revenue',
    'FOUR-ERA-AI',
    'gh',
    'gh-extracted',
  ],
  excludeFiles: [
    'replace-console-logs.js',
    'babel.config.js',
    'babel.config.cjs',
  ],
  testFilePatterns: [
    /test.*\.js$/,
    /.*\.test\.js$/,
    /.*\.spec\.js$/,
    /cypress\//,
  ],
};

// Statistics
const stats = {
  filesScanned: 0,
  filesWithConsole: 0,
  totalConsoleStatements: 0,
  productionFiles: 0,
  testFiles: 0,
  replacements: 0,
};

// Console statement patterns
const consolePatterns = {
  log: /console\.log\(/g,
  error: /console\.error\(/g,
  warn: /console\.warn\(/g,
  info: /console\.info\(/g,
  debug: /console\.debug\(/g,
};

/**
 * Check if path should be excluded
 */
function shouldExclude(filePath) {
  const relativePath = path.relative(process.cwd(), filePath);

  // Check excluded directories
  for (const dir of config.excludeDirs) {
    if (relativePath.includes(dir)) return true;
  }

  // Check excluded files
  const fileName = path.basename(filePath);
  if (config.excludeFiles.includes(fileName)) return true;

  return false;
}

/**
 * Check if file is a test file
 */
function isTestFile(filePath) {
  const relativePath = path.relative(process.cwd(), filePath);
  return config.testFilePatterns.some((pattern) => pattern.test(relativePath));
}

/**
 * Find console statements in content
 */
function findConsoleStatements(content) {
  const statements = [];

  for (const [type, pattern] of Object.entries(consolePatterns)) {
    const matches = content.matchAll(pattern);
    for (const match of matches) {
      statements.push({
        type,
        index: match.index,
        statement: match[0],
      });
    }
  }

  return statements.sort((a, b) => a.index - b.index);
}

/**
 * Generate replacement suggestion
 */
function generateReplacement(statement, type) {
  const replacements = {
    log: 'info',
    error: 'error',
    warn: 'warn',
    info: 'info',
    debug: 'debug',
  };

  const loggerMethod = replacements[type] || 'info';
  return statement.replace(`console.${type}(`, `logger.${loggerMethod}(`);
}

/**
 * Replace console statements in file
 */
function replaceConsoleInFile(filePath, content) {
  let newContent = content;
  let replacementCount = 0;

  // Add import if not present
  if (
    !newContent.includes('import') &&
    !newContent.includes("from 'utils/loggerWrapper.js'")
  ) {
    newContent = `import { info, error, warn, debug } from 'utils/loggerWrapper.js';\n\n${newContent}`;
  }

  // Replace console statements
  for (const [type, pattern] of Object.entries(consolePatterns)) {
    const loggerMethod = type === 'log' ? 'info' : type;
    const replacement = `logger.${loggerMethod}(`;
    const count = (newContent.match(pattern) || []).length;
    newContent = newContent.replace(pattern, replacement);
    replacementCount += count;
  }

  return { newContent, replacementCount };
}

/**
 * Process a single file
 */
function processFile(filePath) {
  if (shouldExclude(filePath)) return;
  if (!filePath.endsWith('.js')) return;

  stats.filesScanned++;

  const content = fs.readFileSync(filePath, 'utf8');
  const statements = findConsoleStatements(content);

  if (statements.length === 0) return;

  stats.filesWithConsole++;
  stats.totalConsoleStatements += statements.length;

  const isTest = isTestFile(filePath);
  if (isTest) {
    stats.testFiles++;
  } else {
    stats.productionFiles++;
  }

  const relativePath = path.relative(process.cwd(), filePath);

  /* console.log(`\n📄 ${relativePath}`); */
  /* console.log(
    `   Type: ${isTest ? '🧪 TEST FILE (keep console) */' : '⚠️  PRODUCTION FILE (needs replacement)'}`
  );
  /* console.log(`   Console statements: ${statements.length}`); */

  if (!isTest) {
    statements.forEach((stmt, idx) => {
      const lineNumber = content.substring(0, stmt.index).split('\n').length;
      const suggestion = generateReplacement(stmt.statement, stmt.type);
      /* console.log(
        `   ${idx + 1}. Line ${lineNumber}: ${stmt.statement} → ${suggestion}`
      ); */
    });

    if (!config.dryRun) {
      const { newContent, replacementCount } = replaceConsoleInFile(
        filePath,
        content
      );
      fs.writeFileSync(filePath, newContent, 'utf8');
      stats.replacements += replacementCount;
      /* console.log(`   ✅ Replaced ${replacementCount} statements`); */
    }
  }
}

/**
 * Process directory recursively
 */
function processDirectory(dirPath) {
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);

    if (entry.isDirectory()) {
      if (!shouldExclude(fullPath)) {
        processDirectory(fullPath);
      }
    } else if (entry.isFile()) {
      processFile(fullPath);
    }
  }
}

/**
 * Main execution
 */
function main() {
  /* console.log('🔍 Console.log Replacement Script\n'); */
  /* console.log(
    `Mode: ${config.dryRun ? 'DRY RUN (no changes) */' : 'REPLACE MODE'}`
  );
  /* console.log(`Target: ${config.targetPath}\n`); */
  /* console.log('='.repeat(80) */);

  const startTime = Date.now();
  const targetPath = path.resolve(process.cwd(), config.targetPath);

  if (fs.statSync(targetPath).isDirectory()) {
    processDirectory(targetPath);
  } else {
    processFile(targetPath);
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);

  /* console.log('\n' + '='.repeat(80) */);
  /* console.log('\n📊 Summary:'); */
  /* console.log(`   Files scanned: ${stats.filesScanned}`); */
  /* console.log(`   Files with console: ${stats.filesWithConsole}`); */
  /* console.log(`   Total console statements: ${stats.totalConsoleStatements}`); */
  /* console.log(`   Production files: ${stats.productionFiles}`); */
  /* console.log(`   Test files: ${stats.testFiles} (excluded from replacement) */`);

  if (!config.dryRun) {
    /* console.log(`   ✅ Replacements made: ${stats.replacements}`); */
  } else {
    /* console.log(`\n💡 Run without --dry-run to apply changes`); */
  }

  /* console.log(`\n⏱️  Completed in ${duration}s`); */

  // Recommendations
  /* console.log('\n📝 Next Steps:'); */
  /* console.log('   1. Review the changes made'); */
  /* console.log('   2. Run tests to ensure nothing broke'); */
  /* console.log('   3. Run ESLint to check for any issues'); */
  /* console.log('   4. Commit the changes'); */
}

// Run the script
main();
