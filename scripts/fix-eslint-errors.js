import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { info, error } from '../utils/loggerWrapper.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Files with merge conflicts to fix
const mergeConflictFiles = [
  'earnings_dashboard/jpmorgan_payment.js',
  'earnings_dashboard/merchant_bill_pay.js',
  'services/assetManagementService.js',
];

// Files that need logger imports (sampling - we'll add more as we go)
const loggerImportFiles = [
  'create_oscar_broome_login_simple.js',
  'earnings_dashboard/analytics_router.js',
  'earnings_dashboard/notification_service.js',
  'earnings_dashboard/payment.js',
  'earnings_dashboard/payment_router.js',
  'earnings_dashboard/payroll_api.js',
  'earnings_dashboard/payroll_router.js',
  'earnings_dashboard/wallet_endpoints.js',
  'middleware/authOverride.js',
  'routes/auth.js',
  'routes/itgRoutes.js',
  'routes/plaidRoutes.js',
  'routes/transactionOverrideRoutes.js',
];

function resolveMergeConflicts(filePath) {
  try {
    const fullPath = path.join(process.cwd(), filePath);
    if (!fs.existsSync(fullPath)) {
      info(`⚠️  File not found: ${filePath}`);
      return false;
    }

    let content = fs.readFileSync(fullPath, 'utf-8');

    // Check if file has merge conflicts
    if (!content.includes('<<<<<<< HEAD')) {
      info(`✓ No merge conflicts in: ${filePath}`);
      return true;
    }

    // Resolve conflicts by keeping the HEAD version (current branch)
    // This regex matches the entire conflict block and keeps only the HEAD section
    content = content.replace(
      /<<<<<<< HEAD\n([\s\S]*?)\n=======\n[\s\S]*?\n>>>>>>> [^\n]+\n/g,
      '$1\n'
    );

    fs.writeFileSync(fullPath, content, 'utf-8');
    info(`✓ Resolved merge conflicts in: ${filePath}`);
    return true;
  } catch (err) {
    error(`✗ Error resolving conflicts in ${filePath}:`, err);
    return false;
  }
}

function addLoggerImport(filePath) {
  try {
    const fullPath = path.join(process.cwd(), filePath);
    if (!fs.existsSync(fullPath)) {
      info(`⚠️  File not found: ${filePath}`);
      return false;
    }

    let content = fs.readFileSync(fullPath, 'utf-8');

    // Check if logger is already imported
    if (content.includes('import') && content.includes('logger')) {
      info(`✓ Logger already imported in: ${filePath}`);
      return true;
    }

    // Check if file uses logger
    if (!content.includes('logger.')) {
      info(`ℹ️  File doesn't use logger: ${filePath}`);
      return true;
    }

    // Add logger import at the top after other imports
    const lines = content.split('\n');
    let insertIndex = 0;

    // Find the last import statement
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].trim().startsWith('import ')) {
        insertIndex = i + 1;
      }
    }

    // Determine the correct path to logger based on file location
    const fileDir = path.dirname(filePath);
    const loggerPath = path
      .relative(fileDir, 'config/logger.js')
      .replace(/\\/g, '/');
    const importPath = loggerPath.startsWith('.')
      ? loggerPath
      : `./${loggerPath}`;

    // Insert logger import
    const loggerImport = `import logger from '${importPath}';`;
    lines.splice(insertIndex, 0, loggerImport);

    content = lines.join('\n');
    fs.writeFileSync(fullPath, content, 'utf-8');
    info(`✓ Added logger import to: ${filePath}`);
    return true;
  } catch (err) {
    error(`✗ Error adding logger import to ${filePath}:`, err);
    return false;
  }
}

info('🔧 Starting ESLint Error Fixes...\n');

info('📝 Phase 1: Resolving Merge Conflicts');
info('=====================================');
let conflictsResolved = 0;
for (const file of mergeConflictFiles) {
  if (resolveMergeConflicts(file)) {
    conflictsResolved++;
  }
}
info(
  `\n✓ Resolved ${conflictsResolved}/${mergeConflictFiles.length} merge conflicts\n`
);

info('📝 Phase 2: Adding Logger Imports');
info('==================================');
let importsAdded = 0;
for (const file of loggerImportFiles) {
  if (addLoggerImport(file)) {
    importsAdded++;
  }
}
info(
  `\n✓ Processed ${importsAdded}/${loggerImportFiles.length} files for logger imports\n`
);

info('✅ ESLint error fixes completed!');
info('\nNext steps:');
info('1. Run: npm run lint');
info('2. Review remaining errors');
info('3. Fix any remaining issues manually');
