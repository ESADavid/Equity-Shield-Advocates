#!/usr/bin/env node

/**
 * Fix Phase 2 Logger Imports
 * Fixes all createLogger imports in Phase 2 files
 */

const fs = require('fs');
const path = require('path');

console.log('🔧 FIXING PHASE 2 LOGGER IMPORTS\n');
console.log('='.repeat(60));

const filesToFix = [
  'routes/partnerRoutes.js',
  'routes/citizenPortalRoutes.js',
  'routes/notificationRoutes.js',
  'routes/ubiPaymentRoutes.js',
  'services/partnerCoordinationService.js',
  'services/pmcIntegrationService.js',
  'services/citizenPortalService.js',
  'services/multiChannelNotificationService.js',
  'services/ubiPaymentService.js',
  'services/complianceMonitoringService.js'
];

const fixes = [];
const errors = [];

filesToFix.forEach(filePath => {
  const fullPath = path.join(process.cwd(), filePath);
  
  if (!fs.existsSync(fullPath)) {
    console.log(`⚠️  Skipping ${filePath} (not found)`);
    return;
  }
  
  try {
    let content = fs.readFileSync(fullPath, 'utf8');
    let modified = false;
    
    // Check if file has createLogger import
    if (content.includes('createLogger')) {
      console.log(`📝 Fixing ${filePath}...`);
      
      // Replace createLogger import with loggerWrapper
      content = content.replace(
        /import\s*{\s*createLogger\s*}\s*from\s*['"]\.\.\/config\/logger\.js['"]/g,
        "import { info, error, warn, debug } from '../utils/loggerWrapper.js'"
      );
      
      // Remove logger variable declarations
      content = content.replace(/const logger = createLogger\([^)]+\);?\s*/g, '');
      
      // Replace logger.method with method
      content = content.replace(/logger\.info\(/g, 'info(');
      content = content.replace(/logger\.error\(/g, 'error(');
      content = content.replace(/logger\.warn\(/g, 'warn(');
      content = content.replace(/logger\.debug\(/g, 'debug(');
      
      fs.writeFileSync(fullPath, content, 'utf8');
      fixes.push(filePath);
      modified = true;
    }
    
    if (!modified) {
      console.log(`✓ ${filePath} (already correct)`);
    }
  } catch (err) {
    console.log(`❌ Error fixing ${filePath}: ${err.message}`);
    errors.push(`${filePath}: ${err.message}`);
  }
});

console.log('\n' + '='.repeat(60));
console.log('\n📊 RESULTS\n');

if (fixes.length > 0) {
  console.log('✅ FIXED FILES:');
  fixes.forEach(file => console.log(`   ✓ ${file}`));
}

if (errors.length > 0) {
  console.log('\n❌ ERRORS:');
  errors.forEach(err => console.log(`   ✗ ${err}`));
}

console.log(`\n📈 Summary: ${fixes.length} files fixed, ${errors.length} errors`);

if (errors.length === 0) {
  console.log('\n🎉 All Phase 2 logger imports fixed!');
  process.exit(0);
} else {
  console.log('\n⚠️  Some files had errors');
  process.exit(1);
}
