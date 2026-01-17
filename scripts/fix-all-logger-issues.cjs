#!/usr/bin/env node

/**
 * Fix All Logger Import Issues
 * Systematically fixes all undefined logger references
 */

const fs = require('fs');
const path = require('path');

console.log('🔧 FIXING ALL LOGGER IMPORT ISSUES\n');
console.log('='.repeat(60));

const fixes = [];
const errors = [];

// Fix routes/ubiRoutes.js
console.log('\n📝 Fixing routes/ubiRoutes.js...');
try {
  const filePath = path.join(process.cwd(), 'routes', 'ubiRoutes.js');
  if (fs.existsSync(filePath)) {
    let content = fs.readFileSync(filePath, 'utf8');
    
    // Check if logger import is missing
    if (!content.includes('loggerWrapper') && !content.includes('import.*logger')) {
      // Add logger import at the top
      const lines = content.split('\n');
      let importIndex = 0;
      
      // Find last import statement
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].trim().startsWith('import ')) {
          importIndex = i + 1;
        }
      }
      
      lines.splice(importIndex, 0, "import { info, error, warn } from '../utils/loggerWrapper.js';");
      content = lines.join('\n');
      
      // Replace logger.method with method
      content = content.replace(/logger\.info\(/g, 'info(');
      content = content.replace(/logger\.error\(/g, 'error(');
      content = content.replace(/logger\.warn\(/g, 'warn(');
      
      fs.writeFileSync(filePath, content, 'utf8');
      fixes.push('routes/ubiRoutes.js');
    }
  }
} catch (err) {
  errors.push(`routes/ubiRoutes.js: ${err.message}`);
}

// Fix routes/educationRoutes.js
console.log('📝 Fixing routes/educationRoutes.js...');
try {
  const filePath = path.join(process.cwd(), 'routes', 'educationRoutes.js');
  if (fs.existsSync(filePath)) {
    let content = fs.readFileSync(filePath, 'utf8');
    
    if (!content.includes('loggerWrapper') && !content.includes('import.*logger')) {
      const lines = content.split('\n');
      let importIndex = 0;
      
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].trim().startsWith('import ')) {
          importIndex = i + 1;
        }
      }
      
      lines.splice(importIndex, 0, "import { info, error, warn } from '../utils/loggerWrapper.js';");
      content = lines.join('\n');
      
      content = content.replace(/logger\.info\(/g, 'info(');
      content = content.replace(/logger\.error\(/g, 'error(');
      content = content.replace(/logger\.warn\(/g, 'warn(');
      
      fs.writeFileSync(filePath, content, 'utf8');
      fixes.push('routes/educationRoutes.js');
    }
  }
} catch (err) {
  errors.push(`routes/educationRoutes.js: ${err.message}`);
}

// Fix services/universalBasicIncomeService.js
console.log('📝 Fixing services/universalBasicIncomeService.js...');
try {
  const filePath = path.join(process.cwd(), 'services', 'universalBasicIncomeService.js');
  if (fs.existsSync(filePath)) {
    let content = fs.readFileSync(filePath, 'utf8');
    
    if (!content.includes('loggerWrapper') && content.includes('createLogger')) {
      // Replace createLogger import with loggerWrapper
      content = content.replace(
        /import.*createLogger.*from.*config\/logger\.js.*/,
        "import { info, error, warn, debug } from '../utils/loggerWrapper.js';"
      );
      
      // Replace logger variable
      content = content.replace(/const logger = createLogger\([^)]+\);?/g, '');
      
      // Replace logger.method with method
      content = content.replace(/logger\.info\(/g, 'info(');
      content = content.replace(/logger\.error\(/g, 'error(');
      content = content.replace(/logger\.warn\(/g, 'warn(');
      content = content.replace(/logger\.debug\(/g, 'debug(');
      
      fs.writeFileSync(filePath, content, 'utf8');
      fixes.push('services/universalBasicIncomeService.js');
    }
  }
} catch (err) {
  errors.push(`services/universalBasicIncomeService.js: ${err.message}`);
}

// Fix services/aiLearningService.js
console.log('📝 Fixing services/aiLearningService.js...');
try {
  const filePath = path.join(process.cwd(), 'services', 'aiLearningService.js');
  if (fs.existsSync(filePath)) {
    let content = fs.readFileSync(filePath, 'utf8');
    
    if (!content.includes('loggerWrapper') && content.includes('createLogger')) {
      content = content.replace(
        /import.*createLogger.*from.*config\/logger\.js.*/,
        "import { info, error, warn, debug } from '../utils/loggerWrapper.js';"
      );
      
      content = content.replace(/const logger = createLogger\([^)]+\);?/g, '');
      content = content.replace(/logger\.info\(/g, 'info(');
      content = content.replace(/logger\.error\(/g, 'error(');
      content = content.replace(/logger\.warn\(/g, 'warn(');
      content = content.replace(/logger\.debug\(/g, 'debug(');
      
      fs.writeFileSync(filePath, content, 'utf8');
      fixes.push('services/aiLearningService.js');
    }
  }
} catch (err) {
  errors.push(`services/aiLearningService.js: ${err.message}`);
}

// Print results
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
  console.log('\n🎉 All logger issues fixed!');
  process.exit(0);
} else {
  console.log('\n⚠️  Some files had errors');
  process.exit(1);
}
