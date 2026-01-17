#!/usr/bin/env node

/**
 * Make All Phase 2 Systems Non-Fatal
 * Converts all process.exit(1) calls to warnings for Phase 2 systems
 */

const fs = require('fs');
const path = require('path');

console.log('🔧 MAKING ALL PHASE 2 SYSTEMS NON-FATAL\n');
console.log('='.repeat(60));

const serverPath = path.join(process.cwd(), 'server-enhanced.js');

if (!fs.existsSync(serverPath)) {
  console.log('❌ server-enhanced.js not found');
  process.exit(1);
}

let content = fs.readFileSync(serverPath, 'utf8');
let changesMade = 0;

// List of systems to make non-fatal
const systemsToFix = [
  'UBI system',
  'Education system',
  'Partner system',
  'Citizen portal',
  'UBI payment system',
  'notification routes'
];

systemsToFix.forEach(system => {
  const errorPattern = new RegExp(
    `(logger\\.error\\('❌ Failed to load ${system}:',.*?\\);)\\s*process\\.exit\\(1\\);`,
    'g'
  );
  
  const replacement = `$1\n  logger.info('   Server will continue without ${system} routes');`;
  
  const before = content;
  content = content.replace(errorPattern, replacement);
  
  if (content !== before) {
    console.log(`✓ Made ${system} non-fatal`);
    changesMade++;
  }
});

// Also make ITG system non-fatal
const itgPattern = /(logger\.error\('❌ Failed to load ITG system:',.*?\);)\s*process\.exit\(1\);/g;
content = content.replace(itgPattern, "$1\n  logger.info('   Server will continue without ITG routes');");
if (content.match(/Server will continue without ITG routes/)) {
  console.log('✓ Made ITG system non-fatal');
  changesMade++;
}

fs.writeFileSync(serverPath, content, 'utf8');

console.log('\n' + '='.repeat(60));
console.log(`\n📊 RESULTS: ${changesMade} systems made non-fatal\n`);

if (changesMade > 0) {
  console.log('✅ All Phase 2 systems are now non-fatal');
  console.log('   Server will start even if some systems fail to load\n');
  process.exit(0);
} else {
  console.log('⚠️  No changes made - systems may already be non-fatal\n');
  process.exit(0);
}
