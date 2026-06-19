#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const rootDir = path.resolve('.');
const jsFiles = [];

// Find all .js files recursively
function findJSFiles(dir) {
  const items = fs.readdirSync(dir, { withFileTypes: true });
  for (const item of items) {
    const fullPath = path.join(dir, item.name);
    if (item.isDirectory()) {
      if (item.name !== 'node_modules' && item.name !== '.git') {
        findJSFiles(fullPath);
      }
    } else if (item.name.endsWith('.js')) {
      jsFiles.push(fullPath);
    }
  }
}

findJSFiles(rootDir);

console.log(`Found ${jsFiles.length} JS files`);

let fixed = 0;
const errors = [];

for (const file of jsFiles) {
  try {
    let content = fs.readFileSync(file, 'utf8');

    // Fix common patterns
    const fixes = [
      // Unterminated testPassed
      [
        /\/\*\s*console\.log\(.+?testPassed\(\);/g,
        '// console.log disabled: testPassed',
      ],
      [/testPassed\(\);/g, '// testPassed'],
      // Arrow breaks
      [/map\(\(c\) \*\/ testPassed\(\); =>/g, 'map((c) =>'],
      [/every\(\(c\) \*\/ testPassed\(\); =>/g, 'every((c) =>'],
      // Extra );
      [/\); \*\/ testPassed\(\);/g, ')'],
      // Shebang after import
      [
        /import .+?\n\n#!\/usr\/bin\/env node/g,
        'const logger = require("utils/loggerWrapper.js").info;',
      ],
      // import.meta in cjs
      [/import\.meta\.url/g, '__filename'],
    ];

    let changed = false;
    for (const [pattern, replacement] of fixes) {
      const newContent = content.replace(pattern, replacement);
      if (newContent !== content) {
        changed = true;
        content = newContent;
      }
    }

    if (changed) {
      fs.writeFileSync(file, content);
      console.log(`Fixed: ${path.relative('.', file)}`);
      fixed++;
    }
  } catch (e) {
    errors.push(`${file}: ${e.message}`);
  }
}

console.log(`\\n✅ Fixed ${fixed} files`);
if (errors.length) {
  console.log('Errors:', errors.join('\\n'));
}

console.log('Run: npx prettier --write . && npm run lint');
