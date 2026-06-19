#!/usr/bin/env node
/* eslint-disable no-console */

import { readdirSync, readFileSync, writeFileSync } from 'fs';
import path from 'path';

const rootDir = path.resolve('.');
const jsFiles = [];

// Find all .js files recursively
function findJSFiles(dir) {
  const items = readdirSync(dir, { withFileTypes: true });
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
    let content = readFileSync(file, 'utf8');

    // Fix common patterns - simple regex
    const fixes = [
      [/testPassed\\(\\);/g, '// testPassed();'],
      [/console\.log\(/g, '// console.log('],
      [/map\\(\\(c\\) =>/g, 'map((c) =>'],
      [/every\\(\\(c\\) =>/g, 'every((c) =>'],
      [/import\\.meta\\.url/g, '__filename'],
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
      writeFileSync(file, content);
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
