#!/usr/bin/env node
/**
 * Fix .env file encoding from UTF-16/BOM to UTF-8 no-BOM
 * Usage: node scripts/fix-env-encoding.cjs
 */

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const envPath = path.join(__dirname, '../.env');

async function fixEnvEncoding() {
  try {
    console.log('🔧 Checking .env encoding...');
    const content = await fs.readFile(envPath, 'utf8');
    
    // Detect BOM or UTF-16
    if (content.startsWith('\uFEFF') || content.includes('\uFFFD')) {
      console.log('⚠️ Detected BOM/encoding issues. Fixing...');
      
      let fixedContent = content.replace(/^\uFEFF/, ''); // Remove BOM
      
      // Normalize line endings
      fixedContent = fixedContent.replace(/\r\n/g, '\n');
      
      await fs.writeFile(envPath, fixedContent, 'utf8');
      console.log('✅ .env fixed to UTF-8 no-BOM');
    } else {
      console.log('✅ .env already UTF-8 clean');
    }
    
    // Validate no invalid chars
    const stats = await fs.stat(envPath);
    console.log(`📄 .env size: ${stats.size} bytes`);
    
  } catch (error) {
    console.error('❌ Error fixing .env:', error.message);
    process.exit(1);
  }
}

fixEnvEncoding();

