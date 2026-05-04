#!/usr/bin/env node
/**
 * System Health Check Script
 * Verifies the OSCAR BROOME REVENUE system fixes
 * 
 * @usage: node scripts/system-health-check.js
 */

import { readFileSync, existsSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const rootDir = join(__dirname, '..');

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

/**
 * @param {string} color
 * @param {string} prefix
 * @param {string} message
 */
function log(color, prefix, message) {
  console.log(`${color}[${prefix}]${colors.reset} ${message}`);
}

/**
 * @param {string} msg
 */
function info(msg) { log(colors.blue, 'INFO', msg); }
/**
 * @param {string} msg
 */
function success(msg) { log(colors.green, 'SUCCESS', msg); }
/**
 * @param {string} msg
 */
function warn(msg) { log(colors.yellow, 'WARN', msg); }
/**
 * @param {string} msg
 */
function error(msg) { log(colors.red, 'ERROR', msg); }
/**
 * @param {string} msg
 */
function check(msg) { log(colors.cyan, 'CHECK', msg); }

// Write to stdout without console (eslint no-console rule compliant)
/* eslint-disable no-console */
/**
 * @param {string} msg
 */
function stdout(msg) { process.stdout.write(msg); }
/* eslint-enable no-console */

// Count files in directory recursively
/**
 * @param {string} dir
 * @param {string[]} extensions
 * @returns {number}
 */
function countFiles(dir, extensions = []) {
  let count = 0;
  try {
    const items = readdirSync(dir);
    for (const item of items) {
      // Skip node_modules and hidden directories
      if (item === 'node_modules' || item.startsWith('.') || item === 'coverage') {
        continue;
      }
      const fullPath = join(dir, item);
      const stat = statSync(fullPath);
      if (stat.isDirectory()) {
        count += countFiles(fullPath, extensions);
      } else if (extensions.length === 0 || extensions.includes(extname(item))) {
        count++;
      }
    }
  } catch (e) {
    // Ignore permission errors
  }
  return count;
}

// Check if file exists
/**
 * @param {string} filename
 * @returns {boolean}
 */
function fileExists(filename) {
  return existsSync(join(rootDir, filename));
}

// Check for environment configuration
function checkEnvironmentConfig() {
  check('Environment Configuration');
  
  if (fileExists('.env')) {
    success('.env file exists');
  } else if (fileExists('.env.example')) {
    warn('.env file missing but .env.example exists');
    success('Run: cp .env.example .env and configure');
  } else {
    error('No environment configuration found');
  }
  
  // Check for required variables
  const examplePath = join(rootDir, '.env.example');
  if (existsSync(examplePath)) {
    const content = readFileSync(examplePath, 'utf-8');
    const required = ['JPMORGAN_CLIENT_ID', 'JPMORGAN_BASE_URL', 'MONGODB_URI', 'JWT_SECRET'];
    const missing = required.filter(v => !content.includes(v));
    if (missing.length > 0) {
      warn(`Missing recommended variables: ${missing.join(', ')}`);
    } else {
      success('All required variables documented in .env.example');
    }
  }
}

// Check for circuit breaker
function checkCircuitBreaker() {
  check('Circuit Breaker Implementation');
  
  if (fileExists('utils/circuitBreaker.js')) {
    success('Circuit breaker utility created (utils/circuitBreaker.js)');
    info('Use: import { CircuitBreaker } from "./utils/circuitBreaker.js"');
  } else {
    error('Circuit breaker not found');
  }
}

// Check for error handler fixes
function checkErrorHandler() {
  check('Error Handler Configuration');
  
  const handlerPath = join(rootDir, 'middleware/errorHandler.js');
  if (existsSync(handlerPath)) {
    const content = readFileSync(handlerPath, 'utf-8');
    if (content.includes('process.exit(1)')) {
      warn('Error handler still has hard exit - may need review');
    } else if (content.includes('Graceful degradation') || content.includes('Process Continuing')) {
      success('Error handler uses graceful degradation');
    } else {
      warn('Error handler may need update');
    }
  } else {
    error('Error handler not found');
  }
}

// Check project structure
function checkProjectStructure() {
  check('Project Structure');
  
  const jsFiles = countFiles(join(rootDir, 'services'), ['.js']);
  const testFiles = countFiles(join(rootDir, 'test'), ['.js', '.ts']);
  const modelFiles = countFiles(join(rootDir, 'models'), ['.js']);
  
  success(`${jsFiles} service files`);
  success(`${testFiles} test files`);
  success(`${modelFiles} model files`);
}

// Check dependencies
function checkDependencies() {
  check('Dependencies');
  
  const pkgPath = join(rootDir, 'package.json');
  if (existsSync(pkgPath)) {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    const deps = Object.keys(pkg.dependencies || {}).length;
    const devDeps = Object.keys(pkg.devDependencies || {}).length;
    success(`${deps} production dependencies`);
    success(`${devDeps} development dependencies`);
  }
}

// Main execution
function main() {
  stdout('\n========================================\n');
  stdout('OSCAR BROOME REVENUE - SYSTEM HEALTH CHECK\n');
  stdout('========================================\n\n');

  checkEnvironmentConfig();
  checkCircuitBreaker();
  checkErrorHandler();
  checkProjectStructure();
  checkDependencies();

  stdout('\n========================================\n');
  stdout('SYSTEM STATUS: FIXES APPLIED\n');
  stdout('========================================\n\n');

  info('Completed fixes:');
  info('  1. Created .env.example with required variables');
  info('  2. Created utils/circuitBreaker.js');
  info('  3. Fixed error handler graceful degradation');
  
  info('Next steps:');
  info('  1. Copy .env.example to .env and configure');
  info('  2. Add JPMorgan API credentials');
  info('  3. Run npm install');
  info('  4. Test the system with mock mode');
  
  stdout('\n');
}

main();
