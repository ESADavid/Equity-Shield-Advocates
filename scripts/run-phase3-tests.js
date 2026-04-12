#!/usr/bin/env node

import { execSync } from 'child_process';
import { cwd } from 'node:process';
import logger from '../utils/logger.js';

const projectDir = cwd();
logger.info('🧪 Running Phase 3 Validation Suite...');

try {
  logger.info('1. Running ESLint...');
  execSync('npm run lint', { cwd: projectDir, encoding: 'utf8', stdio: 'inherit' });
  logger.info('✅ Lint passed');
} catch (err) {
  logger.error('❌ Lint failed:', err.message);
  process.exit(1);
}

try {
  logger.info('2. Running Jest tests...');
  execSync('npm test', { cwd: projectDir, encoding: 'utf8', stdio: 'inherit' });
  logger.info('✅ Tests passed');
} catch (err) {
  logger.error('❌ Tests failed:', err.message);
  process.exit(1);
}

try {
  logger.info('3. Running coverage...');
  execSync('npm run test:coverage', { cwd: projectDir, encoding: 'utf8', stdio: 'inherit' });
  logger.info('✅ Coverage report generated');
} catch (err) {
  logger.error('⚠️ Coverage warning:', err.message);
}

logger.info('🎉 Phase 3 tests COMPLETE!');

