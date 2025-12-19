/**
 * PHASE 3 TEST RUNNER
 * Executes all Phase 3 test suites
 */

import { execSync } from 'child_process';
import { createLogger } from '../config/logger.js';

const logger = createLogger('Phase3-Test-Runner');

const testSuites = {
  integration: [
    'test/integration/citizen-portal-flow.test.js',
    'test/integration/partner-coordination-flow.test.js',
    'test/integration/notification-delivery-flow.test.js',
    'test/integration/pmc-operations-flow.test.js'
  ],
  api: [
    'test/api/notification-endpoints.test.js',
    'test/api/partner-endpoints.test.js',
    'test/api/citizen-portal-endpoints.test.js'
  ],
  security: [
    'test/security/input-validation.test.js',
    'test/security/data-sanitization.test.js'
  ],
  performance: [
    'test/performance/service-performance.test.js'
  ],
  uat: [
    'test/uat/user-workflows.test.js'
  ]
};

async function runTestSuite(suiteName, tests) {
  logger.info(`\n${'='.repeat(60)}`);
  logger.info(`Running ${suiteName.toUpperCase()} Tests`);
  logger.info('='.repeat(60));

  for (const test of tests) {
    try {
      logger.info(`\nExecuting: ${test}`);
      execSync(`npm test ${test}`, { stdio: 'inherit' });
      logger.info(`✅ ${test} - PASSED`);
    } catch (error) {
      logger.error(`❌ ${test} - FAILED`);
    }
  }
}

async function runAllTests() {
  logger.info('\n🚀 Starting Phase 3 Comprehensive Testing\n');

  const startTime = Date.now();

  for (const [suiteName, tests] of Object.entries(testSuites)) {
    await runTestSuite(suiteName, tests);
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);

  logger.info('\n' + '='.repeat(60));
  logger.info('Phase 3 Testing Complete');
  logger.info('='.repeat(60));
  logger.info(`Total Duration: ${duration} seconds`);
  logger.info(`Test Files: ${Object.values(testSuites).flat().length}`);
  logger.info('\n✅ Phase 3 Testing Framework Operational\n');
}

runAllTests().catch(error => {
  logger.error('Test execution failed:', error);
  process.exit(1);
});
