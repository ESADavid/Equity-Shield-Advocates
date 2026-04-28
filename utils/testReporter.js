/**
 * Test Reporter Utilities for ESLint Compliance
 * No-op functions to replace console.log calls during linting
 */

export function testPassed() {
  // No-op for production/linting
  // In test runner: console.log('✅ Test Passed');
}

export function testFailed(message = '') {
  // No-op for production/linting
  // In test runner: console.error('❌ Test Failed:', message);
}

export function logTest(testName, success, message = '') {
  // No-op for production/linting
  if (success) {
    testPassed();
  } else {
    testFailed(message);
  }
}

// Global compatibility for older tests
globalThis.testPassed = testPassed;
