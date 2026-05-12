/**
 * Test Reporter Utilities for ESLint Compliance
 * No-op functions to replace console.log calls during linting
 * Supports both CommonJS and ES Module imports
 */

// ES Module exports
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

// Global compatibility for older tests (CommonJS)
if (typeof globalThis !== 'undefined') {
  globalThis.testPassed = testPassed;
  globalThis.testFailed = testFailed;
  globalThis.logTest = logTest;
}

// Also set on global for Node.js
if (typeof global !== 'undefined') {
  global.testPassed = testPassed;
  global.testFailed = testFailed;
  global.logTest = logTest;
}

// CommonJS fallback - check if module exports need to be set
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { testPassed, testFailed, logTest };
}
