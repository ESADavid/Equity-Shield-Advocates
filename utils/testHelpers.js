/**
 * Test Helper Utilities
 * Provides global test functions for ESLint compatibility
 * @module testHelpers
 */

/**
 * Global testPassed function - used in test files to indicate test success
 * @returns {void}
 */
function testPassed() {
  console.log('TEST PASSED');
}

/**
 * Global test helpers
 * @typedef {Object} TestHelpers
 * @property {Function} testPassed - Mark a test as passed
 * @property {Function} assert - Mock assert function
 * @property {Function} expect - Expect function for test assertions
 * @property {Function} chaiExpect - Stub for chai expect
 */

/**
 * Mock assert function
 * @param {boolean} condition - Assertion condition
 * @param {string} [message='Assertion failed'] - Optional message
 * @returns {void}
 */
const assert = (condition, message = 'Assertion failed') => {
  if (!condition) {
    throw new Error(message);
  }
};

/**
 * Expect function for test assertions
 * @param {unknown} actual - Actual value
 * @returns {Object} Expect chain object
 */
const expect = (actual) => ({
toBe: (/** @type {unknown} */ expected) => {
    if (actual !== expected) {
      throw new Error(`Expected ${JSON.stringify(expected)} but got ${JSON.stringify(actual)}`);
    }
  },
  toEqual: (/** @type {unknown} */ expected) => {
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      throw new Error(`Expected ${JSON.stringify(expected)} but got ${JSON.stringify(actual)}`);
    }
  },
toBeTruthy: () => {
    if (!actual) {
      throw new Error(`Expected ${JSON.stringify(actual)} to be truthy`);
    }
  },
  toBeFalsy: () => {
    if (actual) {
      throw new Error(`Expected ${JSON.stringify(actual)} to be falsy`);
    }
  },
  toBeDefined: () => {
    if (actual === undefined) {
      throw new Error('Expected value to be defined');
    }
  },
toBeNull: () => {
    if (actual !== null) {
      throw new Error(`Expected null but got ${JSON.stringify(actual)}`);
    }
  }
});

export default { testPassed, assert, expect };
export { testPassed, assert, expect };
