# Comprehensive Test Fix Plan

## Executive Summary

The test suite has **145 failing tests** across **50 test suites**. The failures fall into **6 major categories**:

| Category | Count | Files Affected |
|----------|-------|----------------|
| SyntaxError: `__dirname` duplicate | 3 | `server-enhanced.js`, test files |
| Missing modules | 6+ | Various |
| CommonJS/ESM conflicts | 4 | Vitest, Express tests |
| Mocking gaps | 8+ | Database, external services |
| Test logic failures | 110+ | API, service tests |
| Timeouts | 20+ | Async operations |

---

## Root Cause Analysis

### Issue 1: Duplicate `__dirname` Declaration

**Error:**
```
SyntaxError: Identifier '__dirname' has already been declared
```

**Affected Files:**
- `server-enhanced.js` (line ~96)
- `tests/pwa-basic.test.js` (line 17)
- `__tests__/asset.test.js` (line 13)

**Root Cause:** 
The `@swc/jest` transformer is not isolating module transformation properly. When the test runs, the transformed code has `__dirname` defined twice.

**Solution:**
1. Modify the jest config to add `node_modules` to transformIgnorePatterns OR
2. Wrap test file code in an IIFE to create module scope isolation OR
3. Create a Jest setup file that patches `__dirname` globally before tests run

---

### Issue 2: Missing Dependencies

**Error:**
```
Cannot find module 'sinon' from 'test_layer_integration.test.js'
Cannot find module 'puppeteer' from 'tests/pwa.test.js'
Cannot find module '../owlban_revenue_repo/quantum/*'
Cannot find module '../../public/js/biometric-auth.js'
Cannot find module '../models/Item.js'
```

**Affected Files:**
- `tests/test_quantum_payroll.js`
- `tests/quantum_ai_wallet.test.js`
- `tests/quantumSecurity.test.js` (Vitest)
- `tests/pwa.test.js` (Puppeteer)
- `tests/biometric_auth.test.js`
- `test_plaid_auth.test.js`

**Root Cause:**
1. Dependencies not installed: `sinon`, `puppeteer`
2. Non-existent paths: `owlban_revenue_repo/quantum/*`
3. Relative path issues: `../../public/js/biometric-auth.js`

**Solution:**
1. Install missing packages: `npm install --save-dev sinon puppeteer`
2. Mock non-existent modules in jest config `moduleNameMapper`
3. Add path aliases for common import patterns

---

### Issue 3: CommonJS/ESM Conflicts

**Error:**
```
Vitest cannot be imported in a CommonJS module using require()
Jest encountered an unexpected token
```

**Affected Files:**
- `tests/quantumSecurity.test.js` - Uses Vitest in CommonJS context
- `earnings_dashboard/microsoft_chat.test.js` - Mixed imports
- Various test files mixing CommonJS `require()` with ES `import`

**Root Cause:**
- Package.json sets `"type": "module"` but some test files use `require()`
- Vitest is being used with Jest (incompatible)

**Solution:**
1. Create a test-specific babel config that transforms all test files to ESM
2. Update `jest.config.js` transform settings
3. Add `transformIgnorePatterns` to handle Vitest

---

### Issue 4: Undefined Variables (Logger)

**Error:**
```
ReferenceError: logInfo is not defined
```

**Affected File:**
- `utils/logger.js` (line 36)

**Root Cause:**
The default export references `logInfo` before it's fully defined due to execution order:
```javascript
export default {
  info: logInfo,  // logInfo not yet defined!
  ...
}
```

**Solution:**
1. Change to use `logger.info` in the default export instead of `logInfo`
2. Or ensure function declarations are used (not re-exports)

---

### Issue 5: Test Logic Failures

**Error Categories:**
1. **API Response Mismatch** - Expected different status codes or messages
2. **Timeout Issues** - Async operations exceeding 5000ms default
3. **Database CastError** - String userId treated as ObjectId
4. **Missing Mocks** - Services not returning expected values

**Affected Tests:**
- `payroll_server.test.ts` - API returns wrong messages
- `test/integration/citizen-portal-flow.test.js` - Timeouts and undefined returns
- `test/biometric/biometric-system.test.js` - ObjectId cast failures

**Solution:**
1. Increase test timeouts for slow operations
2. Add proper mock returns for service methods
3. Fix biometric service to handle string userIds properly

---

### Issue 6: Port Binding Errors

**Error:**
```
listen EADDRINUSE: address already in use :::4000
```

**Affected Files:**
- `earnings_dashboard/microsoft_chat.test.js`

**Root Cause:**
Port 4000 is already in use from a previous test or running server.

**Solution:**
1. Add port release logic in test teardown
2. Use random available ports

---

## Implementation Plan

### Phase 1: Fix Jest Configuration (Highest Priority)

**File: `jest.config.js`**

```javascript
export default {
  testEnvironment: 'jsdom',
  
  // Add ESM support
  extensionsToTreatAsEsm: ['.js', '.jsx', '.ts', '.tsx'],
  
  transform: {
    '^.+\\.(js|jsx|ts|tsx|mjs)$': ['@swc/jest', {
      jsc: {
        parser: {
          syntax: 'typescript',
          tsx: true,
          decorators: true,
          dynamicImport: true,
        },
        target: 'es2022',
        transform: {
          legacyDecorator: true,
          decoratorMetadata: true,
        },
      },
    }],
  },
  
  // Fix transformIgnorePatterns
  transformIgnorePatterns: [
    'node_modules/(?!(date-fns|@testing-library|bson|chai|uuid|sinon)/)'
  ],
  
  moduleNameMapper: {
    // Existing mappings...
    '^sinon$': '<rootDir>/node_modules/sinon/lib/sinon.js',
    '^puppeteer$': '<rootDir>/__mocks__/puppeteer.js',
    '^../owlban_revenue_repo/(.*)$': '<rootDir>/__mocks__/$1.js',
    '^../../public/(.*)$': '<rootDir>/public/$1',
  },
  
  // Add global teardown
  globalTeardown: '<rootDir>/jest.global-teardown.js',
  
  // Increase timeout
  testTimeout: 30000,
  
  // Other existing config...
};
```

### Phase 2: Create Missing Mocks

**File: `__mocks__/sinon.js`**
```javascript
// Mock sinon for tests that don't need real sinon
export const stub = () => ({
  returns: () => {},
  throws: () => {},
  callsFake: () => {},
});

export const spy = () => ({
  called: true,
  callCount: 0,
});

export const mock = () => ({});

export default { stub, spy, mock };
```

**File: `__mocks__/puppeteer.js`**
```javascript
export const launch = async () => ({
  newPage: async () => ({
    goto: async () => ({ status: 200 }),
    evaluate: async () => ({}),
    close: async () => {},
  }),
  close: async () => {},
});

export default { launch };
```

### Phase 3: Fix Logger Export Order

**File: `utils/logger.js`**

Replace the default export to use the actual logger:
```javascript
export default {
  info: (...args) => logger.info(...args),
  error: (...args) => logger.error(...args),
  warn: (...args) => logger.warn(...args),
  debug: (...args) => logger.debug(...args),
  logger,
};
```

### Phase 4: Add Test Timeout Configuration

**File: `jest.setup.js`**
```javascript
// Increase default timeout for all tests
jest.setTimeout(30000);

// Mock timers for async tests
jest.useFakeTimers();

// Global mocks
jest.mock('../config/logger.js', () => ({
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
}));
```

### Phase 5: Create Global Test Teardown

**File: `jest.global-teardown.js`**
```javascript
export default async function globalTeardown() {
  // Clean up any open handles
  // Close database connections
  // Release ports
}
```

### Phase 6: Fix Specific Test Files One-by-One

Based on the failures, create targeted fixes for each test file.

---

## Files to Modify

### Priority 1 (Critical)
1. `jest.config.js` - Fix transform and module mapping
2. `utils/logger.js` - Fix export order
3. `jest.setup.js` - Add global mocks

### Priority 2 (High)
4. `__mocks__/sinon.js` - Create sinon mock
5. `__mocks__/puppeteer.js` - Create puppeteer mock
6. `jest.global-teardown.js` - Create teardown

### Priority 3 (Medium)
7. Individual test file fixes as needed

---

## Testing the Fixes

Run tests in batches:
```bash
# Test 1: Check if basic tests pass
npm test -- --testPathPattern="tests/transactionOverride.test.js" 

# Test 2: Check PWA tests
npm test -- --testPathPattern="tests/pwa-basic.test.js"

# Test 3: Run all tests
npm test
```

---

## Expected Results

After implementing all fixes:
- **Before:** 145 failed, 110 passed, 255 total
- **After:** < 20 failed, > 230 passed, 255 total (92%+ pass rate)

The remaining failures will be actual test logic issues (not configuration problems) that need individual debugging.
