# Test Fix Plan

## Summary of Test Failures

### 1. tests/service_worker.test.js
**Error:** Cannot find module '../../public/sw.js'

**Root Cause:** The Jest config moduleNameMapper doesn't include a mapping for `public/*` paths. The test is trying to require `../../public/sw.js` but Jest can't resolve it.

**Fix:** Add a moduleNameMapper entry in jest.config.js to map public files correctly.

---

### 2. quickbooks_payroll_integration.test.ts
**Errors:**
1. ReferenceError: setImmediate is not defined
2. Tests expect response.message to match /Missing bank account/ but receive "Failed to update payroll data"
3. Tests expect response.data.length to be greater than 0 but get success: false
4. TypeError: integration.createPayrollRun is not a function

**Root Cause:** 
- The test environment doesn't have setImmediate polyfilled
- The implementation returns early with `{ success: false, message }` when bank account is missing, but the test expects data to be returned 
- The getAllEmployees mock response structure doesn't match what the implementation expects
- The test is importing a different file than the one with createPayrollRun

**Fix:**
- Add setImmediate polyfill in jest.setup.js
- Update the test expectations or implementation to match
- Add proper mock responses for getAllEmployees
- Ensure correct import path

---

### 3. earnings_dashboard/update_revenue_data.test.js
**Error:** Cannot find module './update_revenue_data'

**Root Cause:** The test is located at `earnings_dashboard/update_revenue_data.test.js` but trying to import from `./update_revenue_data` which should resolve to `earnings_dashboard/update_revenue_data.js`. This might be a jest config issue with module resolution.

**Fix:** Ensure jest properly resolves the module. May need to add moduleNameMapper or fix the test file location.

---

## Implementation Plan

### Step 1: Fix jest.config.js
Add public path mapping:
```javascript
'^public/(.*)$': '<rootDir>/public/$1',
```

### Step 2: Fix jest.setup.js
Add setImmediate polyfill if not present:
```javascript
global.setImmediate = global.setImmediate || ((fn, ...args) => setTimeout(() => fn(...args), 0));
```

### Step 3: Fix quickbooks_payroll_integration.test.ts
- Fix mock responses to match implementation expectations
- Ensure createPayrollRun is available in the integration instance

### Step 4: Fix update_revenue_data test
- Verify module resolution is correct in jest.config.js

---

## Files to Modify
1. jest.config.js
2. jest.setup.js (check if exists and create if needed)
3. tests/service_worker.test.js (may need path adjustment)
4. quickbooks_payroll_integration.test.ts
