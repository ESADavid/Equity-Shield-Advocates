# Test Fix Plan

## Summary of Issues Found

Based on the test execution output, there are multiple categories of test failures:

### 1. TypeScript Syntax in JavaScript Files (Critical)
- **Issue**: SWC parser configured for ECMAScript, encounters TypeScript syntax (`interface`, `as`, `: type`)
- **Affected files**: 
  - `payrollSystem.ts` imported by `.js` files
  - Multiple `.test.ts` files with TypeScript syntax
- **Root cause**: `jest.config.js` transform uses `syntax: 'ecmascript'` instead of `'typescript'`

### 2. Missing Mock Files
- **Issue**: `node-cron` mock missing at `__mocks__/node-cron.js`
- **Affected tests**: `server_rebuilt.test.js` - POST /api/sync/all

### 3. Missing Dependencies
- **Issue**: `sinon` not in package.json
- **Affected tests**: `test_layer_integration.test.js`

### 4. Module Resolution Failures
- **Issue**: Cannot find modules like `../models/Item.js`
- **Affected tests**: Multiple test files

### 5. Test Logic Issues
- Status code mismatches (expecting 200, getting 500 or 400)
- Timeout issues
- Missing logger reference in `payroll_api.js`

## Fix Plan

### Step 1: Fix Jest Configuration
Update `jest.config.js` to properly parse TypeScript:
```javascript
// Change from:
syntax: 'ecmascript'
// To:
syntax: 'typescript'
```

### Step 2: Create Missing Mock Files
- Create `__mocks__/node-cron.js`

### Step 3: Add Missing Dependencies
Add `sinon` to devDependencies in package.json

### Step 4: Fix Module Resolution
Add proper moduleNameMapper entries for models and other modules

### Step 5: Fix Test Files with TS Syntax Issues
Convert or alias TypeScript files properly

### Step 6: Fix Business Logic Issues
- Fix logger reference in `payroll_api.js`
- Fix status code returns in various endpoints

## Implementation Order

1. Fix jest.config.js (transform)
2. Create __mocks__/node-cron.js
3. Add sinon to package.json
4. Fix module mappers
5. Fix test files
6. Fix business logic

## Dependencies Between Fixes

- jest.config.js fix enables parsing of TS files
- node-cron mock creates required mock
- sinon addition fixes dependency issue
- Module mappers help with resolution
- Business logic fixes resolve test failures
