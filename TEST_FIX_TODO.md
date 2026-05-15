# Test Fix TODO - Comprehensive Execution

## Information Gathered

From analyzing the test failure output and codebase:

### Main Test Issues Identified:
1. **QuickBooksPayrollIntegration** - Missing `createPayrollRun` function
2. **payroll_api.js** - Uses `logger` without importing it  
3. **test_plaid_auth.test.js** - Missing module mock for `../models/Item.js`
4. **Biometric tests** - Using string userIds ("test-user-123") but Mongoose expects ObjectId
5. **Port 4000 conflict** - EADDRINUSE error in server tests
6. **MongoDB timeouts** - Database connection timeout issues
7. **Module resolution** - Various path/mapping issues
8. **Test logic issues** - Wrong status codes, undefined results

## Fix Plan

### Step 1: Fix QuickBooksPayrollIntegration
- Add missing `createPayrollRun()` method to quickbooks_payroll_integration.js

### Step 2: Fix payroll_api.js 
- Add import for logger

### Step 3: Fix test_plaid_auth.test.js
- Add Jest mock for Item model

### Step 4: Fix Biometric Tests
- Update tests to use valid ObjectId format or mock properly

### Step 5: Fix Other Test Issues
- Address port conflicts, timeouts, and logic issues

### Step 6: Run Tests
- Execute test suite and verify fixes

## Implementation Order

1. ✅ Create this TODO
2. 🔄 Fix quickbooks_payroll_integration.js - Add createPayrollRun
3. ⏳ Fix payroll_api.js - Add logger import
4. ⏳ Fix test modules/mocks
5. ⏳ Fix biometric tests
6. ⏳ Run and verify tests
