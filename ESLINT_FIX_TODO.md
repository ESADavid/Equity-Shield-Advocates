# ESLint Fix Plan - Fix All 425 Errors

## Error Summary
- Total: 425 problems (398 errors, 27 warnings)
- Categories:
  1. `testPassed` is not defined: ~250 errors
  2. Unicode parsing errors (✅, ❌, ⚠️): ~30 errors
  3. Syntax errors (unterminated strings, missing parens): ~15 errors
  4. Unused variables: ~10 errors
  5. Console warnings: ~27 warnings

## Fix Strategy

### Step 1: Create test utility with testPassed function
- Location: utils/testHelpers.js

### Step 2: Fix Unicode characters in files
- Replace emojis with text alternatives
- Files: comprehensive_payroll_test.js, test_oauth_implementation.js, etc.

### Step 3: Fix syntax errors
- Unterminated strings
- Invalid regex
- Missing parentheses

### Step 4: Fix unused variables
- Add to eslint ignore or prefix with underscore

### Step 5: Verify with npm run lint

## Files to Fix (Priority Order)

### Priority 1: Core test files with testPassed
- debug_test.js
- test_wallet_decryption.js
- test_auth_system.js
- test_endpoint.js
- run_tests*.js

### Priority 2: Files with Unicode errors
- comprehensive_payroll_test.js (line 425: ❌)
- test_oauth_implementation.js (✅)
- comprehensive_treasury_test.js (✅)
- etc.

### Priority 3: Other parsing errors
- critical_path_test.js
- performance_test.js
- etc.

## TODO:
- [ ] Create utils/testHelpers.js with testPassed function
- [ ] Fix files with testPassed errors
- [ ] Fix Unicode character errors
- [ ] Fix remaining syntax errors
- [ ] Run npm run lint to verify
