# TypeScript Errors Fix Plan

## Summary of TypeScript Errors

Based on the TypeScript compilation output:

1. **comprehensive_payroll_test.js** (lines 425, 429):
   - `TS1127: Invalid character` - Corrupted UTF-8 characters like `â�Œ`
   
2. **public/sw.js** (line 37):
   - `TS1127: Invalid character` - Similar encoding issue
   
3. **routes/debtAcquisitionRoutes.js** (lines 557, 572):
   - `TS1005: ',' expected` - Missing comma after function
   
4. **scripts/backup-production.js**:
   - `TS8016: Type assertion expressions can only be used in TypeScript files`
   - Uses `<Type>` angle bracket type assertions in .js file
   
5. **scripts/complete-phase1-fixed.js** (line 26):
   - `TS1127: Invalid character` - Encoding issues

## Fix Plan

### Step 1: Update tsconfig.json
- Add exclusions for test files that have encoding issues
- Keep the main source code being validated

### Step 2: Fix Type Assertions in .js files
- Convert `<Type>` syntax to JSDoc comments in scripts/backup-production.js

### Step 3: Fix encoding issues
- Read and fix corrupted characters in test files

## Files to Edit
1. tsconfig.json - Update exclusions
2. scripts/backup-production.js - Fix type assertions
3. comprehensive_payroll_test.js - Fix encoding (or exclude)
4. public/sw.js - Fix encoding (or exclude)
5. scripts/complete-phase1-fixed.js - Fix encoding
