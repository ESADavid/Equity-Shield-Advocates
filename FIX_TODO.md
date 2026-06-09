# TypeScript Fixes TODO

## Plan confirmed by user - proceeding with fixes

### Step 1: Fix models/Partner.ts
- [x] Fix line 43: Change `mongoose.Decimal128` to `mongoose.Types.Decimal128`
- [x] Fix line 52: Change `mongoose.Decimal128` to `mongoose.Types.Decimal128`
- [x] Fix line 95: Add proper static method type signature for `generatePartnerId`

### Step 2: Fix services/partnerCoordinationService.ts
- [x] Add index signature to IWorkflowStep interface
- [x] Fix workflow initialization (lines 364, 370)

### Step 3: Verify fixes
- [x] Run TypeScript check to confirm errors are resolved

**Result:** TypeScript check ran successfully. The actual .ts files (models/Partner.ts and services/partnerCoordinationService.ts) have NO errors. The 1298 errors found are in OTHER files (test files, scripts, .js files with TypeScript annotations) that have broken syntax like invalid comment patterns - these are NOT part of the TypeScript fix scope.

---

## Next Phase: ESM/CommonJS Module Conversion

### Step 4: Convert CommonJS services to ESM
- [x] services/universalBasicIncomeService.js - Already ESM
- [x] services/educationService.js - Already ESM
- [x] services/ubiPaymentService.js - Already ESM
- [x] services/partnerCoordinationService.js - Already ESM
- [x] services/citizenPortalService.js - Already ESM
- [x] services/pmcIntegrationService.js - Already ESM

### Step 5: Convert CommonJS routes to ESM
- [x] routes/ubiRoutes.js - Already ESM
- [x] routes/educationRoutes.js - Already ESM

### Step 6: Verify module system
- [x] Fixed app.js ESM/CommonJS mixed imports - Now fully ESM
- [x] Start server and verify all routes load - Working correctly
