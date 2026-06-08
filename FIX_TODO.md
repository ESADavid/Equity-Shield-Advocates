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
- [ ] services/universalBasicIncomeService.js
- [ ] services/educationService.js  
- [ ] services/ubiPaymentService.js
- [ ] services/partnerCoordinationService.js (if exists)
- [ ] services/citizenPortalService.js
- [ ] services/pmcIntegrationService.js

### Step 5: Convert CommonJS routes to ESM
- [ ] routes/ubiRoutes.js
- [ ] routes/educationRoutes.js

### Step 6: Verify module system
- [ ] Start server and verify all routes load
