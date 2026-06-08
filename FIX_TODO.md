# TypeScript Fixes TODO

## Plan confirmed by user - proceeding with fixes

### Step 1: Fix models/Partner.ts
- [ ] Fix line 43: Change `mongoose.Decimal128` to `mongoose.Types.Decimal128`
- [ ] Fix line 52: Change `mongoose.Decimal128` to `mongoose.Types.Decimal128`
- [ ] Fix line 95: Add proper static method type signature for `generatePartnerId`

### Step 2: Fix services/partnerCoordinationService.ts
- [ ] Add index signature to IWorkflowStep interface
- [ ] Fix workflow initialization (lines 364, 370)

### Step 3: Verify fixes
- [ ] Run TypeScript check to confirm errors are resolved
