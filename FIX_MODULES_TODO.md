# Module Fix Plan - ESM/CommonJS Consistency

## Root Cause
- package.json has `"type": "module"` (ESM)
- Some service/route files use CommonJS (`require`/`module.exports`)
- This causes module loading errors

## Files to Fix

### Services (convert to ESM)
1. services/universalBasicIncomeService.js - uses require + import mix
2. services/educationService.js - uses require
3. services/ubiPaymentService.js - uses require
4. services/partnerCoordinationService.js - uses require
5. services/citizenPortalService.js - uses require
6. services/pmcIntegrationService.js - uses require

### Routes (convert to ESM)  
1. routes/ubiRoutes.js - uses CommonJS
2. routes/educationRoutes.js - uses CommonJS

### Status
- [ ] Start server and verify all routes load
