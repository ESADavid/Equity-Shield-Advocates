# Module Fix Plan - ESM/CommonJS Consistency

## Root Cause
- package.json has `"type": "module"` (ESM)
- Some service/route files use CommonJS (`require`/`module.exports`)
- This causes module loading errors

## Files to Fix

### Services (convert to ESM)
- [x] services/universalBasicIncomeService.js - Already ESM
- [x] services/educationService.js - Already ESM
- [x] services/ubiPaymentService.js - Already ESM
- [x] services/partnerCoordinationService.js - Already ESM
- [x] services/citizenPortalService.js - Already ESM
- [x] services/pmcIntegrationService.js - Already ESM

### Routes (convert to ESM)  
- [x] routes/ubiRoutes.js - Already ESM
- [x] routes/educationRoutes.js - Already ESM

### Status
- [x] Fixed app.js ESM/CommonJS mixed imports - Now fully ESM
- [x] Start server and verify all routes load - Working correctly
