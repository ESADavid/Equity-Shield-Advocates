# Module Fix Plan - ESM/CommonJS Consistency

## Root Cause
- `package.json` has `"type": "module"` (ESM)
- `models/Education.js` uses CommonJS (`require`/`module.exports`)
- This causes module loading errors when services try to import the model

## Server Startup Errors (Analyzed)
✓ ITG system fails - imports algorithms (sacredGeometry, divineWisdom)
✓ UBI system fails - imports Education model
✓ Education system fails - uses Education model
✓ Partner system fails - partnerCoordinationService.js issue
✓ Citizen portal fails - citizenPortalService.js issue
✓ UBI payment fails - imports UBIPayment model
✓ Notification routes fail
✓ Blackbox Multi-Agent fails

## Fix Required

### Step 1: Convert models/Education.js from CommonJS to ESM
Current (CommonJS):
```javascript
const mongoose = require('mongoose');
// ...
module.exports = mongoose.model('Education', educationSchema);
```

Required (ESM):
```javascript
import mongoose from 'mongoose';
// ...
export default mongoose.model('Education', educationSchema);
```

## Execution Steps
1. Edit models/Education.js - convert to ESM syntax
2. Restart server and verify
3. Check all routes load successfully

## Success Criteria
- Server starts without module errors
- All route modules load successfully
- No "does not provide a named export" errors
