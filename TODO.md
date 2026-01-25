# Server Startup Fixes TODO

## 1. Fix Duplicate Mongoose Indexes
- [ ] Remove `index: true` from `consentExpiration` and `tanExpiration` fields in `models/Item.js`
- [ ] Remove `schema.index({ 'personalInfo.nationalId': 1 })` from `models/Citizen.js` since `unique: true` already creates the index

## 2. Fix Service Imports in Routes
- [ ] Update `routes/partnerRoutes.js`: Import `partnerService` and `pmcService` as instances, remove `new` instantiation
- [ ] Update `routes/citizenPortalRoutes.js`: Import services as instances
- [ ] Update `routes/notificationRoutes.js`: Fix import issues
- [ ] Check and fix `earnings_dashboard/payroll_router.js` import/extension issues

## 3. Test Server Startup
- [ ] Run `node test_server_startup_simple.cjs` and verify no errors
- [ ] Check that all services load successfully
- [ ] Verify no duplicate index warnings
