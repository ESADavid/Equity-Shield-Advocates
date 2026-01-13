# UBI Payment System Fixes

## Issues Identified
1. **Service instantiation error**: `test_ubi_manual.js` tries to instantiate `UBIPaymentService` with `new`, but it's exported as a singleton instance.
2. **ObjectId casting error**: Tests pass string citizen IDs like `'test-citizen-123'`, but the `UBIPayment` model expects `citizenId` to be a MongoDB ObjectId.

## Fixes Required
- [x] Update `test_ubi_manual.js` to use imported service instance directly
- [x] Modify `UBIPaymentService.processPayment()` to handle string citizen IDs by converting to ObjectId
- [x] Test the fixes by running the UBI tests

## Implementation Plan
1. Fix the test file import/usage pattern
2. Update service to handle string-to-ObjectId conversion
3. Verify fixes work with both test files
