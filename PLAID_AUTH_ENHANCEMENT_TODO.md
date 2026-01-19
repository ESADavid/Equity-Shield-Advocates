# Plaid Auth Enhancement TODO

## Overview

Enhance the existing Plaid integration with Auth-specific features according to Plaid's official Auth documentation.

## Tasks

- [x] **Enhance getAuth Method**: Update to include `is_tokenized_account_number` and `persistent_account_id` fields
- [x] **Add Consent Management**: Implement consent expiration time tracking and PNC-specific handling
- [x] **Improve Auth Webhooks**: Add specific handling for AUTH webhook events (consent expiration, verification status)
- [x] **Add TAN Management**: Implement tokenized account number handling for Chase, PNC, US Bank
- [x] **Update Item Model**: Add fields for consent expiration and TAN tracking
- [x] **Add Auth-Specific Routes**: New endpoints for consent management and TAN operations
- [x] **Update Documentation**: Document all Auth-specific features and compliance requirements
- [x] **Add Tests**: Comprehensive tests for Auth functionality

## Files to Modify

- `services/plaidService.js`: Enhance getAuth method and add Auth-specific methods ✅
- `routes/plaidRoutes.js`: Add new Auth management endpoints
- `models/`: Add consent tracking fields to Item/User models
- `PLAID_INTEGRATION_README.md`: Update with Auth-specific documentation ✅

## Expected Outcome

- Full compliance with Plaid Auth documentation
- Proper handling of tokenized account numbers
- Consent expiration management
- Enhanced webhook processing for Auth events
- PNC TAN expiration handling
