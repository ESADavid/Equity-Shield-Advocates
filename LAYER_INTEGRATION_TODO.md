# Plaid Layer Integration TODO

## Overview

Implement Plaid Layer for instant user onboarding with phone number verification.

## Tasks

### Backend Service Layer

- [x] Add `createSessionToken()` method for Layer template integration
- [x] Add `getUserAccountSession()` method to retrieve Layer user data
- [x] Extend webhook handler for Layer-specific events (LAYER_AUTHENTICATION_PASSED, SESSION_FINISHED)

### API Routes

- [x] Add `/layer/session-token` POST route for creating Layer sessions
- [x] Add `/layer/user-session/:sessionId` GET route for retrieving user data
- [x] Update webhook endpoint to handle Layer events

### Frontend Integration

- [x] Create Layer onboarding component in earnings_dashboard
- [x] Handle Layer events (LAYER_READY, LAYER_NOT_AVAILABLE, LAYER_AUTOFILL_NOT_AVAILABLE)
- [x] Implement Extended Autofill flow with date of birth fallback

### Testing

- [x] Add Layer-specific test cases using sandbox phone numbers
- [x] Test Extended Autofill scenarios
- [ ] Test webhook handling for Layer events

### Configuration

- [ ] Configure Layer template in Plaid Dashboard
- [ ] Update environment variables for Layer
- [ ] Update documentation

## Files Modified

- services/plaidService.js - Added Layer methods and webhook handling
- routes/plaidRoutes.js - Added Layer API routes
- earnings_dashboard/src/LayerOnboarding.jsx - Created React component for Layer onboarding
- test_layer_integration.js - Created comprehensive test suite

## Implementation Summary

### Backend Implementation

1. **Layer Service Methods**: Added three new methods to `plaidService.js`:
   - `createSessionToken()` - Creates Layer session tokens using template IDs
   - `getUserAccountSession()` - Retrieves user account and identity data after Layer completion
   - `handleLayerWebhook()` - Processes Layer-specific webhook events

2. **API Routes**: Added two new routes in `plaidRoutes.js`:
   - `POST /api/plaid/layer/session-token` - Creates Layer session tokens
   - `GET /api/plaid/layer/user-session/:sessionId` - Retrieves Layer session data

3. **Webhook Integration**: Extended the main webhook handler to process Layer events including:
   - `LAYER_AUTHENTICATION_PASSED` - User authentication completed
   - `SESSION_FINISHED` - Layer session completed successfully

### Frontend Implementation

1. **LayerOnboarding Component**: Created a comprehensive React component that:
   - Handles phone number input for Layer eligibility check
   - Supports Extended Autofill with date of birth fallback
   - Manages Layer event states (ready, not available, autofill not available)
   - Provides user-friendly UI for the Layer onboarding flow

### Testing Implementation

1. **Comprehensive Test Suite**: Created `test_layer_integration.js` with tests for:
   - Session token creation and error handling
   - User account session retrieval
   - Layer webhook processing
   - API route validation
   - Sandbox phone number validation

## Next Steps

1. Configure Layer template in Plaid Dashboard
2. Set up environment variables for Layer configuration
3. Test the complete Layer flow with sandbox data
4. Update API documentation

## Expected Outcome

- Users can onboard instantly with just a phone number
- Extended Autofill support for users not eligible for standard Layer
- Seamless integration with existing Plaid infrastructure
- Proper webhook handling for Layer events
- Comprehensive test coverage for Layer functionality
