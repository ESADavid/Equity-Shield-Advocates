# Layer Configuration Guide

## Overview

This guide provides step-by-step instructions for completing the Layer integration setup after the code implementation is complete.

## Prerequisites

- Access to Plaid Dashboard (<https://dashboard.plaid.com/>)
- Environment file access (`.env`)
- Layer feature enabled in your Plaid account

## Step 1: Configure Layer Template in Plaid Dashboard

### 1.1 Access Plaid Dashboard

1. Log in to your Plaid Dashboard at <https://dashboard.plaid.com/>
2. Navigate to the "Layer" section in the left sidebar

### 1.2 Create Layer Template

1. Click "Create Template" or "New Template"
2. Configure the following settings:

#### Basic Settings

- **Template Name**: `OSCAR-BROOME Layer Onboarding`
- **Description**: `Instant user onboarding with phone number verification`

#### Identity Verification

- **Phone Number Verification**: ✅ Enabled
- **Extended Autofill**: ✅ Enabled
- **Date of Birth Fallback**: ✅ Enabled

#### Account Selection

- **Account Types**: Checking, Savings (as needed)
- **Institution Categories**: All major banks

#### Webhook Configuration

- **Webhook URL**: `https://your-domain.com/api/plaid/webhook`
- **Webhook Events**:
  - ✅ `LAYER_AUTHENTICATION_PASSED`
  - ✅ `SESSION_FINISHED`
  - ✅ `LAYER_NOT_AVAILABLE`
  - ✅ `LAYER_AUTOFILL_NOT_AVAILABLE`

#### Branding

- **Client Name**: `OSCAR BROOME REVENUE`
- **Logo**: Upload your company logo (optional)
- **Primary Color**: Your brand color (optional)

### 1.3 Get Template ID

1. After creating the template, note the **Template ID** from the template details page
2. This ID will be used in your environment variables

## Step 2: Update Environment Variables

### 2.1 Add Layer Environment Variables

Add the following variables to your `.env` file:

```bash
# Layer Configuration
PLAID_LAYER_TEMPLATE_ID=your_template_id_here
PLAID_LAYER_WEBHOOK_SECRET=your_webhook_secret_here

# Optional: Layer Customization
PLAID_LAYER_CLIENT_NAME=OSCAR BROOME REVENUE
PLAID_LAYER_WEBHOOK_URL=https://your-domain.com/api/plaid/webhook
```

### 2.2 Get Webhook Secret

1. In Plaid Dashboard, go to "Webhooks" section
2. Find your webhook configuration
3. Copy the **Webhook Secret**
4. Add it to `PLAID_LAYER_WEBHOOK_SECRET`

## Step 3: Test Layer Integration

### 3.1 Sandbox Testing

Use these Plaid sandbox phone numbers for testing:

| Phone Number | Description                         |
| ------------ | ----------------------------------- |
| 4155550000   | Missing all identity and bank data  |
| 4155550011   | Default number for testing          |
| 4155550012   | Missing PII; 3 connected banks      |
| 4155550015   | Standard profile with a single bank |

### 3.2 Test Commands

```bash
# Test Layer session creation
curl -X POST http://localhost:3000/api/plaid/layer/session-token \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "templateId": "your_template_id",
    "userId": "test_user_123",
    "clientName": "Test Client"
  }'

# Test Layer session retrieval
curl -X GET http://localhost:3000/api/plaid/layer/user-session/session_123 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Step 4: Frontend Integration

### 4.1 Update LayerOnboarding Component

Ensure your frontend component uses the correct API endpoints:

```javascript
// Create Layer session
const createSession = async (phoneNumber) => {
  const response = await fetch('/api/plaid/layer/session-token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      templateId: process.env.REACT_APP_PLAID_LAYER_TEMPLATE_ID,
      userId: userId,
      clientName: 'OSCAR BROOME REVENUE',
    }),
  });

  const { data } = await response.json();
  return data;
};

// Handle Layer events
const handleLayerEvent = (event) => {
  switch (event.type) {
    case 'LAYER_READY':
      // Layer is ready for user interaction
      break;
    case 'LAYER_AUTHENTICATION_PASSED':
      // User authentication successful
      break;
    case 'SESSION_FINISHED':
      // Session completed, retrieve user data
      fetchUserSession(event.sessionId);
      break;
    case 'LAYER_NOT_AVAILABLE':
      // Fallback to regular Link
      break;
  }
};
```

## Step 5: Production Deployment

### 5.1 Environment Variables for Production

Ensure production `.env` file includes:

```bash
# Production Layer Configuration
PLAID_LAYER_TEMPLATE_ID=prod_template_id
PLAID_LAYER_WEBHOOK_SECRET=prod_webhook_secret
PLAID_LAYER_CLIENT_NAME=OSCAR BROOME REVENUE
PLAID_LAYER_WEBHOOK_URL=https://your-production-domain.com/api/plaid/webhook
```

### 5.2 Webhook URL Update

Update the webhook URL in Plaid Dashboard to point to your production domain.

## Step 6: Monitoring and Maintenance

### 6.1 Monitor Layer Events

Set up monitoring for Layer webhook events in your logging system:

```javascript
// In your webhook handler
logger.info('Layer event received:', {
  eventType: webhookCode,
  sessionId,
  itemId,
  timestamp: new Date().toISOString(),
});
```

### 6.2 Error Handling

Implement proper error handling for Layer failures:

```javascript
try {
  const sessionData = await plaidService.createSessionToken(templateId, userId);
  // Success handling
} catch (error) {
  if (error.response?.status === 400) {
    // Template configuration issue
    logger.error('Layer template configuration error:', error);
  } else if (error.response?.status === 403) {
    // Layer not enabled for account
    logger.error('Layer not enabled:', error);
  } else {
    // Other errors
    logger.error('Layer session creation failed:', error);
  }
}
```

## Troubleshooting

### Common Issues

1. **Template ID not found**
   - Verify the template ID in Plaid Dashboard
   - Check environment variable spelling

2. **Webhook events not received**
   - Confirm webhook URL is correct
   - Check webhook secret matches
   - Verify server is accessible from Plaid

3. **Layer not available for user**
   - Some users may not qualify for Layer
   - Implement fallback to regular Plaid Link

4. **Phone number validation fails**
   - Use sandbox phone numbers for testing
   - Ensure phone number format is correct

### Support

- Plaid Dashboard: <https://dashboard.plaid.com/>
- Plaid Documentation: <https://plaid.com/docs/layer/>
- Layer Support: Contact Plaid support for Layer-specific issues

## Completion Checklist

- [ ] Layer template created in Plaid Dashboard
- [ ] Template ID added to environment variables
- [ ] Webhook secret configured
- [ ] Webhook URL set correctly
- [ ] Frontend component updated
- [ ] Sandbox testing completed
- [ ] Production environment configured
- [ ] Monitoring and logging implemented

Once all steps are completed, the Layer integration will be fully operational for instant user onboarding with phone number verification.
