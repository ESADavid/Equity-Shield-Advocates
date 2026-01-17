# Server Startup Issues Fix Plan

## Current Issues Identified

Based on the server startup logs, the following issues need to be addressed:

### 1. Redis Connection Errors

- **Issue**: Redis server not running on localhost:6379
- **Impact**: Cache service falls back to in-memory cache
- **Solution**: Install and start Redis server

### 2. Email Configuration Incomplete

- **Issue**: SENDGRID_API_KEY environment variable missing
- **Impact**: Email features disabled
- **Solution**: Configure SendGrid API key

### 3. SMS Service Not Configured

- **Issue**: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER missing
- **Impact**: SMS features disabled
- **Solution**: Configure Twilio credentials

### 4. Module Loading Issues

- **Issue**: Haiti strategic routes, Partner routes, and Payroll router failing to load
- **Impact**: Some API endpoints unavailable
- **Solution**: Fix module import issues

### 5. MongoDB Schema Warnings

- **Issue**: Duplicate schema indexes on personalInfo.nationalId and transactionId
- **Impact**: Performance warnings
- **Solution**: Remove duplicate index definitions

## Implementation Plan

### Phase 1: Infrastructure Setup

#### 1.1 Install and Start Redis

```bash
# Install Redis (Windows)
choco install redis-64

# Start Redis service
redis-server --daemonize yes
```

#### 1.2 Verify Redis Installation

```bash
redis-cli ping
```

### Phase 2: Email Configuration

#### 2.1 Get SendGrid API Key

- Sign up for SendGrid account at <https://sendgrid.com>
- Create API key with full access
- Add to environment variables

#### 2.2 Update Environment Variables

```bash
# Add to .env file
SENDGRID_API_KEY=your_sendgrid_api_key_here
EMAIL_FROM=noreply@oscar-broome-revenue.com
EMAIL_FROM_NAME="Oscar Broome Revenue System"
```

### Phase 3: SMS Configuration

#### 3.1 Get Twilio Credentials

- Sign up for Twilio account at <https://twilio.com>
- Get Account SID, Auth Token, and phone number
- Add to environment variables

#### 3.2 Update Environment Variables

```bash
# Add to .env file
TWILIO_ACCOUNT_SID=your_twilio_account_sid
TWILIO_AUTH_TOKEN=your_twilio_auth_token
TWILIO_PHONE_NUMBER=+1234567890
SMS_FROM_NUMBER=+1234567890
```

### Phase 4: Fix Module Loading Issues

#### 4.1 Fix Payroll Router TypeScript Import Issue

The payroll router is trying to import from `../dist/payrollSystem.js` but the source file is `payrollSystem.ts` and not compiled.

**Solution:**
- Change the import in `earnings_dashboard/payroll_router.js` to import from the correct location
- Either compile the TypeScript file or import the JavaScript version directly

**Implementation:**
```javascript
// Change this line in earnings_dashboard/payroll_router.js:
import { payrollSystem } from '../dist/payrollSystem.js';

// To this:
import { payrollSystem } from '../payrollSystem.js';
```

#### 4.2 Verify Route Exports

All route files (`routes/haitiStrategicRoutes.js`, `routes/partnerRoutes.js`, etc.) appear to have correct ES6 exports. The loading issues are likely due to the payroll router import failure causing the entire module loading to fail gracefully but skip the payroll system.

#### 4.3 Test Module Loading

After fixing the payroll router import, restart the server and check that all modules load without errors.

### Phase 5: Fix MongoDB Schema Issues

#### 5.1 Fix Duplicate Transaction ID Index

The Transaction model has duplicate indexes on `transactionId`:

**Current Issues:**
- `transactionId: { type: String, required: true, index: true }` (schema-level index)
- `transactionSchema.index({ tenantId: 1, transactionId: 1 }, { unique: true })` (compound index)

**Solution:**
Remove the `index: true` from the schema definition since the compound unique index already provides the necessary indexing.

**Implementation:**
```javascript
// In models/Transaction.js, change:
transactionId: {
  type: String,
  required: true,
  index: true,  // Remove this line
},

// Keep the compound index:
transactionSchema.index({ tenantId: 1, transactionId: 1 }, { unique: true });
```

#### 5.2 Verify No Other Duplicate Indexes

Check other models for similar duplicate index issues. The User model appears to be correctly structured with no duplicates.

### Phase 6: Testing and Verification

#### 6.1 Test Server Startup

```bash
npm start
```

**Expected Output:**
- Server should start without module loading errors
- All services should initialize successfully
- No MongoDB schema warnings

#### 6.2 Verify Services Status

Check the `/api/status` endpoint:

```bash
curl http://localhost:3000/api/status
```

**Expected Response:**
```json
{
  "merchantBillPay": { "loaded": true },
  "jpmorganPayment": { "loaded": true },
  "payroll": { "loaded": true },  // Should now be true
  "environment": { "nodeVersion": "v18+", "environment": "development" },
  "services": {
    "redis": true,  // Should be true after Redis setup
    "database": true,
    "email": true,  // Should be true after SendGrid setup
    "sms": true     // Should be true after Twilio setup
  }
}
```

#### 6.3 Test Core API Endpoints

**Test Payroll System:**
```bash
curl http://localhost:3000/api/payroll/welcome
```

**Test Email Service:**
```bash
curl -X POST http://localhost:3000/api/email/test \
  -H "Content-Type: application/json" \
  -d '{"to": "test@example.com", "subject": "Test", "text": "Test email"}'
```

**Test SMS Service:**
```bash
curl -X POST http://localhost:3000/api/sms/test \
  -H "Content-Type: application/json" \
  -d '{"to": "+1234567890", "message": "Test SMS"}'
```

#### 6.4 Verify Database Health

Check the `/health` endpoint:

```bash
curl http://localhost:3000/health
```

**Expected Response:**
```json
{
  "status": "healthy",
  "database": { "status": "connected" },
  "cache": { "status": "connected" }
}
```

### Phase 7: Documentation and Final Configuration

#### 7.1 Update Environment Variables Documentation

Create a comprehensive `.env.example` file with all required variables:

```bash
# Database
MONGODB_URI=mongodb://localhost:27017/oscar-broome-revenue
SKIP_DATABASE=false

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# Email (SendGrid)
SENDGRID_API_KEY=your_sendgrid_api_key
EMAIL_FROM=noreply@oscar-broome-revenue.com
EMAIL_FROM_NAME="Oscar Broome Revenue System"

# SMS (Twilio)
TWILIO_ACCOUNT_SID=your_twilio_account_sid
TWILIO_AUTH_TOKEN=your_twilio_auth_token
TWILIO_PHONE_NUMBER=+1234567890
SMS_FROM_NUMBER=+1234567890

# Server
PORT=3000
NODE_ENV=development
JWT_SECRET=your-super-secure-jwt-secret

# External Services
QUICKBOOKS_BASE_URL=https://sandbox-quickbooks.api.intuit.com
QUICKBOOKS_ACCESS_TOKEN=your_quickbooks_token
QUICKBOOKS_COMPANY_ID=your_company_id
QUICKBOOKS_CLIENT_ID=your_client_id
QUICKBOOKS_CLIENT_SECRET=your_client_secret
QUICKBOOKS_REFRESH_TOKEN=your_refresh_token

# JPMorgan
JPMORGAN_CLIENT_ID=your_jpmorgan_client_id
JPMORGAN_CLIENT_SECRET=your_jpmorgan_client_secret
JPMORGAN_MERCHANT_ID=your_merchant_id
JPMORGAN_TERMINAL_ID=your_terminal_id
```

#### 7.2 Create Setup Verification Script

Create `scripts/verify-setup.js` to automatically check all configurations:

```javascript
// scripts/verify-setup.js
import dotenv from 'dotenv';
import { createClient as createRedisClient } from 'redis';
import mongoose from 'mongoose';

dotenv.config();

async function verifySetup() {
  console.log('🔍 Verifying OSCAR BROOME REVENUE Setup...\n');

  // Check environment variables
  const required = [
    'MONGODB_URI', 'REDIS_HOST', 'SENDGRID_API_KEY',
    'TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN', 'JWT_SECRET'
  ];

  console.log('📋 Environment Variables:');
  required.forEach(key => {
    const status = process.env[key] ? '✅' : '❌';
    console.log(`  ${status} ${key}`);
  });

  // Test Redis connection
  console.log('\n🔴 Redis Connection:');
  try {
    const redis = createRedisClient({
      host: process.env.REDIS_HOST,
      port: process.env.REDIS_PORT
    });
    await redis.connect();
    await redis.ping();
    console.log('  ✅ Connected');
    await redis.disconnect();
  } catch (error) {
    console.log('  ❌ Failed:', error.message);
  }

  // Test MongoDB connection
  console.log('\n🍃 MongoDB Connection:');
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('  ✅ Connected');
    await mongoose.disconnect();
  } catch (error) {
    console.log('  ❌ Failed:', error.message);
  }

  console.log('\n✨ Setup verification complete!');
}

verifySetup().catch(console.error);
```

#### 7.3 Update README with Setup Instructions

Add a comprehensive setup section to README.md covering:
- Prerequisites (Node.js, MongoDB, Redis)
- Environment variable configuration
- Service account setup (SendGrid, Twilio)
- Startup verification steps

## Environment Variables Summary

Add these to your `.env` file:

```bash
# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# Email Configuration (SendGrid)
SENDGRID_API_KEY=your_sendgrid_api_key
EMAIL_FROM=noreply@oscar-broome-revenue.com
EMAIL_FROM_NAME=Oscar Broome Revenue System

# SMS Configuration (Twilio)
TWILIO_ACCOUNT_SID=your_twilio_account_sid
TWILIO_AUTH_TOKEN=your_twilio_auth_token
TWILIO_PHONE_NUMBER=+1234567890
SMS_FROM_NUMBER=+1234567890

# Database
SKIP_DATABASE=false
MONGODB_URI=mongodb://localhost:27017/oscar-broome-revenue
```

## Success Criteria

- [ ] Redis server running and connected
- [ ] Email service configured and functional
- [ ] SMS service configured and functional
- [ ] All API routes loaded without errors
- [ ] No MongoDB schema warnings
- [ ] Server starts cleanly without errors
- [ ] All services show "loaded successfully" in logs
- [ ] Setup verification script created and functional
- [ ] Comprehensive documentation updated

## Next Steps

1. Execute Phase 1-3 (Infrastructure and Configuration)
2. Execute Phase 4-5 (Code Fixes)
3. Execute Phase 6 (Testing and Verification)
4. Execute Phase 7 (Documentation and Final Configuration)
5. Create automated setup verification script
