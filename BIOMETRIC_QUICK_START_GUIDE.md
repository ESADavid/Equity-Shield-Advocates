# 🚀 Biometric System - Quick Start Guide

## 📋 Prerequisites

- Node.js 16+ installed
- MongoDB running locally or remotely
- Environment variables configured

## ⚡ Quick Setup (5 Minutes)

### Step 1: Configure Environment

Add to your `.env` file:

```bash
# MongoDB
MONGODB_URI=mongodb://localhost:27017/oscar-broome-revenue

# Biometric Security
BIOMETRIC_MASTER_KEY=your-super-secure-master-key-change-this-now
BIOMETRIC_ENCRYPTION_ALGORITHM=AES-256-GCM
BIOMETRIC_HASH_ITERATIONS=100000

# Blockchain
BLOCKCHAIN_LOGGING_ENABLED=true

# Server
PORT=4000
NODE_ENV=development
```

### Step 2: Start the Server

```bash
npm install
npm start
```

The server will start at `http://localhost:4000` with biometric routes at `/api/biometric/*`

### Step 3: Initialize Default Permissions

```javascript
// Run this once to create default permissions
import Permission from './models/Permission.js';

await Permission.createDefaultPermissions('your-tenant-id', 'admin-user-id');
```

## 🎯 Common Use Cases

### Use Case 1: Enroll User Biometrics

```javascript
// POST /api/biometric/enroll/fingerprint
const response = await fetch(
  'http://localhost:4000/api/biometric/enroll/fingerprint',
  {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer YOUR_JWT_TOKEN',
    },
    body: JSON.stringify({
      finger: 'index',
      hand: 'right',
      template: 'base64_encoded_fingerprint_data',
      quality: 85,
    }),
  }
);

const result = await response.json();
// { success: true, message: "Fingerprint enrolled successfully", quality: 85 }
```

### Use Case 2: Verify Biometrics

```javascript
// POST /api/biometric/verify/fingerprint
const response = await fetch(
  'http://localhost:4000/api/biometric/verify/fingerprint',
  {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer YOUR_JWT_TOKEN',
      'X-Device-ID': 'device-123',
    },
    body: JSON.stringify({
      template: 'base64_encoded_fingerprint_data',
    }),
  }
);

const result = await response.json();
// { success: true, verified: true, message: "Fingerprint verified successfully" }
```

### Use Case 3: Protect a Route with Biometric

```javascript
import express from 'express';
import { requireBiometric } from './middleware/biometricAuth.js';
import { authenticate } from './middleware/auth.js';

const router = express.Router();

// Require fingerprint verification
router.post(
  '/transfer-money',
  authenticate,
  requireBiometric(['fingerprint']),
  async (req, res) => {
    // This code only runs if biometric verification succeeds
    res.json({ message: 'Transfer initiated' });
  }
);

// Require multiple biometrics
router.post(
  '/admin-action',
  authenticate,
  requireBiometric(['fingerprint', 'facial'], 2), // Require 2 biometrics
  async (req, res) => {
    res.json({ message: 'Admin action completed' });
  }
);
```

### Use Case 4: Check Permissions

```javascript
import permissionService from './services/permissionService.js';

// Check if user has permission
const permissionCheck = await permissionService.checkPermission(
  userId,
  'INITIATE_TRANSFERS',
  tenantId,
  {
    ipAddress: req.ip,
    deviceType: 'desktop',
    isVPN: false,
    isSecureNetwork: true,
    isTrustedDevice: true,
  }
);

if (permissionCheck.allowed) {
  // User has permission
  if (permissionCheck.requiresBiometric) {
    // Biometric verification required
    const requiredBiometrics = permissionCheck.biometricTypes;
    // ['fingerprint', 'facial']
  }
} else {
  // Permission denied
  console.log(permissionCheck.reason);
}
```

### Use Case 5: Multi-Factor Biometric Verification

```javascript
// POST /api/biometric/verify/multi
const response = await fetch(
  'http://localhost:4000/api/biometric/verify/multi',
  {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer YOUR_JWT_TOKEN',
    },
    body: JSON.stringify({
      fingerprint: 'fingerprint_template',
      facial: 'facial_template',
      voice: 'voice_template',
    }),
  }
);

const result = await response.json();
/*
{
  overall: true,
  verifiedCount: 2,
  requiredCount: 2,
  fingerprint: true,
  facial: true,
  voice: false
}
*/
```

## 🔐 Security Best Practices

### 1. Always Use HTTPS in Production

```javascript
// In production, enforce HTTPS
if (process.env.NODE_ENV === 'production' && req.protocol !== 'https') {
  return res.redirect('https://' + req.hostname + req.url);
}
```

### 2. Rotate Master Key Regularly

```bash
# Generate new master key every 90 days
openssl rand -base64 32
```

### 3. Monitor Failed Attempts

```javascript
// Check biometric status
const status = await biometricAuthService.getBiometricStatus(userId, tenantId);

if (status.isLocked) {
  console.log(`Account locked until: ${status.lockedUntil}`);
}
```

### 4. Use Device Fingerprinting

```javascript
// Register trusted device
const deviceInfo = {
  deviceType: 'desktop',
  browser: navigator.userAgent,
  os: 'Windows 11',
  screenResolution: `${screen.width}x${screen.height}`,
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  language: navigator.language,
};

const result = await fetch('/api/biometric/device/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(deviceInfo),
});

const { deviceHash } = await result.json();
// Store deviceHash for future requests
```

## 📊 Monitoring & Debugging

### Check Logs

```bash
# View biometric authentication logs
tail -f logs/biometric-auth.log

# View permission service logs
tail -f logs/permission-service.log

# View middleware logs
tail -f logs/biometric-middleware.log
```

### Get Biometric Status

```javascript
// GET /api/biometric/status
const response = await fetch('http://localhost:4000/api/biometric/status', {
  headers: {
    Authorization: 'Bearer YOUR_JWT_TOKEN',
  },
});

const status = await response.json();
/*
{
  success: true,
  status: {
    enrolled: true,
    fingerprint: true,
    fingerprintCount: 2,
    facial: true,
    facialCount: 1,
    voice: false,
    voiceCount: 0,
    devices: 3,
    trustedDevices: 2,
    isLocked: false
  }
}
*/
```

## 🧪 Testing

### Run Tests

```bash
# Run all biometric tests
npm test test/biometric/biometric-system.test.js

# Run with coverage
npm test -- --coverage test/biometric/

# Run specific test
npm test -- --testNamePattern="should enroll fingerprint"
```

### Manual Testing with cURL

```bash
# Enroll fingerprint
curl -X POST http://localhost:4000/api/biometric/enroll/fingerprint \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "finger": "index",
    "hand": "right",
    "template": "test_template_data",
    "quality": 85
  }'

# Verify fingerprint
curl -X POST http://localhost:4000/api/biometric/verify/fingerprint \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "template": "test_template_data"
  }'

# Get status
curl http://localhost:4000/api/biometric/status \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 🚨 Troubleshooting

### Issue: "MongoDB connection error"

**Solution:**

```bash
# Check if MongoDB is running
mongosh

# Start MongoDB
sudo systemctl start mongod

# Or use Docker
docker run -d -p 27017:27017 mongo:latest
```

### Issue: "Biometric quality too low"

**Solution:**

- Ensure quality score is above threshold (60 for fingerprint, 70 for facial, 65 for voice)
- Improve capture conditions (lighting, positioning, etc.)

### Issue: "Account is locked"

**Solution:**

```javascript
// Reset failed attempts (admin only)
const biometricData = await BiometricData.findByUser(userId, tenantId);
await biometricData.resetFailedAttempts();
```

### Issue: "Permission denied"

**Solution:**

```javascript
// Check permission requirements
const permission = await Permission.findByCode('SYSTEM_ADMIN', tenantId);
console.log('Required biometrics:', permission.getRequiredBiometrics());
console.log('Time restrictions:', permission.restrictions.timeRestrictions);
console.log(
  'Context restrictions:',
  permission.restrictions.contextRestrictions
);
```

## 📚 Additional Resources

- **Full Documentation:** `BIOMETRIC_SYSTEM_COMPLETION_REPORT.md`
- **Implementation Plan:** `BIOMETRIC_SECURITY_IMPLEMENTATION_PLAN.md`
- **API Reference:** See routes in `routes/biometricRoutes.js`
- **Test Examples:** `test/biometric/biometric-system.test.js`

## 💡 Tips

1. **Start Simple:** Begin with fingerprint-only authentication
2. **Add Gradually:** Add facial and voice recognition as needed
3. **Test Thoroughly:** Use the test suite before production deployment
4. **Monitor Logs:** Keep an eye on failed attempts and suspicious activity
5. **Backup Keys:** Store master key in secure location (HSM or encrypted USB)

## 🎉 You're Ready!

The biometric system is now set up and ready to use. Start by enrolling your first biometric and testing the verification flow.

**Need Help?** Check the logs or refer to the comprehensive documentation.

---

_Quick Start Guide - Biometric Authentication System_  
_Last Updated: December 2024_
