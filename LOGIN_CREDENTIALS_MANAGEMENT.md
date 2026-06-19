# Login Credentials & Authentication Management Guide

## Overview

This document provides comprehensive management procedures for login credentials, authentication systems, and access controls within the Oscar Broome Revenue System. All authentication mechanisms are designed with security, compliance, and user experience as primary considerations.

## Authentication System Architecture

### Multi-Layer Authentication

#### Primary Authentication Methods

- **JWT Token Authentication**: Standard API authentication
- **Basic Authentication**: Legacy system compatibility
- **Emergency Override System**: Administrative emergency access
- **MFA Integration**: Multi-factor authentication support

#### Authentication Flow

```javascript
// Standard authentication flow
1. User submits credentials
2. System validates username/password
3. MFA challenge (if enabled)
4. JWT token generation
5. Session establishment
6. Continuous validation
```

### Security Features

#### Password Security

- **Minimum Length**: 12 characters (configurable)
- **Complexity Requirements**: Uppercase, lowercase, numbers, special characters
- **Password History**: Cannot reuse last 5 passwords
- **Expiration Policy**: 90 days for admin accounts

#### Session Management

- **Token Expiration**: 24 hours for standard tokens
- **Refresh Tokens**: 7 days expiration with rotation
- **Concurrent Sessions**: Maximum 3 per user
- **Device Tracking**: IP address and user agent logging

## User Account Management

### Account Creation

#### Standard User Registration

```javascript
// POST /auth/register
{
  "username": "oscar.broome",
  "email": "oscar.broome@jpmorgan.com",
  "password": "SecurePass2024!",
  "firstName": "Oscar",
  "lastName": "Broome",
  "role": "admin",
  "tenantId": "tenant_123"
}

// Response
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "userId": "USER_1234567890",
    "username": "oscar.broome",
    "email": "oscar.broome@jpmorgan.com",
    "role": "admin"
  }
}
```

#### Admin User Creation

```javascript
// Administrative user creation with enhanced security
const adminUser = {
  username: 'oscar.broome',
  email: 'oscar.broome@jpmorgan.com',
  password: 'SecurePass2024!',
  role: 'admin',
  mfaEnabled: true,
  accountStatus: 'active',
  securityClearance: 'level_5',
};
```

### Account Activation

#### Email Verification Process

1. **Registration**: User submits registration details
2. **Email Sent**: Verification email dispatched
3. **Token Generation**: Secure verification token created
4. **Email Click**: User clicks verification link
5. **Account Activation**: Account becomes active
6. **Welcome Email**: Confirmation sent to user

#### Manual Activation (Admin)

```javascript
// Admin manual activation
await userService.activateUser(userId, {
  activatedBy: adminUserId,
  activationReason: 'Administrative approval',
  securityClearance: 'approved',
});
```

## Login Procedures

### Standard Login

#### Authentication Endpoint

```javascript
// POST /auth/login
{
  "username": "oscar.broome",
  "password": "SecurePass2024!"
}

// Successful Response
{
  "success": true,
  "message": "Login successful",
  "data": {
    "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "refresh_token_here",
    "user": {
      "id": "USER_1234567890",
      "username": "oscar.broome",
      "email": "oscar.broome@jpmorgan.com",
      "role": "admin",
      "lastLogin": "2024-01-15T10:30:00Z"
    },
    "expiresIn": 86400
  }
}
```

#### Failed Login Handling

```javascript
// Failed login response
{
  "success": false,
  "message": "Invalid credentials",
  "attemptsRemaining": 4,
  "lockoutTime": null
}

// Account lockout response
{
  "success": false,
  "message": "Account temporarily locked due to too many failed attempts",
  "lockoutUntil": "2024-01-15T11:00:00Z"
}
```

### Multi-Factor Authentication (MFA)

#### MFA Setup

```javascript
// POST /auth/enable-mfa
// Requires: authenticated user

// Response
{
  "success": true,
  "mfaSecret": "JBSWY3DPEHPK3PXP", // Base32 encoded
  "qrCodeUrl": "otpauth://totp/Oscar%20Broome%20Revenue:oscar.broome?secret=JBSWY3DPEHPK3PXP&issuer=Oscar%20Broome%20Revenue",
  "message": "MFA enabled successfully"
}
```

#### MFA Verification

```javascript
// POST /auth/verify-mfa
{
  "token": "123456" // 6-digit TOTP code
}

// Response
{
  "success": true,
  "message": "MFA token verified"
}
```

### Emergency Override System

#### Emergency Access Activation

```javascript
// Emergency override for Oscar Broome
const emergencyResult = await loginOverrideManager.emergencyOverride(
  userId,
  'SYSTEM_EMERGENCY_ACCESS',
  additionalAuthData
);

// Response
{
  "success": true,
  "overrideId": "OVERRIDE_1234567890",
  "message": "Emergency override activated for Oscar Broome",
  "expiresAt": "2024-01-15T10:45:00Z",
  "accessGranted": true
}
```

#### Administrative Override

```javascript
// Admin override for technical issues
const adminOverride = await loginOverrideManager.adminOverride(
  adminUserId,
  targetUserId,
  'TECHNICAL_MAINTENANCE',
  'Server maintenance window - user access required'
);
```

## Password Management

### Password Policies

#### Complexity Requirements

```javascript
function validatePasswordStrength(password) {
  const minLength = 12;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChars = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(
    password
  );

  if (password.length < minLength) {
    return {
      valid: false,
      reason: 'Password must be at least 12 characters long',
    };
  }

  if (!hasUppercase || !hasLowercase || !hasNumbers || !hasSpecialChars) {
    return {
      valid: false,
      reason:
        'Password must contain uppercase, lowercase, numbers, and special characters',
    };
  }

  return { valid: true };
}
```

#### Password Change Process

```javascript
// PUT /auth/change-password
{
  "currentPassword": "CurrentPass123!",
  "newPassword": "NewSecurePass456!"
}

// Response
{
  "success": true,
  "message": "Password changed successfully"
}
```

### Password Reset

#### Self-Service Reset

```javascript
// POST /auth/forgot-password
{
  "email": "oscar.broome@jpmorgan.com"
}

// Response
{
  "success": true,
  "message": "Password reset email sent"
}
```

#### Token-Based Reset

```javascript
// POST /auth/reset-password
{
  "token": "reset_token_from_email",
  "newPassword": "NewSecurePass456!"
}

// Response
{
  "success": true,
  "message": "Password reset successfully"
}
```

## Session Management

### Token Handling

#### JWT Token Structure

```javascript
// JWT Payload
{
  "userId": "USER_1234567890",
  "username": "oscar.broome",
  "email": "oscar.broome@jpmorgan.com",
  "role": "admin",
  "tenantId": "tenant_123",
  "iat": 1705312200, // Issued at
  "exp": 1705398600, // Expires at
  "jti": "unique_token_id" // JWT ID
}
```

#### Token Refresh

```javascript
// POST /auth/refresh
{
  "refreshToken": "refresh_token_here"
}

// Response
{
  "success": true,
  "token": "new_jwt_token",
  "refreshToken": "new_refresh_token",
  "expiresIn": 86400
}
```

### Session Security

#### Concurrent Session Limits

- **Standard Users**: Maximum 3 concurrent sessions
- **Admin Users**: Maximum 5 concurrent sessions
- **Emergency Sessions**: Unlimited during override periods

#### Session Timeout

- **Active Sessions**: 30 minutes of inactivity
- **Absolute Timeout**: 24 hours maximum
- **Emergency Override**: 15-minute windows

## Access Control

### Role-Based Access Control (RBAC)

#### User Roles

- **admin**: Full system access
- **manager**: Department-level access
- **user**: Standard user access
- **readonly**: View-only access
- **api**: API-only access

#### Permission Matrix

```javascript
const rolePermissions = {
  admin: [
    'user.create',
    'user.delete',
    'user.update',
    'system.config',
    'system.backup',
    'system.restore',
    'financial.view',
    'financial.modify',
    'financial.approve',
    'override.emergency',
    'override.admin',
  ],
  manager: [
    'user.view',
    'user.update.own',
    'financial.view',
    'financial.modify.own',
    'report.generate',
  ],
  user: [
    'user.view.self',
    'user.update.self',
    'financial.view.own',
    'financial.modify.own',
  ],
};
```

### Resource-Based Access Control

#### API Endpoint Protection

```javascript
// Middleware for endpoint protection
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res
      .status(401)
      .json({ success: false, message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

const authorize = (requiredPermissions) => {
  return (req, res, next) => {
    const userPermissions = getUserPermissions(req.user.role);

    const hasPermission = requiredPermissions.every((permission) =>
      userPermissions.includes(permission)
    );

    if (!hasPermission) {
      return res
        .status(403)
        .json({ success: false, message: 'Insufficient permissions' });
    }

    next();
  };
};
```

## Security Monitoring

### Authentication Logging

#### Login Event Logging

```javascript
// Authentication event logging
const logAuthEvent = (eventType) => {
  return (req, res, next) => {
    const logData = {
      eventType,
      userId: req.user?.id,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString(),
      endpoint: req.path,
      method: req.method,
    };

    // Log to Winston
    authLogger.info(`AUTH_EVENT: ${eventType}`, logData);

    // Log to blockchain for critical events
    if (['login', 'logout', 'password_change'].includes(eventType)) {
      blockchainService.recordSystemEvent('authentication', logData);
    }

    next();
  };
};
```

#### Failed Login Monitoring

```javascript
// Failed login tracking
const recordFailedLogin = async (userId, reason) => {
  const user = await getUserById(userId);
  if (user) {
    user.loginAttempts = (user.loginAttempts || 0) + 1;

    // Lock account after 5 failed attempts
    if (user.loginAttempts >= 5) {
      user.lockoutUntil = new Date(Date.now() + 30 * 60 * 1000);
      user.lockoutReason = 'Too many failed login attempts';
    }

    await updateUser(user);

    // Alert on suspicious activity
    if (user.loginAttempts >= 3) {
      securityMonitor.alert('multiple_failed_logins', {
        userId,
        attempts: user.loginAttempts,
        ipAddress: getClientIP(),
        timestamp: new Date().toISOString(),
      });
    }
  }
};
```

### Rate Limiting

#### Authentication Rate Limits

```javascript
// Rate limiting configuration
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: {
    success: false,
    message: 'Too many authentication attempts, please try again later',
    retryAfter: 900, // seconds
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Custom key generator for user-based limiting
  keyGenerator: (req) => {
    return req.body.username || req.body.email || req.ip;
  },
  // Custom handler for rate limit exceeded
  handler: (req, res) => {
    const retryAfter = Math.ceil(req.rateLimit.resetTime / 1000);

    securityMonitor.alert('rate_limit_exceeded', {
      ipAddress: req.ip,
      endpoint: req.path,
      retryAfter,
      timestamp: new Date().toISOString(),
    });

    res.status(429).json({
      success: false,
      message: 'Too many requests, please try again later',
      retryAfter,
    });
  },
});
```

## Emergency Procedures

### Account Lockout Recovery

#### Administrative Unlock

```javascript
// Admin unlock procedure
const unlockAccount = async (userId, adminUserId, reason) => {
  const user = await getUserById(userId);

  if (!user.lockoutUntil) {
    throw new Error('Account is not locked');
  }

  // Verify admin permissions
  const admin = await getUserById(adminUserId);
  if (!admin.roles.includes('admin')) {
    throw new Error('Insufficient permissions to unlock account');
  }

  // Unlock account
  user.loginAttempts = 0;
  user.lockoutUntil = null;
  user.unlockReason = reason;
  user.unlockedBy = adminUserId;
  user.unlockedAt = new Date().toISOString();

  await updateUser(user);

  // Log unlock event
  auditLogger.info('ACCOUNT_UNLOCKED', {
    userId,
    adminUserId,
    reason,
    timestamp: user.unlockedAt,
  });

  // Send notification to user
  await emailService.sendAccountUnlockNotification(user.email, {
    unlockedBy: admin.username,
    reason,
    timestamp: user.unlockedAt,
  });
};
```

### Emergency Access Procedures

#### System Emergency Access

1. **Trigger Emergency**: System detects critical failure
2. **Override Activation**: Emergency override codes used
3. **Multi-Person Approval**: Secondary authorization required
4. **Time-Limited Access**: 15-minute access windows
5. **Full Audit Trail**: All actions recorded in blockchain
6. **Post-Incident Review**: Complete security review conducted

#### User Emergency Access

1. **User Reports Issue**: User cannot access system
2. **Verification**: Support team verifies user identity
3. **Temporary Credentials**: Time-limited access provided
4. **Password Reset**: User guided through password reset
5. **Security Review**: Access patterns reviewed for anomalies

## Compliance & Auditing

### Regulatory Compliance

#### SOX Compliance

- **Access Logging**: All authentication events logged
- **Change Tracking**: Password and permission changes audited
- **Separation of Duties**: Admin actions require approval
- **Audit Trails**: Immutable blockchain records

#### GDPR Compliance

- **Data Minimization**: Only necessary authentication data stored
- **Consent Management**: Clear user consent for data processing
- **Right to Erasure**: Account deletion procedures
- **Data Portability**: User data export capabilities

### Security Auditing

#### Regular Audit Procedures

```javascript
// Authentication audit function
const performAuthAudit = async (timeRange) => {
  const auditReport = {
    period: timeRange,
    totalUsers: 0,
    activeUsers: 0,
    lockedAccounts: 0,
    failedLoginAttempts: 0,
    successfulLogins: 0,
    passwordChanges: 0,
    suspiciousActivities: [],
  };

  // Analyze authentication logs
  const authLogs = await getAuthLogs(timeRange);

  for (const log of authLogs) {
    switch (log.eventType) {
      case 'login_success':
        auditReport.successfulLogins++;
        break;
      case 'login_failure':
        auditReport.failedLoginAttempts++;
        break;
      case 'password_change':
        auditReport.passwordChanges++;
        break;
      case 'account_locked':
        auditReport.lockedAccounts++;
        break;
    }

    // Detect suspicious patterns
    if (isSuspiciousActivity(log)) {
      auditReport.suspiciousActivities.push(log);
    }
  }

  // Get user statistics
  const users = await getAllUsers();
  auditReport.totalUsers = users.length;
  auditReport.activeUsers = users.filter((u) => u.isActive).length;

  return auditReport;
};
```

## Maintenance & Updates

### Regular Maintenance Tasks

#### Daily Tasks

- Review failed login attempts
- Check for locked accounts
- Monitor authentication performance
- Verify MFA token generation

#### Weekly Tasks

- Clean up expired sessions
- Review security alerts
- Update password policies
- Check compliance status

#### Monthly Tasks

- Full authentication audit
- User access review
- Security policy updates
- Performance optimization

### System Updates

#### Authentication System Updates

1. **Planning**: Assess update requirements and impact
2. **Testing**: Comprehensive testing in staging environment
3. **Backup**: Full user database and session backup
4. **Deployment**: Phased rollout with rollback capability
5. **Monitoring**: Post-deployment authentication monitoring
6. **User Communication**: Notify users of changes
7. **Documentation**: Update procedures and policies

## Contact Information

### Support Contacts

- **Technical Support**: <support@oscarsystem.com>
- **Security Team**: <security@oscarsystem.com>
- **User Administration**: <admin@oscarsystem.com>
- **Emergency Hotline**: +1-800-AUTH-HELP

### Emergency Contacts

- **System Owner**: Oscar Broome (<oscar.broome@jpmorgan.com>)
- **Security Incident Response**: <security-incident@oscarsystem.com>
- **Compliance Officer**: <compliance@oscarsystem.com>

---

## Document Information

- **Document Owner**: Oscar Broome
- **Last Updated**: January 2024
- **Review Cycle**: Quarterly
- **Classification**: Restricted
- **Version**: 1.0

**This document contains sensitive authentication information. Access is restricted to authorized personnel only.**
