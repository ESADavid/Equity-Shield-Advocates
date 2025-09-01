# Oscar Broome Login Override System

## Overview

The Oscar Broome Login Override System provides emergency access and administrative override capabilities for critical system access scenarios. This system is designed to handle situations where normal authentication processes are unavailable or insufficient.

## Features

### 🔐 Emergency Override
- **Purpose**: Immediate access for Oscar Broome and authorized executive personnel
- **Use Case**: Critical system access when normal authentication fails
- **Duration**: 15 minutes (configurable)
- **Requirements**: Valid emergency override code

### 👑 Administrative Override
- **Purpose**: Administrative bypass for user account issues
- **Use Case**: Account locked, MFA failure, password reset issues
- **Requirements**: Admin credentials + detailed justification
- **Audit Trail**: Full logging of all admin actions

### 🔧 Technical Support Override
- **Purpose**: Support team access for technical issues
- **Use Case**: MFA problems, account access issues
- **Requirements**: Support credentials + valid ticket number
- **Validation**: Ticket number format validation

## System Architecture

```
├── auth/login_override.js              # Core override logic
├── routes/login_override_routes.js     # API endpoints
├── executive-portal/override-dashboard.html  # Web interface
├── executive-portal/override-dashboard.js    # Frontend logic
├── test_login_override.js             # Test suite
└── server-enhanced.js                 # Server integration
```

## API Endpoints

### Emergency Override
```http
POST /api/override/emergency
Content-Type: application/json

{
  "userId": "oscar.broome@oscarsystem.com",
  "reason": "emergency_access",
  "emergencyCode": "OSCAR_BROOME_EMERGENCY_2024",
  "additionalAuth": "optional_additional_auth"
}
```

### Administrative Override
```http
POST /api/override/admin
Content-Type: application/json
Authorization: Bearer <admin_token>

{
  "adminUserId": "admin@oscarsystem.com",
  "targetUserId": "user@oscarsystem.com",
  "reason": "account_locked",
  "justification": "Detailed justification for the override"
}
```

### Technical Support Override
```http
POST /api/override/technical
Content-Type: application/json

{
  "supportUserId": "support@oscarsystem.com",
  "targetUserId": "user@oscarsystem.com",
  "reason": "mfa_failure",
  "ticketNumber": "TECH-1234"
}
```

### Override Validation
```http
POST /api/override/validate/{overrideId}
Content-Type: application/json

{
  "userId": "user@oscarsystem.com"
}
```

### Override Management
```http
GET /api/override/active/{userId}     # Get active overrides
GET /api/override/stats               # System statistics
POST /api/override/revoke/{overrideId} # Revoke override
GET /api/override/health              # Health check
```

## Configuration

### Environment Variables

```bash
# Emergency Override
EMERGENCY_OVERRIDE_CODE=OSCAR_BROOME_EMERGENCY_2024
MAX_OVERRIDE_ATTEMPTS=3
OVERRIDE_WINDOW_MINUTES=15

# Admin Override
ADMIN_OVERRIDE_TOKEN=your_secure_admin_token

# Security
REQUIRE_ADDITIONAL_AUTH=false
NOTIFICATION_EMAILS=security@oscarsystem.com,admin@oscarsystem.com
```

### Override Reasons

- `emergency_access` - Emergency system access
- `system_maintenance` - System maintenance activities
- `technical_issue` - Technical problems
- `account_locked` - User account locked
- `mfa_failure` - Multi-factor authentication failure
- `password_reset` - Password reset issues

## Security Features

### 🔒 Authentication & Authorization
- **Multi-level Access**: Emergency, Admin, Technical roles
- **Code Validation**: Emergency override codes
- **Token-based**: JWT tokens for admin operations
- **Role-based**: Different permissions per user type

### 📊 Audit & Logging
- **Comprehensive Logging**: All override actions logged
- **Winston Integration**: Structured logging with timestamps
- **Security Alerts**: Automatic notifications for suspicious activity
- **Attempt Tracking**: Failed attempt monitoring

### 🛡️ Rate Limiting & Validation
- **Attempt Limits**: Maximum 3 failed attempts per user
- **Time Windows**: 15-minute override sessions
- **Input Validation**: Strict validation of all inputs
- **Format Checking**: Ticket number and code format validation

## Usage Instructions

### 1. Starting the System

```bash
cd OSCAR-BROOME-REVENUE
npm install
node server-enhanced.js
```

### 2. Accessing the Dashboard

Navigate to: `http://localhost:4000/override-dashboard`

### 3. Emergency Override Process

1. Select "Emergency Override" tab
2. Enter user ID (oscar.broome@oscarsystem.com)
3. Select appropriate reason
4. Enter emergency override code
5. Click "Activate Emergency Override"

### 4. Administrative Override Process

1. Select "Admin Override" tab
2. Enter admin user ID
3. Enter target user ID
4. Select reason and provide justification
5. Click "Activate Admin Override"

### 5. Technical Support Override Process

1. Select "Technical Support" tab
2. Enter support user ID
3. Enter target user ID
4. Select reason and enter ticket number
5. Click "Activate Technical Override"

## Testing

### Automated Testing

```bash
cd OSCAR-BROOME-REVENUE
node test_login_override.js
```

### Manual Testing

1. **Health Check**: `GET /api/override/health`
2. **Emergency Override**: Use dashboard or API
3. **Admin Override**: Requires admin token
4. **Validation**: Test override session validation
5. **Statistics**: Check system statistics

## Monitoring & Maintenance

### Log Files
- `logs/login_override.log` - Override actions
- `logs/login_override_api.log` - API requests
- `override.log` - General override logging
- `error.log` - Error logging

### Key Metrics
- Active override count
- Override success/failure rates
- Attempt frequency
- Session duration statistics

### Maintenance Tasks
- **Log Rotation**: Regular log file cleanup
- **Session Cleanup**: Remove expired overrides
- **Security Review**: Regular code validation
- **Performance Monitoring**: Response time tracking

## Emergency Procedures

### System Unavailable
1. Use emergency override code
2. Contact system administrator
3. Document incident details
4. Review access logs

### Security Breach
1. Immediately revoke all active overrides
2. Change emergency codes
3. Review audit logs
4. Update security policies

## Troubleshooting

### Common Issues

**Override Code Rejected**
- Verify emergency code is correct
- Check attempt limits (max 3 attempts)
- Ensure proper user permissions

**Admin Override Failed**
- Verify admin token is valid
- Check justification length (min 10 characters)
- Confirm admin permissions

**Technical Override Failed**
- Validate ticket number format (ABCD-1234)
- Check support user permissions
- Verify ticket exists in system

### Debug Mode

Enable debug logging by setting:
```bash
DEBUG=login-override:*
```

## Compliance & Legal

### Audit Requirements
- All override actions are logged
- Justification required for admin overrides
- Session tracking with timestamps
- User identification and authorization

### Data Retention
- Override logs retained for 2 years
- Session data cleaned up after expiration
- Audit trails maintained for compliance

### Privacy Considerations
- Minimal personal data collection
- Secure log storage
- Access restricted to authorized personnel

## Support & Contact

### Technical Support
- **Email**: support@oscarsystem.com
- **Emergency**: Call system administrator
- **Documentation**: This README file

### Security Team
- **Email**: security@oscarsystem.com
- **Incident Response**: 24/7 availability
- **Code Reviews**: Regular security assessments

---

**Important**: This system should only be used in accordance with Oscar Broome's security policies and procedures. All override actions are monitored and audited.
