# Oscar Broome Revenue System - API Documentation

## Overview

This document provides comprehensive API documentation for the Oscar Broome Revenue System, including all endpoints, request/response formats, authentication requirements, and usage examples.

## 🔐 Authentication

All API endpoints require authentication using quantum-secure JWT tokens or basic authentication headers.

### Authentication Methods

#### JWT Token Authentication
```javascript
Authorization: Bearer <jwt_token>
```

#### Basic Authentication
```javascript
Authorization: Basic <base64_encoded_credentials>
```

### Token Generation
```javascript
POST /auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "securepassword",
  "mfa_code": "123456"  // Optional
}
```

Response:
```javascript
{
  "success": true,
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 900,
  "user": {
    "id": "123",
    "role": "admin",
    "permissions": ["read", "write", "control"]
  }
}
```

## 📡 JPMorgan Control Center APIs

### Base URL
```
https://api.oscar-broome.com/jpmorgan/control
```

### 1. System Status

#### Get System Status
```http
GET /jpmorgan/control/status
Authorization: Bearer <token>
```

**Response:**
```javascript
{
  "status": "operational",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0",
  "uptime": 86400,
  "services": {
    "banking_api": "online",
    "website_control": "online",
    "security_layer": "online",
    "database": "online"
  },
  "alerts": [
    {
      "id": "alert_001",
      "level": "warning",
      "message": "High CPU usage detected",
      "timestamp": "2024-01-15T10:25:00Z"
    }
  ]
}
```

### 2. System Metrics

#### Get Performance Metrics
```http
GET /jpmorgan/control/metrics
Authorization: Bearer <token>
```

**Query Parameters:**
- `period` (optional): `1h`, `24h`, `7d`, `30d` (default: `24h`)
- `metrics` (optional): comma-separated list of metrics

**Response:**
```javascript
{
  "period": "24h",
  "metrics": {
    "api_response_time": {
      "average": 245,
      "min": 120,
      "max": 1200,
      "p95": 450
    },
    "transaction_volume": {
      "total": 15420,
      "successful": 15385,
      "failed": 35
    },
    "system_resources": {
      "cpu_usage": 68.5,
      "memory_usage": 72.3,
      "disk_usage": 45.2
    },
    "security_events": {
      "failed_logins": 12,
      "anomalies_detected": 3,
      "threats_blocked": 27
    }
  }
}
```

### 3. Activity Log

#### Get Recent Activities
```http
GET /jpmorgan/control/activities
Authorization: Bearer <token>
```

**Query Parameters:**
- `limit` (optional): Number of activities to return (default: 50, max: 500)
- `offset` (optional): Pagination offset (default: 0)
- `filter` (optional): Filter by action type, user, or status
- `start_date` (optional): ISO 8601 start date
- `end_date` (optional): ISO 8601 end date

**Response:**
```javascript
{
  "total": 1250,
  "limit": 50,
  "offset": 0,
  "activities": [
    {
      "id": "act_001",
      "timestamp": "2024-01-15T10:30:00Z",
      "user": "admin",
      "action": "website_login_control",
      "status": "success",
      "details": {
        "target": "website_001",
        "action": "enable_login",
        "ip_address": "192.168.1.100"
      },
      "signature": "a1b2c3d4e5f6..."
    }
  ]
}
```

### 4. Execute Control Actions

#### Execute System Action
```http
POST /jpmorgan/control/execute
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**
```javascript
{
  "action": "emergency_stop",
  "parameters": {
    "reason": "Security incident detected",
    "duration": 3600  // seconds
  },
  "confirmation": "quantum_signature_here"
}
```

**Available Actions:**
- `emergency_stop`: Halt all operations
- `system_reset`: Restart all services
- `backup_initiate`: Trigger data backup
- `alert_clear`: Clear active alerts
- `maintenance_mode`: Enable/disable maintenance mode

**Response:**
```javascript
{
  "success": true,
  "action_id": "exec_001",
  "status": "executing",
  "estimated_completion": "2024-01-15T10:35:00Z",
  "message": "Emergency stop initiated successfully"
}
```

## 🌐 Website Management APIs

### Base URL
```
https://api.oscar-broome.com/jpmorgan/control/websites
```

### 1. Get Website List

#### List Managed Websites
```http
GET /jpmorgan/control/websites
Authorization: Bearer <token>
```

**Response:**
```javascript
{
  "websites": [
    {
      "id": "web_001",
      "name": "Oscar Broome Main Site",
      "url": "https://oscar-broome.com",
      "status": "online",
      "login_enabled": true,
      "active_sessions": 45,
      "last_backup": "2024-01-15T06:00:00Z",
      "security_level": "high"
    }
  ]
}
```

### 2. Website Actions

#### Execute Website Action
```http
POST /jpmorgan/control/website-action
Authorization: Bearer <token>
Content-Type: application/json
```

**Login Control:**
```javascript
{
  "action": "login_control",
  "website_id": "web_001",
  "parameters": {
    "enable": false,
    "reason": "Maintenance window",
    "duration": 7200
  }
}
```

**Configuration Update:**
```javascript
{
  "action": "config_update",
  "website_id": "web_001",
  "parameters": {
    "settings": {
      "maintenance_mode": true,
      "custom_message": "Site under maintenance"
    }
  }
}
```

**Content Management:**
```javascript
{
  "action": "content_modify",
  "website_id": "web_001",
  "parameters": {
    "section": "homepage",
    "content": "<h1>Updated Homepage</h1>",
    "backup_before_change": true
  }
}
```

**Response:**
```javascript
{
  "success": true,
  "action_id": "web_act_001",
  "website_id": "web_001",
  "status": "completed",
  "message": "Website login disabled successfully"
}
```

## 🏦 Banking Operations APIs

### Base URL
```
https://api.oscar-broome.com/jpmorgan/control/banking
```

### 1. Account Management

#### Get Banking Accounts
```http
GET /jpmorgan/control/banking/accounts
Authorization: Bearer <token>
```

**Response:**
```javascript
{
  "accounts": [
    {
      "id": "acc_001",
      "account_number": "****1234",
      "type": "checking",
      "balance": 125000.50,
      "currency": "USD",
      "status": "active",
      "last_transaction": "2024-01-15T10:00:00Z",
      "overdraft_limit": 5000.00
    }
  ]
}
```

### 2. Banking Actions

#### Fund Transfer
```http
POST /jpmorgan/control/banking-action
Authorization: Bearer <token>
Content-Type: application/json
```

```javascript
{
  "action": "transfer_funds",
  "parameters": {
    "from_account": "acc_001",
    "to_account": "acc_002",
    "amount": 50000.00,
    "currency": "USD",
    "description": "Monthly transfer",
    "scheduled_date": "2024-01-16T09:00:00Z"  // Optional
  }
}
```

#### Process Payment
```javascript
{
  "action": "process_payment",
  "parameters": {
    "account_id": "acc_001",
    "amount": 2500.00,
    "currency": "USD",
    "payee": "Vendor ABC",
    "payment_method": "wire",
    "reference": "INV-2024-001",
    "urgent": false
  }
}
```

#### Account Maintenance
```javascript
{
  "action": "account_maintenance",
  "parameters": {
    "account_id": "acc_001",
    "action_type": "close_account",
    "reason": "Account consolidation",
    "transfer_remaining_balance": "acc_002"
  }
}
```

**Response:**
```javascript
{
  "success": true,
  "action_id": "bank_act_001",
  "transaction_id": "txn_123456",
  "status": "completed",
  "details": {
    "amount": 50000.00,
    "fee": 25.00,
    "confirmation_number": "CONF-2024-001"
  }
}
```

## 📊 Earnings & Analytics APIs

### Base URL
```
https://api.oscar-broome.com/api
```

### 1. Earnings Data

#### Get Earnings Data
```http
GET /api/earnings
Authorization: Bearer <token>
```

**Query Parameters:**
- `period` (optional): `daily`, `weekly`, `monthly`, `yearly`
- `start_date` (optional): ISO 8601 date
- `end_date` (optional): ISO 8601 date
- `stream` (optional): Filter by revenue stream

**Response:**
```javascript
{
  "period": "monthly",
  "total_earnings": 1250000.50,
  "streams": [
    {
      "name": "Consulting Services",
      "amount": 750000.00,
      "percentage": 60.0,
      "trend": "up"
    },
    {
      "name": "Software Licensing",
      "amount": 375000.00,
      "percentage": 30.0,
      "trend": "stable"
    }
  ],
  "projections": {
    "next_month": 1320000.00,
    "confidence": 85.5
  }
}
```

### 2. Analytics Data

#### Get Revenue Analytics
```http
GET /api/analytics/revenue
Authorization: Bearer <token>
```

#### Get AI Predictions
```http
GET /api/analytics/predictions
Authorization: Bearer <token>
```

#### Get Notifications
```http
GET /api/notifications
Authorization: Bearer <token>
```

## 💰 Payroll System APIs

### Base URL
```
https://api.oscar-broome.com/api/payroll
```

### 1. Employee Management

#### Get Employees
```http
GET /api/payroll/employees
Authorization: Bearer <token>
```

### 2. Payroll Processing

#### Process Payroll
```http
POST /api/payroll/process
Authorization: Bearer <token>
Content-Type: application/json
```

```javascript
{
  "pay_period": "2024-01-01 to 2024-01-15",
  "employees": ["emp_001", "emp_002"],
  "include_bonuses": true,
  "quickbooks_sync": true
}
```

### 3. Payroll Reports

#### Get Payroll Reports
```http
GET /api/payroll/reports
Authorization: Bearer <token>
```

## 🛒 Merchant Processing APIs

### Base URL
```
https://api.oscar-broome.com/api/merchant
```

### 1. Payment Processing

#### Process Payment
```http
POST /api/merchant/payment
Authorization: Bearer <token>
Content-Type: application/json
```

```javascript
{
  "amount": 299.99,
  "currency": "USD",
  "payment_method": "card",
  "customer_id": "cust_001",
  "description": "Service payment",
  "metadata": {
    "invoice_id": "INV-2024-001"
  }
}
```

### 2. Transaction History

#### Get Transactions
```http
GET /api/merchant/transactions
Authorization: Bearer <token>
```

### 3. Bill Payments

#### Process Bill Payment
```http
POST /api/merchant/bill-pay
Authorization: Bearer <token>
Content-Type: application/json
```

## 📋 Error Handling

### Standard Error Response
```javascript
{
  "success": false,
  "error": {
    "code": "AUTHENTICATION_FAILED",
    "message": "Invalid or expired token",
    "details": "Token expired at 2024-01-15T10:00:00Z",
    "timestamp": "2024-01-15T10:30:00Z",
    "request_id": "req_123456"
  }
}
```

### Common Error Codes
- `AUTHENTICATION_FAILED`: Invalid credentials or token
- `AUTHORIZATION_FAILED`: Insufficient permissions
- `VALIDATION_ERROR`: Invalid request parameters
- `RESOURCE_NOT_FOUND`: Requested resource doesn't exist
- `RATE_LIMIT_EXCEEDED`: Too many requests
- `SERVICE_UNAVAILABLE`: Service temporarily down
- `QUANTUM_SECURITY_ERROR`: Security validation failed

## 🔒 Security Features

### Request Signing
All critical operations require quantum signature verification:

```javascript
{
  "data": { /* request payload */ },
  "signature": "hmac_sha256_signature",
  "timestamp": 1705312200000,
  "nonce": "unique_request_id"
}
```

### Rate Limiting
- Standard endpoints: 1000 requests/hour
- Control endpoints: 100 requests/hour
- Emergency endpoints: Unlimited (authenticated only)

### Audit Logging
All API calls are logged with:
- Request/response details
- User identification
- Timestamp and signature
- IP address and user agent

## 🧪 Testing

### Test Environment
```bash
# Run API tests
npm run test:api

# Run integration tests
npm run test:integration

# Run security tests
npm run test:security
```

### Mock Data
Use mock mode for testing:
```javascript
process.env.MOCK_MODE = 'true';
```

## 📞 Support

### API Support
- **Documentation**: This document
- **Status Page**: `https://status.oscar-broome.com`
- **Support Ticket**: Create issue in repository
- **Emergency**: Call security hotline

### Version Information
- **Current Version**: 1.0.0
- **Last Updated**: January 15, 2024
- **Supported Until**: December 31, 2024

---

**For technical support or questions, please contact the development team or create a support ticket.**
