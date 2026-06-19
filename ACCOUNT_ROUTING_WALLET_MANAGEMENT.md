# Account Numbers, Routing Numbers & Blockchain Wallets Management Guide

## Overview

This document provides detailed management procedures for account numbers, routing numbers, and blockchain wallets within the Oscar Broome Revenue System. All operations are designed with security, compliance, and auditability as primary concerns.

## Account Numbers Management

### Account Number Structure

#### Banking Account Format

- **Length**: 8-17 digits
- **Format**: Standard US banking account numbers
- **Validation**: ABA routing number compatible
- **Masking**: Last 4 digits displayed in logs/interfaces

#### Account Types Supported

- **Checking Accounts**: Primary operational accounts
- **Savings Accounts**: Reserve and emergency funds
- **Treasury Accounts**: Cash management and investments
- **Payroll Accounts**: Employee compensation processing

### Account Number Validation

#### Validation Rules

```javascript
function validateAccountNumber(accountNumber) {
  // Must be numeric only
  if (!/^\d+$/.test(accountNumber)) {
    return { valid: false, reason: 'Account number must contain only digits' };
  }

  // Length validation
  if (accountNumber.length < 8 || accountNumber.length > 17) {
    return { valid: false, reason: 'Account number must be 8-17 digits long' };
  }

  // Security validation - cannot start with 0
  if (accountNumber.startsWith('0')) {
    return { valid: false, reason: 'Account number cannot start with 0' };
  }

  return { valid: true };
}
```

#### Implementation in Code

```javascript
// From payroll_integration.js
if (accountNumber.startsWith('0')) {
  await new Promise((resolve) => setTimeout(resolve, 500));
  throw new Error('Invalid account number: cannot start with 0');
}
```

### Account Number Storage

#### Security Measures

- **Encryption**: AES-256-GCM encryption at rest
- **Masking**: Only last 4 digits stored in logs
- **Tokenization**: PCI DSS compliant tokenization
- **Access Control**: Role-based access restrictions

#### Storage Format

```javascript
{
  "accountId": "acc_123456",
  "accountNumber": "****-****-****-1234", // Masked
  "routingNumber": "021000021",
  "accountType": "checking",
  "owner": "Oscar Broome",
  "encryptedData": "encrypted_blob_here",
  "lastUpdated": "2024-01-15T10:30:00Z"
}
```

## Routing Numbers Management

### Routing Number Structure

#### ABA Routing Number Format

- **Length**: Exactly 9 digits
- **Format**: XXYYYYYYY (Federal Reserve District + Bank Code)
- **Validation**: Checksum algorithm required
- **Usage**: ACH, wire transfers, check processing

### Routing Number Validation

#### ABA Checksum Algorithm

```javascript
function validateRoutingNumber(routingNumber) {
  // Must be exactly 9 digits
  if (!/^\d{9}$/.test(routingNumber)) {
    return { valid: false, reason: 'Routing number must be exactly 9 digits' };
  }

  // ABA checksum validation
  const digits = routingNumber.split('').map(Number);
  const checksum =
    (3 * (digits[0] + digits[3] + digits[6]) +
      7 * (digits[1] + digits[4] + digits[7]) +
      1 * (digits[2] + digits[5] + digits[8])) %
    10;

  if (checksum !== 0) {
    return { valid: false, reason: 'Invalid ABA routing number checksum' };
  }

  return { valid: true };
}
```

#### JPMorgan Chase Routing Numbers

- **Primary**: 021000021 (New York)
- **California**: 322271627
- **Texas**: 111000614
- **Florida**: 267084131
- **Illinois**: 071000013

### Routing Number Operations

#### Adding New Routing Numbers

```javascript
async function addRoutingNumber(accountId, routingNumber, bankName) {
  // Validate routing number
  const validation = validateRoutingNumber(routingNumber);
  if (!validation.valid) {
    throw new Error(validation.reason);
  }

  // Check for duplicates
  const existing = await getRoutingNumberByValue(routingNumber);
  if (existing) {
    throw new Error('Routing number already exists in system');
  }

  // Store routing number
  const routingData = {
    id: generateId(),
    accountId,
    routingNumber,
    bankName,
    status: 'active',
    createdAt: new Date().toISOString(),
    createdBy: 'system',
  };

  await saveRoutingNumber(routingData);

  // Log to blockchain
  await blockchainService.recordTransaction('system', accountId, 0, {
    type: 'routing_number_added',
    routingNumber: routingNumber,
    bankName: bankName,
  });

  return routingData;
}
```

## Blockchain Wallets Management

### Wallet Types Supported

#### Cryptocurrency Wallets

- **Bitcoin (BTC)**: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
- **Ethereum (ETH)**: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
- **USDC (ERC-20)**: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e

#### Wallet Security Features

- **Multi-signature**: 2-of-3 signature requirement
- **Cold Storage**: Hardware wallet for large amounts
- **Backup**: Encrypted seed phrase storage
- **Rotation**: Regular key rotation procedures

### Wallet Operations

#### Wallet Encryption

```javascript
// POST /wallet-encrypt
{
  "cardNumber": "4111111111111111",
  "expiryDate": "12/25",
  "cvv": "123",
  "cardholderName": "John Doe",
  "billingAddress": {
    "street": "123 Main St",
    "city": "New York",
    "state": "NY",
    "zipCode": "10001",
    "country": "US"
  }
}

// Response
{
  "success": true,
  "encryptedData": "encrypted_wallet_data_here",
  "walletId": "wallet_12345"
}
```

#### Wallet Tokenization

```javascript
// POST /wallet-tokenize
{
  "cardNumber": "4111111111111111",
  "expiryDate": "12/25",
  "cvv": "123",
  "cardholderName": "John Doe"
}

// Response
{
  "success": true,
  "token": "tok_1234567890abcdef",
  "tokenId": "token_12345",
  "expiresAt": "2025-12-31T23:59:59Z"
}
```

#### Wallet Decryption

```javascript
// POST /wallet-decrypt
{
  "encryptedWalletData": "encrypted_data_here"
}

// Response
{
  "success": true,
  "decryptedWallet": {
    "cardNumber": "4111111111111111",
    "expiryDate": "12/25",
    "cardholderName": "John Doe"
  }
}
```

### Blockchain Integration

#### Audit Trail Recording

```javascript
// Record wallet operation in blockchain
await blockchainService.recordTransaction(fromAddress, toAddress, amount, {
  type: 'wallet_operation',
  operation: 'encryption|tokenization|decryption',
  walletId: walletId,
  timestamp: Date.now(),
});
```

#### Transaction Verification

```javascript
// Verify transaction in blockchain
const auditTrail = await blockchainService.getAuditTrail(transactionId);
const verification = blockchainService.verifyAuditTrail(auditTrail);
```

## Security Protocols

### Data Protection

#### Encryption Standards

- **Symmetric Encryption**: AES-256-GCM
- **Asymmetric Encryption**: RSA-4096 for key exchange
- **Hashing**: SHA3-256 for integrity
- **HMAC**: For request authentication

#### Access Controls

- **Role-Based Access**: Admin, User, Read-only roles
- **Multi-Factor Authentication**: Required for sensitive operations
- **IP Whitelisting**: Restricted access locations
- **Session Management**: Automatic timeout and rotation

### Compliance Requirements

#### PCI DSS Compliance

- **Data Storage**: Never store full card numbers
- **Tokenization**: Use secure tokenization services
- **Encryption**: AES-256 minimum standard
- **Access Logging**: All access attempts logged

#### SOX Compliance

- **Audit Trails**: Immutable blockchain records
- **Change Management**: Version control and approval
- **Access Reviews**: Regular permission audits
- **Incident Response**: Documented breach procedures

### Monitoring & Alerting

#### Real-time Monitoring

- **Failed Access Attempts**: Alert on suspicious activity
- **Unusual Patterns**: Anomaly detection algorithms
- **Compliance Violations**: Automated compliance checks
- **System Health**: Performance and availability monitoring

#### Alert Thresholds

- **Failed Logins**: > 5 attempts in 15 minutes
- **Invalid Routing Numbers**: Any invalid submissions
- **Wallet Access**: All wallet operations logged
- **Account Changes**: All account modifications tracked

## Operational Procedures

### Adding New Accounts

#### Step-by-Step Process

1. **Validation**: Verify account ownership documents
2. **Security Review**: Assess security requirements
3. **System Entry**: Add account with masked storage
4. **Testing**: Validate account connectivity
5. **Approval**: Executive approval for high-value accounts
6. **Documentation**: Update ownership documentation
7. **Audit**: Record in blockchain ledger

#### Required Documentation

- Bank account statements
- Account ownership verification
- Authorization signatures
- Compliance certifications

### Updating Routing Numbers

#### Change Management Process

1. **Business Justification**: Document reason for change
2. **Impact Assessment**: Evaluate system impact
3. **Testing**: Test with new routing number
4. **Change Window**: Schedule during low-activity period
5. **Rollback Plan**: Prepare contingency procedures
6. **Execution**: Update in all systems
7. **Verification**: Confirm successful routing
8. **Documentation**: Update all records

### Wallet Management Procedures

#### Key Rotation

1. **Generate New Keys**: Create new wallet addresses
2. **Transfer Assets**: Move funds to new addresses
3. **Update Systems**: Change addresses in all integrations
4. **Verify Transfers**: Confirm successful asset movement
5. **Secure Old Keys**: Archive old keys securely
6. **Update Documentation**: Record key rotation details
7. **Audit Record**: Log rotation in blockchain

#### Emergency Access

1. **Trigger Emergency**: Activate emergency override
2. **Multi-Person Approval**: Require secondary authorization
3. **Limited Access**: Time-bound access window
4. **Full Audit**: Record all emergency actions
5. **Post-Incident Review**: Analyze emergency access usage

## Emergency Procedures

### Account Compromise Response

1. **Immediate Isolation**: Disable compromised accounts
2. **Notification**: Alert security team and authorities
3. **Investigation**: Forensic analysis of breach
4. **Recovery**: Restore from clean backups
5. **Communication**: Notify affected parties
6. **Prevention**: Implement additional security measures

### Routing Number Issues

1. **Verification**: Confirm routing number validity
2. **Bank Communication**: Contact bank for confirmation
3. **System Update**: Correct routing number in systems
4. **Transaction Review**: Check for failed transactions
5. **Customer Notification**: Inform affected customers
6. **Process Improvement**: Update validation procedures

### Wallet Security Breach

1. **Asset Freeze**: Immediately secure all wallets
2. **Key Assessment**: Evaluate key compromise extent
3. **Asset Recovery**: Move funds to secure wallets
4. **Investigation**: Blockchain analysis of transactions
5. **Legal Action**: Report to authorities if criminal
6. **System Enhancement**: Implement additional security

## Maintenance & Updates

### Regular Maintenance Tasks

#### Monthly Tasks

- Review account access logs
- Update routing number databases
- Verify wallet balances
- Check compliance status
- Update security patches

#### Quarterly Tasks

- Full security audit
- Compliance certification review
- Key rotation assessment
- Backup integrity verification
- Performance optimization

#### Annual Tasks

- Complete system audit
- Regulatory compliance review
- Disaster recovery testing
- Business continuity planning
- Security policy updates

### System Updates

#### Update Procedures

1. **Planning**: Assess update requirements
2. **Testing**: Comprehensive testing in staging
3. **Backup**: Full system backup creation
4. **Deployment**: Phased rollout approach
5. **Monitoring**: Post-deployment monitoring
6. **Rollback**: Quick rollback capability
7. **Documentation**: Update procedures and documentation

## Contact Information

### Primary Contacts

- **System Owner**: Oscar Broome (<oscar.broome@jpmorgan.com>)
- **Security Team**: <security@oscarsystem.com>
- **Compliance Officer**: <compliance@oscarsystem.com>
- **Technical Support**: <support@oscarsystem.com>

### Emergency Contacts

- **24/7 Security Hotline**: +1-800-SECURITY
- **Banking Emergency**: JPMorgan Emergency Line
- **Regulatory Reporting**: Primary Regulator Hotline

---

## Document Information

- **Document Owner**: Oscar Broome
- **Last Updated**: January 2024
- **Review Cycle**: Quarterly
- **Classification**: Restricted
- **Version**: 1.0

**This document contains sensitive financial information. Access is restricted to authorized personnel only.**
