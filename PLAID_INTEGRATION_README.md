# Plaid Integration for Proof of Funds and Income Verification

## Overview

This integration provides secure access to bank account data through Plaid's API for proof of funds verification and income validation. The system enables real-time account verification, transaction monitoring, and automated compliance reporting.

## Features

### 💰 Transactions

- **Transaction Data Retrieval**: Access to detailed transaction history with merchant, category, and location data
- **ML-Enhanced Descriptions**: Improved transaction descriptions using Plaid's machine learning
- **Real-time Updates**: Transaction data updated 1-4 times per day depending on institution
- **Historical Data**: Access up to 2 years of transaction history
- **Recurring Transactions**: Identify and analyze recurring payment patterns

### 📈 Investments

- **Holdings Data**: Access to investment account holdings including securities, quantities, and values
- **Transaction History**: Detailed investment transactions (trades, transfers, dividends)
- **Real-time Updates**: Investment data updated once per day after market close
- **ACATS Transfers**: Support for account transfers between brokerages
- **Security Information**: Comprehensive security details and performance data

### 💳 Liabilities

- **Debt Information**: Access to credit card, student loan, mortgage, and PayPal loan details
- **Balance Tracking**: Current outstanding balances and repayment schedules
- **Interest Rates**: Interest rate information for applicable accounts
- **Payment History**: Details of most recent payments and repayment schedules
- **Loan Types**: Support for credit cards, private student loans, mortgages, and PayPal loans

### 🔄 Enrich

- **Transaction Enhancement**: Improve existing transaction data with Plaid's ML-powered enrichment
- **Category Classification**: Automatic categorization of transactions
- **Merchant Identification**: Enhanced merchant name recognition
- **Location Data**: Geographic information for transactions where available
- **Third-party Integration**: Enhance data from non-Plaid sources

### 📈 Investments Move (ACATS Transfers)

- **Broker-Sourced Data**: Obtain account number, account type, account holder name, holdings data, and DTC codes for ACATS transfers
- **Fallback Flows**: Support for institutions with limited data availability
  - **Masked Number Match**: Handle institutions with partial account numbers
  - **Stated Account Number**: Support institutions without account number data
  - **Manual Entry**: Allow users to manually enter transfer information
- **Canada Support**: Retrieve data necessary for ATON transfers in Canada
- **Early Availability**: Access to Plaid's Investments Move feature

### 🔐 Auth (Account & Routing Numbers)

- **Account Number Retrieval**: Secure access to account and routing numbers for ACH payments
- **Tokenized Account Numbers**: Support for TAN-enabled institutions (Chase, PNC, US Bank)
- **Persistent Account IDs**: Consistent identification across different Item instances
- **Consent Management**: Automatic tracking of consent expiration times
- **PNC TAN Handling**: Specialized logic for PNC tokenized account number expiration
- **Multi-Account Support**: Handle multiple accounts per Item with different number types

### 🔐 Proof of Funds Verification

- **Real-time Balance Checking**: Verify account balances against required amounts
- **Multi-Account Support**: Check balances across multiple linked accounts
- **Automated Verification**: Scheduled balance confirmations
- **Compliance Reporting**: Generate proof of funds documentation

### 💰 Income Verification

- **Transaction Analysis**: Analyze income patterns and consistency
- **Income Source Validation**: Verify employment and income sources
- **Historical Data**: Access up to 2 years of transaction history
- **Automated Reporting**: Generate income verification reports

### 🆔 Identity Verification

- **Identity Data Retrieval**: Access to name, email, phone, and address from financial institutions
- **Account Ownership Verification**: Match user-provided identity data against institution records
- **Identity Match Scoring**: Receive confidence scores (0-100) for each identity field
- **Fraud Prevention**: Reduce fraud by verifying account ownership
- **KYC Compliance**: Support Know Your Customer compliance requirements
- **Multi-Owner Support**: Handle accounts with multiple owners

## API Endpoints

### Link Token Creation

```http
POST /api/plaid/create-link-token
Content-Type: application/json

{
  "userId": "user_123",
  "products": ["transactions", "income", "balances"]
}
```

### Public Token Exchange

```http
POST /api/plaid/exchange-public-token
Content-Type: application/json

{
  "publicToken": "public-sandbox-123..."
}
```

### Account Verification

```http
POST /api/plaid/verify-ownership/{accessToken}/{accountId}
Content-Type: application/json

{
  "amounts": [10000, 50000, 100000]
}
```

### Income Data Retrieval

```http
GET /api/plaid/income/{accessToken}
```

### Identity Data Retrieval

```http
GET /api/plaid/identity/{accessToken}
```

### Identity Match Verification

```http
POST /api/plaid/identity/match/{accessToken}
Content-Type: application/json

{
  "legal_name": "John Doe",
  "phone_number": "+1234567890",
  "email_address": "john.doe@example.com",
  "address": {
    "street": "123 Main St",
    "city": "Anytown",
    "region": "CA",
    "postal_code": "12345",
    "country": "US"
  }
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "accounts": [
      {
        "account_id": "account_123",
        "scores": {
          "legal_name": {
            "score": 95
          },
          "phone_number": {
            "score": 100
          },
          "email_address": {
            "score": 100
          },
          "address": {
            "score": 85
          }
        }
      }
    ]
  }
}
```

### Investments Move - Create Link Token

```http
POST /api/plaid/create-link-token
Content-Type: application/json

{
  "userId": "user_123",
  "products": ["investments_auth"],
  "maskedNumberMatchEnabled": true,
  "statedAccountNumberEnabled": true,
  "manualEntryEnabled": true
}
```

### Get Investments Holdings and Transactions

```http
GET /api/plaid/investments/{accessToken}?count=100&offset=0
```

### Get Liabilities Information

```http
GET /api/plaid/liabilities/{accessToken}
```

### Enrich Transactions Data

```http
POST /api/plaid/enrich/transactions
Content-Type: application/json

{
  "transactions": [
    {
      "id": "txn_123",
      "amount": -25.50,
      "date": "2024-01-15",
      "description": "STARBUCKS STORE #1234",
      "account_id": "acc_123"
    }
  ],
  "account_type": "checking",
  "country_code": "US"
}
```

### Investments Move - Get Auth Data

```http
GET /api/plaid/investments/auth/{accessToken}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "accounts": [
      {
        "account_id": "account_123",
        "name": "Investment Account",
        "type": "investment",
        "subtype": "brokerage",
        "mask": "1234",
        "balances": {
          "available": 10000.00,
          "current": 10000.00,
          "iso_currency_code": "USD"
        },
        "numbers": {
          "account": "123456789",
          "routing": "021000021"
        },
        "holdings": [
          {
            "account_id": "account_123",
            "security_id": "sec_123",
            "quantity": 100,
            "price": 50.00,
            "value": 5000.00
          }
        ]
      }
    ],
    "securities": [
      {
        "security_id": "sec_123",
        "name": "Apple Inc.",
        "ticker_symbol": "AAPL",
        "type": "equity"
      }
    ],
    "item": {
      "item_id": "item_123",
      "institution_id": "ins_1"
    }
  }
}
```

## Setup Instructions

### 1. Plaid Account Setup

1. Visit [Plaid Dashboard](https://dashboard.plaid.com)
2. Create a new account (Sandbox for testing)
3. Get your API credentials:
   - `PLAID_CLIENT_ID`
   - `PLAID_SECRET`

### 2. Environment Configuration

Add to your `.env` file:

```bash
PLAID_CLIENT_ID=your_client_id_here
PLAID_SECRET=your_sandbox_secret_here
PLAID_ENV=sandbox  # sandbox, development, production
FRONTEND_URL=http://localhost:3000  # For OAuth redirects
```

### 3. OAuth Configuration (Optional)

For OAuth support with supported institutions:

1. Configure your redirect URI in Plaid Dashboard under "Allowed redirect URIs"
2. Add your OAuth redirect endpoint: `https://yourdomain.com/api/plaid/oauth/redirect`
3. Set `FRONTEND_URL` environment variable for OAuth success/error redirects

### 3. Frontend Integration

```javascript
// Initialize Plaid Link
const linkHandler = Plaid.create({
  token: linkToken,
  onSuccess: (publicToken, metadata) => {
    // Exchange public token for access token
    fetch('/api/plaid/exchange-public-token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ publicToken }),
    });
  },
  onExit: (err, metadata) => {
    console.log('Plaid Link exited:', err, metadata);
  },
});
```

## Use Cases

### Investment Account Verification

- Verify minimum balance requirements
- Confirm account ownership
- Generate compliance reports

### Loan Application Processing

- Income verification for loan qualification
- Asset verification for collateral
- Automated document collection

### Regulatory Compliance

- KYC/AML verification
- Anti-money laundering checks
- Transaction monitoring

### Account Ownership Verification

- Identity match scoring for fraud prevention
- User onboarding verification
- Account security validation
- Multi-factor identity confirmation

## Data Security

### Encryption Standards

- **At Rest**: AES-256-GCM encryption
- **In Transit**: TLS 1.3 encryption
- **Key Management**: AWS KMS or equivalent

### Data Retention

- **Transaction Data**: 2 years maximum
- **Access Tokens**: 30 days expiration
- **Audit Logs**: 7 years retention

### Access Controls

- **Role-Based Access**: Admin, User, Read-only
- **IP Whitelisting**: Restricted access locations
- **MFA Required**: Multi-factor authentication for all users

## Testing

### Sandbox Environment

Use Plaid's sandbox environment for testing:

```javascript
// Test credentials
const testCredentials = {
  username: 'user_good',
  password: 'pass_good',
};
```

### Test Scenarios

1. **Successful Connection**: Verify account linking works
2. **Balance Verification**: Test proof of funds functionality
3. **Income Retrieval**: Validate income data access
4. **Error Handling**: Test failure scenarios

## Production Deployment

### Prerequisites

1. **Production API Keys**: Obtain production credentials from Plaid
2. **SSL Certificate**: Valid SSL certificate required
3. **Compliance Review**: Legal and compliance team approval
4. **Security Audit**: Third-party security assessment

### Deployment Steps

1. Update environment variables to production
2. Configure production webhook endpoints
3. Enable production monitoring and alerting
4. Conduct thorough testing with real accounts
5. Obtain final compliance approval

## Monitoring & Support

### Health Checks

```javascript
// API health check
GET /api/plaid/health

// Response
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0"
}
```

### Error Monitoring

- **Real-time Alerts**: Failed API calls and authentication issues
- **Performance Monitoring**: Response times and success rates
- **Security Monitoring**: Suspicious activity detection

### Support Channels

- **Technical Support**: <support@plaid.com>
- **Documentation**: <https://plaid.com/docs>
- **Status Page**: <https://status.plaid.com>

## Compliance & Legal

### Regulatory Compliance

- **GLBA**: Gramm-Leach-Bliley Act compliance
- **Regulation S-P**: Privacy of consumer financial information
- **FCRA**: Fair Credit Reporting Act compliance

### Data Privacy

- **GDPR Compliant**: EU General Data Protection Regulation
- **CCPA Compliant**: California Consumer Privacy Act
- **Data Minimization**: Only collect necessary financial data

## Troubleshooting

### Common Issues

1. **Invalid Credentials**: Verify API keys are correct
2. **Rate Limiting**: Implement exponential backoff
3. **Webhook Failures**: Check webhook endpoint configuration
4. **Token Expiration**: Implement token refresh logic

### Debug Mode

Enable debug logging:

```javascript
process.env.PLAID_DEBUG = 'true';
```

## Future Enhancements

### Planned Features

- **Enhanced Analytics**: Advanced transaction categorization
- **Risk Scoring**: Automated risk assessment models
- **Multi-Currency Support**: International account support
- **Mobile SDK**: Native mobile application support

### Integration Opportunities

- **Credit Scoring**: Integration with credit bureaus
- **Fraud Detection**: Advanced fraud prevention
- **Investment Platforms**: Robo-advisor integrations
- **Insurance Platforms**: Underwriting automation

---

## Contact Information

### Oscar Broome Revenue System

- **Technical Lead**: Oscar Broome
- **Email**: <oscar.broome@jpmorgan.com>
- **Phone**: +1-212-270-6000

### Plaid Support

- **Website**: <https://plaid.com>
- **Documentation**: <https://plaid.com/docs>
- **Support**: <https://support.plaid.com>

---

_This integration provides secure, compliant access to financial data while maintaining the highest standards of data protection and regulatory compliance._
