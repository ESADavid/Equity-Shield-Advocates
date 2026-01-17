# JPMorgan Wallet Management Endpoints

This document describes the additional wallet management endpoints that have been added to the JPMorgan payment module for enhanced security and compliance.

## Overview

The wallet management endpoints provide secure handling of sensitive payment data through encryption, validation, tokenization, and detokenization processes. These endpoints ensure PCI DSS compliance by never storing sensitive card data in plain text.

## Available Endpoints

### 1. Wallet Encryption (`POST /wallet-encrypt`)

Encrypts sensitive card data for secure storage.

**Request Body:**

```json
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
```

**Response:**

```json
{
  "success": true,
  "encryptedData": "encrypted_wallet_data_here",
  "walletId": "wallet_12345"
}
```

### 2. Wallet Validation (`POST /wallet-validate`)

Validates encrypted wallet data for integrity and authenticity.

**Request Body:**

```json
{
  "walletData": "encrypted_wallet_data_here"
}
```

**Response:**

```json
{
  "success": true,
  "isValid": true,
  "message": "Wallet data is valid",
  "validationDetails": {
    "cardType": "VISA",
    "expiryValid": true,
    "cvvValid": true
  }
}
```

### 3. Wallet Tokenization (`POST /wallet-tokenize`)

Creates a secure token representing the card data for future transactions.

**Request Body:**

```json
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
```

**Response:**

```json
{
  "success": true,
  "token": "tok_1234567890abcdef",
  "tokenId": "token_12345",
  "expiresAt": "2025-12-31T23:59:59Z"
}
```

### 4. Wallet Detokenization (`POST /wallet-detokenize`)

Retrieves the original card data from a token (for authorized use only).

**Request Body:**

```json
{
  "token": "tok_1234567890abcdef"
}
```

**Response:**

```json
{
  "success": true,
  "walletData": {
    "cardNumber": "4111111111111111",
    "expiryDate": "12/25",
    "cardholderName": "John Doe",
    "billingAddress": {
      "street": "123 Main St",
      "city": "New York",
      "state": "NY",
      "zipCode": "10001",
      "country": "US"
    }
  }
}
```

### 5. Wallet Decryption (`POST /wallet-decrypt`) - Existing

Decrypts previously encrypted wallet data.

**Request Body:**

```json
{
  "encryptedWalletData": "encrypted_data_here"
}
```

**Response:**

```json
{
  "success": true,
  "decryptedWallet": {
    "cardNumber": "4111111111111111",
    "expiryDate": "12/25",
    "cardholderName": "John Doe"
  }
}
```

## Security Features

- **PCI DSS Compliance**: Sensitive data is never stored in plain text
- **HMAC Authentication**: All requests are authenticated using HMAC signatures
- **Data Encryption**: AES-256 encryption for sensitive data
- **Token Expiration**: Tokens have configurable expiration times
- **Audit Logging**: All wallet operations are logged for compliance

## Error Handling

All endpoints return standardized error responses:

```json
{
  "success": false,
  "error": "Error description",
  "details": "Detailed error information"
}
```

Common HTTP status codes:

- `400` - Bad Request (missing required fields)
- `401` - Unauthorized (invalid authentication)
- `500` - Internal Server Error (API or processing errors)

## Usage Examples

### JavaScript/Node.js

```javascript
const axios = require('axios');

// Encrypt card data
const encryptResponse = await axios.post(
  '/api/jpmorgan-payment/wallet-encrypt',
  {
    cardNumber: '4111111111111111',
    expiryDate: '12/25',
    cvv: '123',
    cardholderName: 'John Doe',
  }
);

// Use token for payment
const paymentResponse = await axios.post(
  '/api/jpmorgan-payment/create-payment',
  {
    amount: 100.0,
    orderId: 'order_123',
    token: encryptResponse.data.token,
  }
);
```

### cURL Examples

```bash
# Encrypt wallet data
curl -X POST http://localhost:3000/api/jpmorgan-payment/wallet-encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "cardNumber": "4111111111111111",
    "expiryDate": "12/25",
    "cvv": "123",
    "cardholderName": "John Doe"
  }'

# Validate wallet data
curl -X POST http://localhost:3000/api/jpmorgan-payment/wallet-validate \
  -H "Content-Type: application/json" \
  -d '{
    "walletData": "encrypted_data_here"
  }'
```

## Testing

Run the comprehensive test suite:

```bash
node test_wallet_endpoints.js
```

This will test all wallet endpoints with various scenarios including:

- Successful operations
- Missing required fields
- Invalid data formats
- Authentication failures

## Configuration

Ensure the following environment variables are set:

```env
JPMORGAN_BASE_URL=https://api.payments.jpmorgan.com
JPMORGAN_ORGANIZATION_ID=your_org_id
JPMORGAN_PROJECT_ID=your_project_id
JPMORGAN_CLIENT_ID=your_client_id
JPMORGAN_CLIENT_SECRET=your_client_secret
JPMORGAN_MERCHANT_ID=your_merchant_id
JPMORGAN_TERMINAL_ID=your_terminal_id
```

## Files Created

- `jpmorgan_payment_complete.js` - Complete module with all wallet endpoints
- `wallet_endpoints.js` - Standalone wallet endpoints module
- `test_wallet_endpoints.js` - Comprehensive test suite
- `WALLET_ENDPOINTS_README.md` - This documentation

## Integration Notes

- The wallet endpoints are designed to work seamlessly with existing payment endpoints
- All endpoints use the same authentication mechanism as other JPMorgan endpoints
- Tokenization supports both one-time and recurring payment scenarios
- Encryption/decryption operations are optimized for performance
