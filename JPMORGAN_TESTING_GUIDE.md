# JPMorgan Payment Integration Testing Guide

## Overview

This guide provides comprehensive testing instructions for the JPMorgan Payments API integration in `jpmorgan_payment.js`.

## Prerequisites

1. Set up environment variables:

   ```bash
   JPMORGAN_BASE_URL=https://api.payments.jpmorgan.com
   JPMORGAN_ORGANIZATION_ID=D3R56WRGSR3R
   JPMORGAN_PROJECT_ID=DK2MQSR1FS7V
   JPMORGAN_CLIENT_ID=your_client_id
   JPMORGAN_CLIENT_SECRET=your_client_secret
   JPMORGAN_MERCHANT_ID=your_merchant_id
   JPMORGAN_TERMINAL_ID=your_terminal_id
   ```

2. Install dependencies:
   ```bash
   npm install express axios crypto fs path
   ```

## Testing Endpoints

### 1. Health Check

```bash
curl -X GET http://localhost:3000/jpmorgan/health
```

### 2. Create Payment

```bash
curl -X POST http://localhost:3000/jpmorgan/create-payment \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 100.00,
    "currency": "USD",
    "orderId": "TEST-ORDER-001",
    "description": "Test payment",
    "customer": {
      "name": "John Doe",
      "email": "john@example.com"
    }
  }'
```

### 3. Get Payment Status

```bash
curl -X GET http://localhost:3000/jpmorgan/payment-status/PAYMENT_ID_HERE
```

### 4. Refund Payment

```bash
curl -X POST http://localhost:3000/jpmorgan/refund \
  -H "Content-Type: application/json" \
  -d '{
    "paymentId": "PAYMENT_ID_HERE",
    "amount": 50.00,
    "reason": "Customer request"
  }'
```

### 5. Capture Authorized Payment

```bash
curl -X POST http://localhost:3000/jpmorgan/capture \
  -H "Content-Type: application/json" \
  -d '{
    "paymentId": "PAYMENT_ID_HERE",
    "amount": 100.00
  }'
```

### 6. Void Payment

```bash
curl -X POST http://localhost:3000/jpmorgan/void \
  -H "Content-Type: application/json" \
  -d '{
    "paymentId": "PAYMENT_ID_HERE",
    "reason": "Customer request"
  }'
```

### 7. Get Transaction History

```bash
curl -X GET "http://localhost:3000/jpmorgan/transactions?startDate=2024-01-01&endDate=2024-12-31&limit=10"
```

### 8. Wallet Decryption

```bash
curl -X POST http://localhost:3000/jpmorgan/wallet-decrypt \
  -H "Content-Type: application/json" \
  -d '{
    "encryptedWalletData": "ENCRYPTED_DATA_HERE"
  }'
```

## Treasury Management Endpoints

### 1. Cash Positions

```bash
curl -X GET "http://localhost:3000/jpmorgan/treasury/cash-positions?currency=USD"
```

### 2. Foreign Exchange Rates

```bash
curl -X GET "http://localhost:3000/jpmorgan/treasury/fx-rates?baseCurrency=USD&quoteCurrency=EUR"
```

### 3. Liquidity Forecast

```bash
curl -X GET "http://localhost:3000/jpmorgan/treasury/liquidity-forecast?days=30&currency=USD"
```

### 4. Risk Exposure

```bash
curl -X GET "http://localhost:3000/jpmorgan/treasury/risk-exposure?currency=USD"
```

### 5. Portfolio Performance

```bash
curl -X GET "http://localhost:3000/jpmorgan/treasury/portfolio-performance?period=1M&currency=USD"
```

### 6. Cash Flow Analytics

```bash
curl -X GET "http://localhost:3000/jpmorgan/treasury/cash-flow-analytics?granularity=daily&currency=USD"
```

### 7. Treasury Health Check

```bash
curl -X GET http://localhost:3000/jpmorgan/treasury/health
```

## QuickBooks Integration Testing

### Sync Payments with QuickBooks

```bash
curl -X POST http://localhost:3000/jpmorgan/sync-quickbooks
```

## Webhook Testing

### Simulate Webhook Event

```bash
curl -X POST http://localhost:3000/jpmorgan/webhook \
  -H "Content-Type: application/json" \
  -H "x-jpmorgan-signature: SIGNATURE_HERE" \
  -H "x-jpmorgan-timestamp: TIMESTAMP_HERE" \
  -H "x-jpmorgan-nonce: NONCE_HERE" \
  -d '{
    "type": "payment.authorized",
    "id": "evt_1234567890",
    "data": {
      "paymentId": "PAYMENT_ID_HERE"
    }
  }'
```

## Automated Testing Script

Create a test script `test_jpmorgan_endpoints.js`:

```javascript
const axios = require('axios');

const BASE_URL = 'http://localhost:3000/jpmorgan';

async function testEndpoints() {
  try {
    // Test health check
    console.log('Testing health check...');
    const healthResponse = await axios.get(`${BASE_URL}/health`);
    console.log('Health check:', healthResponse.data);

    // Test treasury health
    console.log('Testing treasury health...');
    const treasuryHealth = await axios.get(`${BASE_URL}/treasury/health`);
    console.log('Treasury health:', treasuryHealth.data);
  } catch (error) {
    console.error('Test failed:', error.response?.data || error.message);
  }
}

testEndpoints();
```

## Error Handling Tests

### Test Invalid Payment Creation

```bash
curl -X POST http://localhost:3000/jpmorgan/create-payment \
  -H "Content-Type: application/json" \
  -d '{}'
```

Expected response: 400 Bad Request with error message

### Test Non-existent Payment Status

```bash
curl -X GET http://localhost:3000/jpmorgan/payment-status/INVALID_ID
```

Expected response: 500 Internal Server Error

## Performance Testing

Use tools like Artillery or k6 for load testing:

```yaml
# artillery.yml
config:
  target: 'http://localhost:3000'
  phases:
    - duration: 60
      arrivalRate: 10

scenarios:
  - name: 'Payment creation load test'
    requests:
      - post:
          url: '/jpmorgan/create-payment'
          json:
            amount: 100
            currency: 'USD'
            orderId: 'LOAD-TEST-{{ $randomInt }}'
```

## Security Testing

1. Test webhook signature verification
2. Test authentication headers
3. Test rate limiting
4. Test input validation

## Integration Testing Checklist

- [ ] All endpoints return expected responses
- [ ] Error handling works correctly
- [ ] Authentication headers are generated properly
- [ ] Webhook signature verification works
- [ ] QuickBooks integration syncs correctly
- [ ] Treasury endpoints function properly
- [ ] Performance meets requirements
- [ ] Security measures are in place

## Troubleshooting

### Common Issues

1. **Authentication Errors**: Check environment variables
2. **Timeout Errors**: Verify network connectivity to JPMorgan API
3. **Webhook Signature Failures**: Ensure webhook secret is correct
4. **QuickBooks Sync Failures**: Check QuickBooks credentials

### Debug Mode

Enable debug logging by setting:

```bash
DEBUG=jpmorgan:* npm start
```

## Production Deployment Checklist

- [ ] Environment variables configured
- [ ] SSL certificates installed
- [ ] Webhook endpoints secured
- [ ] Rate limiting configured
- [ ] Monitoring and alerting set up
- [ ] Backup and recovery procedures in place
