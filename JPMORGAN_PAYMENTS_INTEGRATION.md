# JPMorgan Payments Integration Guide

## Overview

This document provides comprehensive documentation for integrating JPMorgan Payments into the Oscar Broome Revenue system. The integration allows processing payments through JPMorgan's payment gateway alongside existing payment providers like Stripe.

## API Endpoints

The JPMorgan Payments integration provides the following API endpoints:

### Base URL
All endpoints are mounted under `/api/jpmorgan-payment/`

### 1. Create Payment
- **Endpoint**: `POST /api/jpmorgan-payment/create-payment`
- **Description**: Creates a new payment transaction
- **Request Body**:
  ```json
  {
    "amount": 10000, // Amount in cents
    "currency": "USD", // Optional, defaults to USD
    "orderId": "ORDER-12345", // Required unique order identifier
    "description": "Payment for services", // Optional
    "customer": {
      "email": "customer@example.com",
      "firstName": "John",
      "lastName": "Doe"
    } // Optional customer information
  }
  ```
- **Response**:
  ```json
  {
    "success": true,
    "paymentId": "PAY-123456789",
    "status": "AUTHORIZED",
    "authorizationCode": "AUTH123",
    "transactionDetails": { ... }
  }
  ```

### 2. Get Payment Status
- **Endpoint**: `GET /api/jpmorgan-payment/payment-status/:paymentId`
- **Description**: Retrieves the status of a specific payment
- **Response**:
  ```json
  {
    "success": true,
    "paymentStatus": {
      "id": "PAY-123456789",
      "status": "CAPTURED",
      "amount": 10000,
      "currency": "USD",
      "createdAt": "2024-01-15T10:30:00Z"
    }
  }
  ```

### 3. Refund Payment
- **Endpoint**: `POST /api/jpmorgan-payment/refund`
- **Description**: Processes a refund for an existing payment
- **Request Body**:
  ```json
  {
    "paymentId": "PAY-123456789",
    "amount": 5000, // Partial refund amount in cents
    "reason": "Customer request" // Optional
  }
  ```
- **Response**:
  ```json
  {
    "success": true,
    "refundId": "REF-987654321",
    "status": "COMPLETED",
    "refundDetails": { ... }
  }
  ```

### 4. Capture Payment
- **Endpoint**: `POST /api/jpmorgan-payment/capture`
- **Description**: Captures a previously authorized payment
- **Request Body**:
  ```json
  {
    "paymentId": "PAY-123456789",
    "amount": 10000 // Optional, defaults to full authorized amount
  }
  ```
- **Response**:
  ```json
  {
    "success": true,
    "captureId": "CAP-123456789",
    "status": "COMPLETED",
    "captureDetails": { ... }
  }
  ```

### 5. Void Payment
- **Endpoint**: `POST /api/jpmorgan-payment/void`
- **Description**: Voids/cancels an authorized payment
- **Request Body**:
  ```json
  {
    "paymentId": "PAY-123456789",
    "reason": "Customer request" // Optional
  }
  ```
- **Response**:
  ```json
  {
    "success": true,
    "voidId": "VOID-123456789",
    "status": "VOIDED",
    "voidDetails": { ... }
  }
  ```

### 6. Get Transaction History
- **Endpoint**: `GET /api/jpmorgan-payment/transactions`
- **Query Parameters**:
  - `startDate`: Start date for filtering (ISO format)
  - `endDate`: End date for filtering (ISO format)
  - `status`: Filter by transaction status
  - `limit`: Number of results to return (default: 50)
- **Response**:
  ```json
  {
    "success": true,
    "transactions": [...],
    "totalCount": 150
  }
  ```

### 7. Webhook Endpoint
- **Endpoint**: `POST /api/jpmorgan-payment/webhook`
- **Description**: Receives webhook events from JPMorgan Payments
- **Headers**: Requires JPMorgan signature verification headers
- **Events Handled**:
  - `payment.authorized`
  - `payment.captured`
  - `payment.refunded`
  - `payment.voided`
  - `payment.failed`

### 8. Health Check
- **Endpoint**: `GET /api/jpmorgan-payment/health`
- **Description**: Checks the health of the JPMorgan Payments integration
- **Response**:
  ```json
  {
    "status": "healthy",
    "jpmorganStatus": "available",
    "timestamp": "2024-01-15T10:30:00Z"
  }
  ```

## Environment Configuration

Create a `.env` file with the following JPMorgan-specific variables:

```bash
# JPMorgan Payments API Configuration
JPMORGAN_BASE_URL=https://api-mock.payments.jpmorgan.com
JPMORGAN_CLIENT_ID=your_client_id_here
JPMORGAN_CLIENT_SECRET=your_client_secret_here
JPMORGAN_MERCHANT_ID=your_merchant_id_here
JPMORGAN_TERMINAL_ID=your_terminal_id_here
JPMORGAN_WEBHOOK_SECRET=your_webhook_secret_here
JPMORGAN_API_TIMEOUT=10000
JPMORGAN_DEBUG=true
```

## Authentication

The integration uses HMAC-SHA256 authentication with the following headers:
- `Client-Id`: Your JPMorgan client ID
- `Timestamp`: Current UNIX timestamp
- `Nonce`: Random 16-byte hex string
- `Signature`: HMAC-SHA256 signature of the message
- `Merchant-Id`: Your merchant ID
- `Terminal-Id`: Your terminal ID

## Webhook Security

Webhook requests are verified using HMAC signatures. The signature is computed as:
```
signature = HMAC-SHA256(secret_key, timestamp + nonce + request_body)
```

## Error Handling

All endpoints return standardized error responses:

```json
{
  "success": false,
  "error": "Error message",
  "details": "Additional error details if available"
}
```

## Integration with Existing System

The JPMorgan Payments integration works alongside existing payment providers:
- Mounted under `/api/jpmorgan-payment/` route
- Uses the same revenue data structure
- Follows the same authentication patterns as other API endpoints
- Can be used alongside Stripe, Microsoft Payments, etc.

## Testing

To test the integration:

1. Set up sandbox credentials in your `.env` file
2. Use the health endpoint to verify connectivity
3. Test payment creation with small amounts
4. Verify webhook handling with test events

## Security Considerations

- Never commit actual credentials to version control
- Use environment variables for all sensitive data
- Enable webhook signature verification
- Implement proper error logging and monitoring
- Follow JPMorgan's security best practices

## Support

For issues with the JPMorgan Payments integration:
1. Check the server logs for detailed error messages
2. Verify all environment variables are set correctly
3. Test connectivity using the health endpoint
4. Consult JPMorgan's API documentation for specific error codes
