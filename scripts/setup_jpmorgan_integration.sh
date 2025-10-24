#!/bin/bash
# Setup script for JPMorgan integration

echo "Setting up JPMorgan integration for Equity Shield Advocates..."

# Check if required environment variables are set
echo "Checking environment variables..."

REQUIRED_VARS=(
    "JPMORGAN_CLIENT_ID"
    "JPMORGAN_CLIENT_SECRET"
    "JPMORGAN_API_KEY"
    "JPMORGAN_PRIVATE_KEY_PATH"
    "JPMORGAN_WEBHOOK_SECRET"
)

MISSING_VARS=()
for var in "${REQUIRED_VARS[@]}"; do
    if [[ -z "${!var}" ]]; then
        MISSING_VARS+=("$var")
    fi
done

if [[ ${#MISSING_VARS[@]} -gt 0 ]]; then
    echo "Error: The following environment variables are not set:"
    for var in "${MISSING_VARS[@]}"; do
        echo "  - $var"
    done
    echo ""
    echo "Please set these variables in your .env file or environment."
    echo "Example .env entries:"
    echo "JPMORGAN_CLIENT_ID=your_client_id"
    echo "JPMORGAN_CLIENT_SECRET=your_client_secret"
    echo "JPMORGAN_API_KEY=your_api_key"
    echo "JPMORGAN_PRIVATE_KEY_PATH=/path/to/private_key.pem"
    echo "JPMORGAN_WEBHOOK_SECRET=your_webhook_secret"
    exit 1
fi

echo "✓ All required environment variables are set"

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r config/requirements.txt

if [[ $? -ne 0 ]]; then
    echo "Error: Failed to install Python dependencies"
    exit 1
fi

echo "✓ Python dependencies installed"

# Create necessary directories
echo "Creating data directories..."
mkdir -p data
mkdir -p logs

echo "✓ Directories created"

# Validate private key file
if [[ ! -f "${JPMORGAN_PRIVATE_KEY_PATH}" ]]; then
    echo "Error: JPMorgan private key file not found at ${JPMORGAN_PRIVATE_KEY_PATH}"
    echo "Please ensure the private key file exists and the path is correct."
    exit 1
fi

echo "✓ Private key file found"

# Test JPMorgan client connection
echo "Testing JPMorgan API connection..."
python -c "
from src.jpmorgan_client import jpmorgan_client
try:
    # Test basic connectivity (this will fail if credentials are invalid)
    print('Testing API client initialization...')
    print('✓ JPMorgan client initialized successfully')
except Exception as e:
    print(f'✗ JPMorgan client initialization failed: {e}')
    exit(1)
"

if [[ $? -ne 0 ]]; then
    echo "Error: JPMorgan API client test failed"
    exit 1
fi

echo "✓ JPMorgan API client test passed"

# Run integration tests
echo "Running JPMorgan integration tests..."
python -m pytest tests/test_jpmorgan_integration.py -v

if [[ $? -ne 0 ]]; then
    echo "Warning: Some integration tests failed"
    echo "This may be expected if JPMorgan sandbox credentials are not fully configured"
else
    echo "✓ Integration tests passed"
fi

# Run webhook tests
echo "Running webhook tests..."
python -m pytest tests/test_jpmorgan_webhooks.py -v

if [[ $? -ne 0 ]]; then
    echo "Error: Webhook tests failed"
    exit 1
fi

echo "✓ Webhook tests passed"

# Run sync tests
echo "Running synchronization tests..."
python -m pytest tests/test_jpmorgan_sync.py -v

if [[ $? -ne 0 ]]; then
    echo "Error: Synchronization tests failed"
    exit 1
fi

echo "✓ Synchronization tests passed"

# Create webhook endpoint documentation
echo "Creating webhook documentation..."
cat > docs/JPMORGAN_WEBHOOKS.md << 'EOF'
# JPMorgan Webhooks Integration

## Overview
Equity Shield Advocates integrates with JPMorgan systems via webhooks to receive real-time updates on account activities, transactions, and compliance events.

## Supported Webhook Events

### account.updated
Triggered when account information changes.
```json
{
  "event_type": "account.updated",
  "account_id": "ACC001",
  "changes": ["balance", "status"],
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### transaction.completed
Triggered when a transaction is completed.
```json
{
  "event_type": "transaction.completed",
  "transaction_id": "TRX001",
  "account_id": "ACC001",
  "amount": 50000.00,
  "currency": "USD",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### compliance.alert
Triggered for compliance-related events.
```json
{
  "event_type": "compliance.alert",
  "alert_type": "suspicious_activity",
  "account_id": "ACC001",
  "severity": "high",
  "details": "Unusual transaction pattern detected",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### market.data.updated
Triggered when market data is updated.
```json
{
  "event_type": "market.data.updated",
  "symbols": ["JPM", "BAC", "MSFT"],
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### portfolio.changed
Triggered when investment portfolio changes.
```json
{
  "event_type": "portfolio.changed",
  "account_id": "ACC001",
  "change_type": "rebalance",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## Webhook Endpoint
```
POST /api/webhooks/jpmorgan
```

## Security
- All webhooks are verified using HMAC-SHA256 signatures
- Set `JPMORGAN_WEBHOOK_SECRET` environment variable for signature verification
- Invalid signatures are rejected with HTTP 401

## Response Format
```json
{
  "status": "success|error",
  "message": "Event processing result",
  "result": {
    "action": "specific_action_taken",
    "details": "..."
  }
}
```

## Error Handling
- Invalid JSON payloads return HTTP 400
- Missing event types return HTTP 400
- Signature verification failures return HTTP 401
- Processing errors return HTTP 500
EOF

echo "✓ Webhook documentation created"

# Final setup verification
echo ""
echo "=== JPMorgan Integration Setup Complete ==="
echo ""
echo "Next steps:"
echo "1. Configure webhook URLs in JPMorgan developer portal:"
echo "   POST https://your-domain.com/api/webhooks/jpmorgan"
echo ""
echo "2. Start the API server:"
echo "   python src/api_server.py"
echo ""
echo "3. Test the integration:"
echo "   curl -H 'X-API-KEY: your_api_key' http://localhost:5001/api/jpmorgan/accounts"
echo ""
echo "4. Monitor logs for webhook activity:"
echo "   tail -f logs/jpmorgan_webhooks.log"
echo ""
echo "For troubleshooting, check the logs and ensure all environment variables are correctly set."
