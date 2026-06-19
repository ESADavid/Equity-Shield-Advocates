# Plaid Credentials Setup Guide

This guide will help you configure your Plaid API credentials for the OSCAR BROOME REVENUE system.

## Prerequisites

- Plaid account access
- Client ID and Secret from Plaid Dashboard
- Visit https://dashboard.plaid.com/developers/integrations to get credentials

## Setup Instructions

### Option 1: Automated PowerShell Script (Recommended for Windows)

1. Open PowerShell as Administrator
2. Navigate to the project root directory:

   ```powershell
   cd C:\Users\bsean\OneDrive\Documents\GitHub\OSCAR-BROOME-REVENUE
   ```

3. Run the setup script:

   ```powershell
   .\setup_plaid_credentials.ps1
   ```

4. Enter your Plaid credentials when prompted:
   - Client ID
   - Secret
   - Environment (sandbox/development/production)

5. Restart your terminal/IDE

### Option 2: Manual Environment Variable Setup

#### Windows (System Environment Variables)

1. Open Start menu and search for "Environment Variables"
2. Click "Edit the system environment variables"
3. Click "Environment Variables..." button
4. Under "User variables", click "New..." for each variable:

   **Required Variables:**
   - `PLAID_CLIENT_ID` = Your Plaid Client ID
   - `PLAID_SECRET` = Your Plaid Secret
   - `PLAID_ENV` = sandbox (or development/production)

5. Click OK and restart your terminal/IDE

#### Windows (Command Line)

```cmd
setx PLAID_CLIENT_ID "your-client-id"
setx PLAID_SECRET "your-secret"
setx PLAID_ENV "sandbox"
```

#### Linux/macOS

```bash
export PLAID_CLIENT_ID="your-client-id"
export PLAID_SECRET="your-secret"
export PLAID_ENV="sandbox"
```

## Getting Plaid Credentials

1. Visit [Plaid Dashboard](https://dashboard.plaid.com/developers/integrations)
2. Sign up or log in to your Plaid account
3. Create a new application or select existing one
4. Copy the Client ID and Secret from the dashboard
5. Choose your environment:
   - **Sandbox**: For testing and development
   - **Development**: For integration testing
   - **Production**: For live applications

## Verification

After setup, restart your server and check the console output. You should see:

```
✅ Plaid service initialized with API credentials
```

Instead of the previous mock mode message.

## Testing the Integration

Run the Plaid service test:

```bash
node test_plaid_service.js
```

This will verify:

- Service configuration
- Link token creation (if credentials are set)
- Mock mode fallback

## API Endpoints

Once configured, the following endpoints are available:

- `POST /api/plaid/create-link-token` - Create account linking token
- `POST /api/plaid/exchange-public-token` - Exchange for access token
- `GET /api/plaid/accounts/:accessToken` - Get account information
- `GET /api/plaid/balances/:accessToken` - Get account balances
- `GET /api/plaid/transactions/:accessToken` - Get transactions
- `GET /api/plaid/income/:accessToken` - Get income data
- `POST /api/plaid/verify-ownership/:accessToken/:accountId` - Verify account ownership

## Security Notes

- Never commit credentials to version control
- Use environment variables for sensitive data
- Rotate credentials regularly
- Monitor API usage and costs

## Troubleshooting

If credentials aren't working:

1. Verify environment variables are set: `echo %PLAID_CLIENT_ID%`
2. Restart your terminal/IDE after setting variables
3. Check Plaid Dashboard for correct credential format
4. Ensure your Plaid application has the necessary permissions
5. Verify the environment setting matches your credentials

## Support

For Plaid API issues, contact Plaid support:

- Website: https://plaid.com
- Documentation: https://plaid.com/docs
- Support: https://support.plaid.com
- Dashboard: https://dashboard.plaid.com/developers/integrations
