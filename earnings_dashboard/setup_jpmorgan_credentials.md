# JPMorgan Credentials Setup Guide

This guide will help you configure your JPMorgan API credentials for the OSCAR BROOME REVENUE system.

## Prerequisites

- JPMorgan Payments API access
- Client ID and Client Secret from JPMorgan
- Merchant ID and Terminal ID from your JPMorgan account

## Setup Instructions

### Option 1: Automated PowerShell Script (Recommended for Windows)

1. Open PowerShell as Administrator
2. Navigate to the earnings_dashboard directory:

   ```powershell
   cd C:\Users\bsean\OneDrive\Documents\GitHub\OSCAR-BROOME-REVENUE\earnings_dashboard
   ```

3. Run the setup script:

   ```powershell
   .\setup_jpmorgan_credentials.ps1
   ```

4. Enter your JPMorgan credentials when prompted
5. Restart your terminal/IDE

### Option 1.5: Node.js Test Credentials Setup

For development testing, you can use the Node.js script to set up test credentials:

1. Open a terminal in the earnings_dashboard directory
2. Run the test credentials setup:

   ```bash
   node test_credentials_setup.js
   ```

3. This will configure sample test credentials for development

### Option 2: Manual Environment Variable Setup

#### Windows (System Environment Variables)

1. Open Start menu and search for "Environment Variables"
2. Click "Edit the system environment variables"
3. Click "Environment Variables..." button
4. Under "User variables", click "New..." for each variable:

   **Required Variables:**
   - `JPMORGAN_CLIENT_ID` = Your JPMorgan Client ID
   - `JPMORGAN_CLIENT_SECRET` = Your JPMorgan Client Secret
   - `JPMORGAN_MERCHANT_ID` = Your JPMorgan Merchant ID
   - `JPMORGAN_TERMINAL_ID` = Your JPMorgan Terminal ID

   **Optional Variables (for Treasury features):**
   - `JPMORGAN_ORGANIZATION_ID` = Your JPMorgan Organization ID
   - `JPMORGAN_PROJECT_ID` = Your JPMorgan Project ID

5. Click OK and restart your terminal/IDE

#### Windows (Command Line)

```cmd
setx JPMORGAN_CLIENT_ID "your-client-id"
setx JPMORGAN_CLIENT_SECRET "your-client-secret"
setx JPMORGAN_MERCHANT_ID "your-merchant-id"
setx JPMORGAN_TERMINAL_ID "your-terminal-id"
```

#### Linux/macOS

```bash
export JPMORGAN_CLIENT_ID="your-client-id"
export JPMORGAN_CLIENT_SECRET="your-client-secret"
export JPMORGAN_MERCHANT_ID="your-merchant-id"
export JPMORGAN_TERMINAL_ID="your-terminal-id"
```

## Verification

After setup, restart your server and check the console output. You should see:

```
Environment check: {
  JPMORGAN_CLIENT_ID: true,
  JPMORGAN_CLIENT_SECRET: true,
  isMockMode: false
}
✅ JPMorgan payment system loaded successfully
```

Instead of the previous mock mode message.

## Security Notes

- Never commit credentials to version control
- Use environment variables for sensitive data
- Rotate credentials regularly
- Monitor API usage and costs

## Troubleshooting

If credentials aren't working:

1. Verify environment variables are set: `echo %JPMORGAN_CLIENT_ID%`
2. Restart your terminal/IDE after setting variables
3. Check JPMorgan API documentation for correct credential format
4. Ensure your JPMorgan account has the necessary permissions

## Support

For JPMorgan API issues, contact your JPMorgan representative or check the JPMorgan Developer Portal.
