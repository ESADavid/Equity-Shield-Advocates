# PowerShell script to set Plaid credentials permanently on Windows

Write-Host "Setting up Plaid credentials for OSCAR BROOME REVENUE system..."
Write-Host ""

# Plaid API credentials
$plaidClientId = Read-Host "Enter Plaid Client ID"
$plaidSecret = Read-Host "Enter Plaid Secret" -AsSecureString
$plaidEnv = Read-Host "Enter Plaid Environment (sandbox/development/production) [default: sandbox]"

if ([string]::IsNullOrEmpty($plaidEnv)) {
    $plaidEnv = "sandbox"
}

# Convert secure string to plain text for environment variable
$plaidSecretPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($plaidSecret))

# Set environment variables permanently for the current user
[Environment]::SetEnvironmentVariable("PLAID_CLIENT_ID", $plaidClientId, "User")
[Environment]::SetEnvironmentVariable("PLAID_SECRET", $plaidSecretPlain, "User")
[Environment]::SetEnvironmentVariable("PLAID_ENV", $plaidEnv, "User")

Write-Host ""
Write-Host "✅ Plaid credentials have been set permanently for the current user."
Write-Host ""
Write-Host "Configured credentials:"
Write-Host "  PLAID_CLIENT_ID: $plaidClientId"
Write-Host "  PLAID_SECRET: [HIDDEN]"
Write-Host "  PLAID_ENV: $plaidEnv"
Write-Host ""
Write-Host "⚠️  Please restart your terminal or IDE to apply the changes."
Write-Host ""
Write-Host "After restarting, the Plaid integration will switch from mock mode to live Plaid API integration."
Write-Host ""
Write-Host "📋 Next Steps:"
Write-Host "1. Visit https://dashboard.plaid.com/developers/integrations to verify your account"
Write-Host "2. Test the integration with: node test_plaid_service.js"
Write-Host "3. Use the API endpoints at /api/plaid/*"
