# PowerShell script to set JPMorgan credentials permanently on Windows

Write-Host "Setting up JPMorgan credentials for OSCAR BROOME REVENUE system..."
Write-Host ""

# JPMorgan Payments API credentials
$jpmorganClientId = Read-Host "Enter JPMorgan Client ID"
$jpmorganClientSecret = Read-Host "Enter JPMorgan Client Secret" -AsSecureString
$jpmorganMerchantId = Read-Host "Enter JPMorgan Merchant ID"
$jpmorganTerminalId = Read-Host "Enter JPMorgan Terminal ID"

# Convert secure string to plain text for environment variable
$jpmorganClientSecretPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($jpmorganClientSecret))

# Set environment variables permanently for the current user
[Environment]::SetEnvironmentVariable("JPMORGAN_CLIENT_ID", $jpmorganClientId, "User")
[Environment]::SetEnvironmentVariable("JPMORGAN_CLIENT_SECRET", $jpmorganClientSecretPlain, "User")
[Environment]::SetEnvironmentVariable("JPMORGAN_MERCHANT_ID", $jpmorganMerchantId, "User")
[Environment]::SetEnvironmentVariable("JPMORGAN_TERMINAL_ID", $jpmorganTerminalId, "User")

# JPMorgan Treasury API credentials (optional)
$setupTreasury = Read-Host "Do you want to set up JPMorgan Treasury credentials? (y/n)"
if ($setupTreasury -eq 'y' -or $setupTreasury -eq 'Y') {
    $jpmorganOrgId = Read-Host "Enter JPMorgan Organization ID"
    $jpmorganProjectId = Read-Host "Enter JPMorgan Project ID"

    [Environment]::SetEnvironmentVariable("JPMORGAN_ORGANIZATION_ID", $jpmorganOrgId, "User")
    [Environment]::SetEnvironmentVariable("JPMORGAN_PROJECT_ID", $jpmorganProjectId, "User")

    Write-Host "Treasury credentials configured."
}

Write-Host ""
Write-Host "✅ JPMorgan credentials have been set permanently for the current user."
Write-Host ""
Write-Host "Configured credentials:"
Write-Host "  JPMORGAN_CLIENT_ID: $jpmorganClientId"
Write-Host "  JPMORGAN_CLIENT_SECRET: [HIDDEN]"
Write-Host "  JPMORGAN_MERCHANT_ID: $jpmorganMerchantId"
Write-Host "  JPMORGAN_TERMINAL_ID: $jpmorganTerminalId"
Write-Host ""
Write-Host "⚠️  Please restart your terminal or IDE to apply the changes."
Write-Host ""
Write-Host "After restarting, the wallet management system will switch from mock mode to live JPMorgan API integration."
