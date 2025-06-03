# PowerShell script to set environment variables for Dynamics365 API

# Replace the placeholder values with your actual values
$env:DYNAMICS365_BASE_URL = "https://your-dynamics365-api-url"
$env:DYNAMICS365_ACCESS_TOKEN = "your-access-token"

Write-Host "Environment variables DYNAMICS365_BASE_URL and DYNAMICS365_ACCESS_TOKEN have been set for this session."

# To persist these variables, you can add them to your system environment variables or user environment variables.
# This script sets them only for the current PowerShell session.
