$ErrorActionPreference = "Stop"

Write-Host "Starting Equity Shield Advocates API in production mode..."

if (!(Test-Path ".env.production")) {
  Write-Error ".env.production not found. Create it from .env.production.example and set real secrets."
}

$env:NODE_ENV = "production"
Get-Content ".env.production" | ForEach-Object {
  if ($_ -match "^\s*#") { return }
  if ($_ -match "^\s*$") { return }
  $name, $value = $_ -split "=", 2
  if ($name -and $value) {
    [System.Environment]::SetEnvironmentVariable($name.Trim(), $value.Trim(), "Process")
  }
}

node src/server.js
