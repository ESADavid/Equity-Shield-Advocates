# Docker Build Script for Production
# This script builds the Docker image using the production Dockerfile
# Uses PowerShell-compatible syntax (semicolons instead of &&)

$ErrorActionPreference = "Stop"

Write-Host "Starting Docker build..." -ForegroundColor Cyan

# Change to project directory (using backslash for Windows paths)
Set-Location "c:\Users\bsean\OneDrive\Documents\GitHub\OSCAR-BROOME-REVENUE"

# Verify .env file exists and is UTF-8 encoded
if (Test-Path ".env") {
    $reader = [System.IO.File]::OpenRead(".env")
    $encoding = [System.Text.Encoding]::ASCII
    $bom = New-Object byte[] 4
    $bytesRead = $reader.Read($bom, 0, 4)
    $reader.Close()
    
    if ($bytesRead -ge 3 -and $bom[0] -eq 0xEF -and $bom[1] -eq 0xBB -and $bom[2] -eq 0xBF) {
        Write-Host ".env is UTF-8 with BOM" -ForegroundColor Green
    } elseif ($bytesRead -ge 2 -and $bom[0] -eq 0xFF -and $bom[1] -eq 0xFE) {
        Write-Host ".env is UTF-16 - Converting to UTF-8..." -ForegroundColor Yellow
        & ".\fix_env_encoding.ps1"
    } else {
        Write-Host ".env is UTF-8 without BOM" -ForegroundColor Green
    }
} else {
    Write-Host ".env file not found!" -ForegroundColor Red
    exit 1
}

# Run Docker build
Write-Host "Building Docker image..." -ForegroundColor Cyan
docker build -t test-env-fix -f Dockerfile.production . 2>&1 | Select-Object -First 30

if ($LASTEXITCODE -eq 0) {
    Write-Host "Docker build successful!" -ForegroundColor Green
} else {
    Write-Host "Docker build failed with exit code: $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}
