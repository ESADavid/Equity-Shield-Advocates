# Integration Test Matrix Script
# Tests OAuth + Banking API endpoints

param(
    [string]$BaseUrl = "http://localhost:3000",
    [switch]$Health,
    [switch]$OAuth,
    [switch]$Banking,
    [switch]$All
)

$ErrorActionPreference = "Stop"

# Colors for output
function Write-Test-Result {
    param([string]$Name, [bool]$Success, [string]$Message)
    if ($Success) {
        Write-Host "✅ PASS" -ForegroundColor Green -NoNewline
        Write-Host " | $Name - $Message"
    } else {
        Write-Host "❌ FAIL" -ForegroundColor Red -NoNewline
        Write-Host " | $Name - $Message"
    }
}

# Test Health Endpoint
function Test-Health {
    Write-Host "`n--- Health Check ---" -ForegroundColor Cyan
    
    try {
        $response = Invoke-RestMethod -Uri "$BaseUrl/health" -Method GET -TimeoutSec 10
        Write-Test-Result "GET /health" $true "Status: $($response.status)"
        return @{ success = $true; data = $response }
    }
    catch {
        Write-Test-Result "GET /health" $false $_.Exception.Message
        return @{ success = $false; error = $_.Exception.Message }
    }
}

# Test OAuth Token Endpoint
function Test-OAuth-Token {
    Write-Host "`n--- OAuth Token ---" -ForegroundColor Cyan
    
    # Note: This will fail without valid credentials but tests the endpoint
    try {
        $body = @{
            client_id = "test-client"
            client_secret = "test-secret"
            grant_type = "client_credentials"
            scope = "payments"
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$BaseUrl/api/oauth/token" `
            -Method POST `
            -Body $body `
            -ContentType "application/json" `
            -TimeoutSec 10
        
        Write-Test-Result "POST /api/oauth/token" $true "Token received"
        return @{ success = $true; data = $response }
    }
    catch {
        # Even if it returns 400, endpoint exists
        if ($_.Exception.Response.StatusCode -eq 400) {
            Write-Test-Result "POST /api/oauth/token" $true "Endpoint responding (auth required)"
            return @{ success = $true; error = "auth_required" }
        }
        Write-Test-Result "POST /api/oauth/token" $false $_.Exception.Message
        return @{ success = $false; error = $_.Exception.Message }
    }
}

# Test Banking Setup Endpoint (requires auth - will show endpoint exists)
function Test-Banking-Setup {
    Write-Host "`n--- Banking Setup ---" -ForegroundColor Cyan
    
    $samplePayload = @{
        entityName = "TEST_ENTITY"
        ein = "12-3456789"
        authorizedSigners = @(
            @{ name = "Test Signer"; title = "CEO" }
        )
        accounts = @(
            @{ type = "checking"; purpose = "operating" }
        )
    } | ConvertTo-Json
    
    try {
        # This will fail with 401 but proves endpoint exists
        $response = Invoke-RestMethod -Uri "$BaseUrl/api/banking/setup" `
            -Method POST `
            -Body $samplePayload `
            -ContentType "application/json" `
            -TimeoutSec 10
        
        Write-Test-Result "POST /api/banking/setup" $true "Setup accepted"
        return @{ success = $true; data = $response }
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 401) {
            Write-Test-Result "POST /api/banking/setup" $true "Endpoint protected (auth required)"
            return @{ success = $true; error = "auth_required" }
        }
        if ($_.Exception.Response.StatusCode -eq 400) {
            Write-Test-Result "POST /api/banking/setup" $true "Endpoint responding (validation)"
            return @{ success = $true; error = "validation" }
        }
        Write-Test-Result "POST /api/banking/setup" $false $_.Exception.Message
        return @{ success = $false; error = $_.Exception.Message }
    }
}

# Test JPM Ping (unauthenticated)
function Test-JPM-Ping {
    Write-Host "`n--- JPM Ping ---" -ForegroundColor Cyan
    
    try {
        $response = Invoke-RestMethod -Uri "$BaseUrl/api/jpm/ping" -Method GET -TimeoutSec 10
        Write-Test-Result "GET /api/jpm/ping" $true "Pong: $($response.ok)"
        return @{ success = $true; data = $response }
    }
    catch {
        Write-Test-Result "GET /api/jpm/ping" $false $_.Exception.Message
        return @{ success = $false; error = $_.Exception.Message }
    }
}

# Run All Tests
function Test-All-Endpoints {
    Write-Host "`n======================================" -ForegroundColor Yellow
    Write-Host "Integration API Test Matrix" -ForegroundColor Yellow
    Write-Host "Base URL: $BaseUrl" -ForegroundColor Yellow
    Write-Host "======================================" -ForegroundColor Yellow
    
    $results = @{
        health = Test-Health
        oauth = Test-OAuth-Token
        banking = Test-Banking-Setup
        jpmPing = Test-JPM-Ping
    }
    
    Write-Host "`n======================================" -ForegroundColor Yellow
    Write-Host "Summary" -ForegroundColor Yellow
    Write-Host "======================================" -ForegroundColor Yellow
    
    $passed = ($results.Values | Where-Object { $_.success }).Count
    $total = $results.Count
    
    Write-Host "Passed: $passed / $total" -ForegroundColor $(if ($passed -eq $total) { "Green" } else { "Yellow" })
    
    return $results
}

# Main execution
if ($All -or (-not $Health -and -not $OAuth -and -not $Banking)) {
    $results = Test-All-Endpoints
}
else {
    if ($Health) { Test-Health }
    if ($OAuth) { Test-OAuth-Token }
    if ($Banking) { Test-Banking-Setup }
}

Write-Host ""
