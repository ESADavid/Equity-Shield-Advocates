# Test API Matrix - PowerShell
# Execute curl test matrix for JPM API endpoints
# Run from project root: node scripts/test_api_matrix.ps1

$BASE_URL = "http://localhost:8080"
$TIMESTAMP = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$OUTPUT_FILE = "tests/curl_results_$TIMESTAMP.json"

# Test results array
$results = @()

function Test-Endpoint {
    param (
        [string]$Name,
        [string]$Method,
        [string]$Endpoint,
        [string]$Body = "",
        [hashtable]$Headers = @{},
        [int]$ExpectedStatus = 200
    )
    
    Write-Host "Testing: $Name" -ForegroundColor Cyan
    
    $params = @{
        Uri = "$BASE_URL$Endpoint"
        Method = $Method
        ContentType = "application/json"
    }
    
    if ($Body) {
        $params.Body = $Body
    }
    
    if ($Headers.Count -gt 0) {
        foreach ($key in $Headers.Keys) {
            $params.Headers[$key] = $Headers[$key]
        }
    }
    
try {
        $response = Invoke-RestMethod @params -ErrorAction Stop
        $statusCode = 200
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.Value__
        $response = $_.Exception.Message
    }
    
    $result = @{
        name = $Name
        method = $Method
        endpoint = $Endpoint
        expectedStatus = $ExpectedStatus
        actualStatus = $statusCode
        success = ($statusCode -eq $ExpectedStatus)
        response = $response
        timestamp = (Get-Date).ToString("o")
    }
    
    $results += $result
    
    if ($result.success) {
        Write-Host "  [PASS] Status: $statusCode" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Expected: $ExpectedStatus, Got: $statusCode" -ForegroundColor Red
    }
    
    return $result
}

Write-Host "========================================" -ForegroundColor Yellow
Write-Host "JPM API Test Matrix" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host ""

# Test 1: Health Endpoint (Happy Path)
Test-Endpoint -Name "Health Happy Path" -Method "GET" -Endpoint "/health" -ExpectedStatus 200

# Test 2: OAuth Token (Happy Path)
Test-Endpoint -Name "OAuth Token Happy Path" -Method "POST" -Endpoint "/api/oauth/token" -Body "{}" -ExpectedStatus 200

# Test 3: OAuth Invalid Credentials (Error Path)
Write-Host ""
Write-Host "OAuth Error Path Tests:" -ForegroundColor Yellow
# Note: These require valid JPM credentials to be configured
# Test with wrong env vars will fail - just verifying error handling

# Test 4: Banking Setup (Happy Path)
$bankingPayload = @{
    entityName = "Test Corp"
    ein = "12-3456789"
    authorizedSigners = @(
        @{ name = "John Doe"; title = "CEO" }
    )
    accounts = @(
        @{ type = "checking"; purpose = "operating" }
    )
} | ConvertTo-Json

Test-Endpoint -Name "Banking Setup Happy Path" -Method "POST" -Endpoint "/api/banking/setup" -Body $bankingPayload -ExpectedStatus 200

# Test 5: Banking Setup Missing Required Fields (Validation Error)
$invalidPayload = @{
    entityName = "Test Corp"
    # Missing ein, authorizedSigners, accounts
} | ConvertTo-Json

Test-Endpoint -Name "Banking Setup Validation Error" -Method "POST" -Endpoint "/api/banking/setup" -Body $invalidPayload -ExpectedStatus 400

# Test 6: Banking Setup Malformed EIN (Validation Error)
$malformedPayload = @{
    entityName = "Test Corp"
    ein = "invalid-ein"
    authorizedSigners = @(
        @{ name = "John Doe"; title = "CEO" }
    )
    accounts = @(
        @{ type = "checking"; purpose = "operating" }
    )
} | ConvertTo-Json

Test-Endpoint -Name "Banking Setup Malformed EIN" -Method "POST" -Endpoint "/api/banking/setup" -Body $malformedPayload -ExpectedStatus 400

# Test 7: Banking Setup Unauthorized (No Auth)
Test-Endpoint -Name "Banking Setup Unauthorized" -Method "POST" -Endpoint "/api/banking/setup" -Body $bankingPayload -ExpectedStatus 401

# Test 8: Protected Ping Endpoint (No Auth)
Test-Endpoint -Name "Protected Ping No Auth" -Method "GET" -Endpoint "/api/jpm/ping" -ExpectedStatus 401

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "Test Summary" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow

$passCount = ($results | Where-Object { $_.success }).Count
$failCount = ($results | Where-Object { -not $_.success }).Count

Write-Host "Total Tests: $($results.Count)" -ForegroundColor White
Write-Host "Passed: $passCount" -ForegroundColor Green
Write-Host "Failed: $failCount" -ForegroundColor Red

# Save results to file
$results | ConvertTo-Json -Depth 10 | Out-File $OUTPUT_FILE
Write-Host ""
Write-Host "Results saved to: $OUTPUT_FILE" -ForegroundColor Cyan
