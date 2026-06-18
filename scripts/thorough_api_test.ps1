$ErrorActionPreference = 'Continue'

function Invoke-Test {
  param(
    [string]$Name,
    [string]$Method,
    [string]$Uri,
    [string]$ContentType = 'application/json',
    [string]$Body = $null
  )

  try {
    if ($null -ne $Body) {
      $resp = Invoke-WebRequest -Method $Method -Uri $Uri -ContentType $ContentType -Body $Body -UseBasicParsing
    } else {
      $resp = Invoke-WebRequest -Method $Method -Uri $Uri -UseBasicParsing
    }

    [PSCustomObject]@{
      test      = $Name
      status    = [int]$resp.StatusCode
      ok        = $true
      requestId = $resp.Headers['x-request-id']
      body      = $resp.Content
    }
  } catch {
    $status = $null
    $requestId = $null
    $bodyText = ''

    if ($_.Exception.Response) {
      try { $status = [int]$_.Exception.Response.StatusCode.value__ } catch { Write-Verbose "Failed to parse status code from response: $($_.Exception.Message)" }
      try { $requestId = $_.Exception.Response.Headers['x-request-id'] } catch { Write-Verbose "Failed to read x-request-id header: $($_.Exception.Message)" }
      try {
        $sr = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $bodyText = $sr.ReadToEnd()
        $sr.Close()
      } catch { Write-Verbose "Failed to read error response body stream: $($_.Exception.Message)" }
    }

    [PSCustomObject]@{
      test      = $Name
      status    = $status
      ok        = $false
      requestId = $requestId
      body      = $bodyText
    }
  }
}

$base = 'http://localhost:8080'

$familyValid  = Get-Content 'tests/family_trust_valid.json' -Raw
$equityValid  = Get-Content 'tests/equityshield_advocates_valid.json' -Raw
$businessValid = Get-Content 'tests/banking_setup_valid.json' -Raw
$equityInvalid = Get-Content 'tests/equityshield_advocates_invalid.json' -Raw

$familyInvalid = '{"trustName":"","trusteeSigners":[],"trustAccounts":[],"transferPolicy":{"requiresTrusteeApproval":false},"separationControls":{"noCommingling":false,"entityAccountsIndependent":false}}'
$malformed = '{bad-json}'
$missingRequired = '{"trusteeSigners":[{"fullName":"Only Signer","email":"only@example.com"}]}'
$wrongTypes = '{"trustName":123,"trusteeSigners":"bad","trustAccounts":{},"transferPolicy":[],"separationControls":"bad"}'

$results = @()
$results += Invoke-Test -Name 'family_trust_valid' -Method 'POST' -Uri "$base/api/banking/setup/family-trust" -Body $familyValid
$results += Invoke-Test -Name 'family_trust_invalid' -Method 'POST' -Uri "$base/api/banking/setup/family-trust" -Body $familyInvalid
$results += Invoke-Test -Name 'family_trust_malformed' -Method 'POST' -Uri "$base/api/banking/setup/family-trust" -Body $malformed
$results += Invoke-Test -Name 'family_trust_missing_required' -Method 'POST' -Uri "$base/api/banking/setup/family-trust" -Body $missingRequired
$results += Invoke-Test -Name 'family_trust_wrong_types' -Method 'POST' -Uri "$base/api/banking/setup/family-trust" -Body $wrongTypes

$results += Invoke-Test -Name 'equityshield_valid' -Method 'POST' -Uri "$base/api/banking/setup/equityshield-advocates" -Body $equityValid
$results += Invoke-Test -Name 'equityshield_invalid' -Method 'POST' -Uri "$base/api/banking/setup/equityshield-advocates" -Body $equityInvalid
$results += Invoke-Test -Name 'equityshield_malformed' -Method 'POST' -Uri "$base/api/banking/setup/equityshield-advocates" -Body $malformed

$results += Invoke-Test -Name 'business_valid' -Method 'POST' -Uri "$base/api/banking/setup/business" -Body $businessValid
$results += Invoke-Test -Name 'business_malformed' -Method 'POST' -Uri "$base/api/banking/setup/business" -Body $malformed

$results | ConvertTo-Json -Depth 6
