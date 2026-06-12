$BaseUrl = $env:BASE_URL
if (-not $BaseUrl) { $BaseUrl = "http://localhost:8080" }

$InternalApiKey = $env:INTERNAL_API_KEY
if (-not $InternalApiKey) { $InternalApiKey = "missing" }

Write-Host ("Using BASE_URL={0}" -f $BaseUrl)
Write-Host ("INTERNAL_API_KEY configured={0}" -f ([string]($InternalApiKey -ne "missing")))
Write-Host ""

function Invoke-GetWithHeaders {
  param(
    [Parameter(Mandatory = $true)][string]$Url,
    [hashtable]$Headers
  )

  try {
    $response = Invoke-WebRequest -Method GET -Uri $Url -Headers $Headers -ErrorAction Stop
    Write-Output ("HTTP/{0} {1}" -f $response.Version, [int]$response.StatusCode)
    Write-Output $response.Content
  } catch {
    if ($null -ne $_.Exception.Response) {
      $r = $_.Exception.Response
      $code = [int]$r.StatusCode
      Write-Output ("HTTP/1.1 {0}" -f $code)
      $reader = New-Object System.IO.StreamReader($r.GetResponseStream())
      $body = $reader.ReadToEnd()
      $reader.Close()
      Write-Output $body
    } else {
      Write-Output $_.Exception.Message
    }
  }
}

function Invoke-JsonPost {
  param(
    [Parameter(Mandatory = $true)][string]$Url,
    [Parameter(Mandatory = $true)]$Payload
  )

  $json = if ($Payload -is [string]) { $Payload } else { $Payload | ConvertTo-Json -Depth 20 -Compress }

  try {
    $response = Invoke-WebRequest -Method POST -Uri $Url -ContentType "application/json" -Body $json -ErrorAction Stop
    Write-Output ("HTTP/{0} {1}" -f $response.Version, [int]$response.StatusCode)
    Write-Output $response.Content
  } catch {
    if ($null -ne $_.Exception.Response) {
      $r = $_.Exception.Response
      $code = [int]$r.StatusCode
      Write-Output ("HTTP/1.1 {0}" -f $code)
      $reader = New-Object System.IO.StreamReader($r.GetResponseStream())
      $body = $reader.ReadToEnd()
      $reader.Close()
      Write-Output $body
    } else {
      Write-Output $_.Exception.Message
    }
  }
}

Write-Host "1) Health"
Invoke-GetWithHeaders -Url "$BaseUrl/health"
Write-Host ""

Write-Host "2) OAuth happy"
Invoke-JsonPost -Url "$BaseUrl/api/oauth/token" -Payload @{}
Write-Host ""

Write-Host "3) Banking malformed payload"
Invoke-JsonPost -Url "$BaseUrl/api/banking/setup" -Payload "{bad-json}"
Write-Host ""

Write-Host "4) Unauthorized ping"
Invoke-GetWithHeaders -Url "$BaseUrl/api/jpm/ping"
Write-Host ""

Write-Host "5) Authorized ping"
Invoke-GetWithHeaders -Url "$BaseUrl/api/jpm/ping" -Headers @{ "x-api-key" = $InternalApiKey }
Write-Host ""

Write-Host "6) AI NL query"
Invoke-JsonPost -Url "$BaseUrl/api/ai/nl-query" -Payload @{
  query = "show sector performance for technology"
}
Write-Host ""

Write-Host "7) AI Predict"
Invoke-JsonPost -Url "$BaseUrl/api/ai/predict" -Payload @{
  records = @(
    @{ value = 1 },
    @{ value = 2 },
    @{ value = 3 },
    @{ value = 4 }
  )
  valueKey = "value"
  horizon = 2
}
Write-Host ""

Write-Host "8) AI Full Analysis"
Invoke-JsonPost -Url "$BaseUrl/api/ai/analysis/full" -Payload @(
  @{
    company_name = "A"
    sector = "Technology"
    valuation = 1000000000
    return_pct = 10
    risk_score = 3
  },
  @{
    company_name = "B"
    sector = "Finance"
    valuation = 2000000000
    return_pct = 8
    risk_score = 5
  }
)
Write-Host ""

Write-Host "9) AI Report"
Invoke-JsonPost -Url "$BaseUrl/api/ai/report" -Payload @{
  analysis = @{
    metrics = @{
      total_companies = 2
    }
  }
  predictive = @{
    status = "ok"
  }
  risk = @{
    overall_risk = "medium"
  }
}
Write-Host ""
