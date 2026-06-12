$BaseUrl = $env:BASE_URL
if (-not $BaseUrl) { $BaseUrl = "http://localhost:8080" }

Write-Host "1) Health"
curl.exe -i "$BaseUrl/health"
Write-Host ""

Write-Host "2) OAuth happy"
curl.exe -i --location "$BaseUrl/api/oauth/token" `
  --header "Content-Type: application/json" `
  --data "{}"
Write-Host ""

Write-Host "3) Banking malformed payload"
curl.exe -i -X POST "$BaseUrl/api/banking/setup" `
  -H "Content-Type: application/json" `
  -d "{\"entityName\":123}"
Write-Host ""

Write-Host "4) Unauthorized ping"
curl.exe -i "$BaseUrl/api/jpm/ping"
Write-Host ""

Write-Host "5) Authorized ping"
$InternalApiKey = $env:INTERNAL_API_KEY
if (-not $InternalApiKey) { $InternalApiKey = "missing" }

curl.exe -i "$BaseUrl/api/jpm/ping" `
  -H "x-api-key: $InternalApiKey"
Write-Host ""
