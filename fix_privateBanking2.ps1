# Fix privateBankingService.js - add proper newlines in executeBankingOperation method
$filePath = "C:\Users\bsean\Desktop\OSCAR-BROOME-REVENUE\services\privateBankingService.js"
$content = Get-Content $filePath -Raw

# Fix the method - add newline after { by replacing the specific bad pattern
$badPattern = 'async executeBankingOperation(operation, accountId, params = {}) {    if'
$goodPattern = 'async executeBankingOperation(operation, accountId, params = {}) {' + [Environment]::NewLine + '    if'

$content = $content.Replace($badPattern, $goodPattern)

Set-Content -Path $filePath -Value $content -NoNewline
Write-Host "Added proper newlines to executeBankingOperation method"
