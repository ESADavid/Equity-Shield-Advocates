# Fix privateBankingService.js - Replace literal \n with real newlines
$filePath = "C:\Users\bsean\Desktop\OSCAR-BROOME-REVENUE\services\privateBankingService.js"
$content = Get-Content $filePath -Raw

# Replace the literal \n with actual newlines in executeBankingOperation
$content = $content -replace 'if \(this\.creditCrisisMode && this\.protectionLimits\) \{\\n', 'if (this.creditCrisisMode && this.protectionLimits) {'
$content = $content -replace 'const account = this\.getAccount\(accountId\);\\n', 'const account = this.getAccount(accountId);'
$content = $content -replace 'if \(account && account\.status === . frozen.\) \{\\n', 'if (account && account.status === ''frozen'') {'
$content = $content -replace 'return \{ success: false, error: . Account frozen due to credit crisis - use sovereign override. \};\\n', 'return { success: false, error: ''Account frozen due to credit crisis - use sovereign override'' };'
$content = $content -replace '\}\\n    \}', '}'
$content = $content -replace 'const account = this\.accounts\.get\(accountId\);\\n', 'const account = this.accounts.get(accountId);'

# Also fix the method signature if needed
$content = $content -replace 'async executeBankingOperation\(operation, accountId, params = \{\}\) \{\\n', 'async executeBankingOperation(operation, accountId, params = {}) {'

Set-Content -Path $filePath -Value $content -NoNewline
Write-Host "Fixed executeBankingOperation method"
