# Fix remaining syntax issues in privateBankingService.js

$filePath = "C:\Users\bsean\Desktop\OSCAR-BROOME-REVENUE\services\privateBankingService.js"
$content = Get-Content $filePath -Raw

Write-Host "Reading file..."

# Fix 1: Remove orphan code blocks before constructor (lines 34-52)
# This pattern matches the orphan JSDoc + code before constructor
$pattern1 = '(?s)/\*\*\n   \* Sovereign liquidity protection mode.*?logger\.info.*?Protection active.*?\;(\n  \})'
$content = $content -replace $pattern1, ''

# Fix 2: Remove orphan sovereignty override 
$pattern2 = '(?s)/\*\*\n   \* Sovereign override.*?logger\.info.*?FULL CONTROL RESTORED.*?\;'
$content = $content -replace $pattern2, ''

Write-Host "Removed orphan methods"

# Fix 3: Fix executeBankingOperation by replacing literal \n with actual newlines
$content = $content -replace '\(\) \{\n    if', '() {\n    if'
$content = $content -replace 'params = \{\}\) \{', 'params = {}) {'

Write-Host "Fixed executeBankingOperation"

# Also need to fix the other \n in executeBankingOperation body
$content = $content -replace '\{\n      const account = this\.getAccount', '{\n      const account = this.getAccount'
$content = $content -replace 'account\.status === ', 'account.status === '
$content = $content -replace '\{\n        return', '{\n        return'
$content = $content -replace ',\n      \}\n', ',n      }n'
$content = $content -replace '!account\) \{\n', '!account) {n'
$content = $content -replace 'return \{ success: false', 'return { success: false'
$content = $content -replace 'error: `Operation failed', 'error: `Operation failed'

# Fix 4: Fix all remaining literal \n in method signatures
$content = $content -replace 'async executeBankingOperation\(operation, accountId, params = \{\}\)', 'async executeBankingOperation(operation, accountId, params = {})'

Write-Host "Fixed method signatures"

Set-Content -Path $filePath -Value $content -NoNewline

Write-Host "Complete!"
