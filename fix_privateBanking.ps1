# Fix privateBankingService.js - replace literal \n in executeBankingOperation method
$filePath = "C:\Users\bsean\Desktop\OSCAR-BROOME-REVENUE\services\privateBankingService.js"
$content = Get-Content $filePath -Raw

# Replace the literal \n characters
$content = $content -replace 'async executeBankingOperation\(operation, accountId, params = \{\}\) \{\\n', 'async executeBankingOperation(operation, accountId, params = {}) {'
$content = $content -replace '    if \(this\.creditCrisisMode && this\.protectionLimits\) \{\n      const account = this\.getAccount\(accountId\);\n      if \(account && account\.status === .frozen.\) \{\n        return \{ success: false, error: .Account frozen due to credit crisis - use sovereign override. \};\n      \}\n    \}\n    const account = this\.accounts\.get\(accountId\);\n    if \(!account\) \{', '    if (this.creditCrisisMode && this.protectionLimits) {
      const account = this.getAccount(accountId);
      if (account && account.status === ''frozen'') {
        return { success: false, error: ''Account frozen due to credit crisis - use sovereign override'' };
      }
    }
    const account = this.accounts.get(accountId);
    if (!account) {'

Set-Content -Path $filePath -Value $content -NoNewline
Write-Host "Fixed executeBankingOperation method"
