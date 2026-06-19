# Fix remaining syntax errors in privateBankingService.js

$filePath = "C:\Users\bsean\Desktop\OSCAR-BROOME-REVENUE\services\privateBankingService.js"
$content = Get-Content $filePath -Raw

Write-Host "Reading file..."

# Fix 1: Remove the orphan methods that appear before constructor (lines ~34-52)
# Find and remove the block with logger.warn before constructor
$pattern1 = '(?s)/\*\*\n   \* Sovereign liquidity protection mode.*?return this\.getPortfolioSummary\(\);\n  \}'
$content = $content -replace $pattern1, ''

Write-Host "Fixed orphan liquidity protection method"

# Fix 2: Remove the orphan Sovereign override that appears before constructor  
$pattern2 = '(?s)/\*\*\n   \* Sovereign override.*?logger\.info.*?FULL CONTROL RESTORED.*?\;'
$content = $content -replace $pattern2, ''

Write-Host "Fixed orphan sovereign override method"

# Fix 3: Fix constructor that has all properties on one line
$pattern3 = 'constructor\(\) \{    this\.accounts = new Map\(\);    this\.assets = new Map\(\);    this\.transactions = \[\];    this\.assetHistory = new Map\(\);    this\.portfolioAnalytics = new Map\(\);    this\.riskMetrics = new Map\(\);    this\.creditCrisisMode = false;    this\.protectionLimits = null;  \}'
$newConstructor = 'constructor() {
    this.accounts = new Map();
    this.assets = new Map();
    this.transactions = [];
    this.assetHistory = new Map();
    this.portfolioAnalytics = new Map();
    this.riskMetrics = new Map();
    this.creditCrisisMode = false;
    this.protectionLimits = null;
  }'
$content = $content -replace $pattern3, $newConstructor

Write-Host "Fixed constructor"

# Fix 4: Fix executeBankingOperation method
$pattern4 = 'async executeBankingOperation\(operation, accountId, params = \{\}\) \{\n    if \(this\.creditCrisisMode && this\.protectionLimits\) \{\n      const account = this\.getAccount\(accountId\);\n      if \(account && account\.status === .frozen.\) \{\n        return \{ success: false, error: .Account frozen.*?\}\n      \}\n    \}\n    const account = this\.accounts\.get\(accountId\);\n    if \(!\)'
$newMethod = 'async executeBankingOperation(operation, accountId, params = {}) {
    if (this.creditCrisisMode && this.protectionLimits) {
      const account = this.getAccount(accountId);
      if (account && account.status === "frozen") {
        return { success: false, error: "Account frozen due to credit crisis - use sovereign override" };
      }
    }
    const account = this.accounts.get(accountId);
    if (!account)'
$content = $content -replace $pattern4, $newMethod

Write-Host "Fixed executeBankingOperation method"

Set-Content -Path $filePath -Value $content -NoNewline

Write-Host "Complete!"
