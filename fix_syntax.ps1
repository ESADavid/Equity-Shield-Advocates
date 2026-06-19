# Fix syntax errors in JavaScript files

$basePath = "C:\Users\bsean\Desktop\OSCAR-BROOME-REVENUE\services"

# Fix privateBankingService.js
$filePath = Join-Path $basePath "privateBankingService.js"
$content = Get-Content $filePath -Raw

Write-Host "Processing $filePath..."

# Fix constructor - remove literal \n sequences  
$content = $content -replace 'constructor\(\) \{\\n', 'constructor() {'
$content = $content -replace 'this\.accounts = new Map\(\);\\n', 'this.accounts = new Map();'
$content = $content -replace 'this\.assets = new Map\(\);\\n', 'this.assets = new Map();'
$content = $content -replace 'this\.transactions = \[\];\\n', 'this.transactions = [];'
$content = $content -replace 'this\.assetHistory = new Map\(\);\\n', 'this.assetHistory = new Map();'
$content = $content -replace 'this\.portfolioAnalytics = new Map\(\);\\n', 'this.portfolioAnalytics = new Map();'
$content = $content -replace 'this\.riskMetrics = new Map\(\);\\n', 'this.riskMetrics = new Map();'
$content = $content -replace 'this\.creditCrisisMode = false;\\n', 'this.creditCrisisMode = false;'
$content = $content -replace 'this\.protectionLimits = null;\\n', 'this.protectionLimits = null;'

# Fix broken method at line 34
$content = $content -replace '  /\*\*\n   \* Sovereign liquidity protection mode \(NO balance reduction\)\n   \*\/\n    logger\.warn', '  /**\n   * Activate liquidity protection mode\n   */\n  activateLiquidityProtection() {\n    logger.warn'

# Fix broken method at line 46
$content = $content -replace '  /\*\*\n   \* Sovereign override - Bypass all protections\n   \*\/\n    logger\.info', '  /**\n   * Activate sovereign override\n   */\n  activateSovereignOverride() {\n    logger.info'

# Fix executeBankingOperation 
$content = $content -replace 'async executeBankingOperation\(operation, accountId, params = \{\}\) \{\n    if \(this\.creditCrisisMode && this\.protectionLimits\)', 'async executeBankingOperation(operation, accountId, params = {}) {\n    if (this.creditCrisisMode && this.protectionLimits)'

Set-Content -Path $filePath -Value $content -NoNewline

Write-Host "Fixed $filePath"
