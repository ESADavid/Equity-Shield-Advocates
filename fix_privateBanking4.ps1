# Fix privateBankingService.js - Comprehensive fix for all literal \n characters
$filePath = "C:\Users\bsean\Desktop\OSCAR-BROOME-REVENUE\services\privateBankingService.js"
$content = Get-Content $filePath -Raw

# Replace all literal \n with proper newlines in executeBankingOperation
# Pattern: {  const -> { backslash n backslash n const
$content = $content -replace 'if \(this\.creditCrisisMode && this\.protectionLimits\) \{      const', 'if (this.creditCrisisMode && this.protectionLimits) {`n      const'
$content = $content -replace 'account\.status === . frozen.  \{\\n        return', 'account.status === ''frozen'') {`n        return'

# Replace the remaining \n patterns
$content = $content -replace '  \{\\n        return \{ success: false, error: . Account frozen due to credit crisis - use sovereign override. \};\\n      \}', '  {`n        return { success: false, error: ''Account frozen due to credit crisis - use sovereign override'' };`n      }'
$content = $content -replace '  \}\\n    const account = this\.accounts\.get\(accountId\);    if', '  }`n    const account = this.accounts.get(accountId);`n    if'

# Also check for the specific pattern with \n that appears as literal in the file
# Read the file in binary mode to handle the exact characters
$bytes = [System.IO.File]::ReadAllBytes($filePath)
$text = [System.Text.Encoding]::UTF8.GetString($bytes)

# Replace the literal string "\n" (not the escape sequence) with newlines
$text = $text -replace '(?<= \{)  ', "`n      "
$text = $text -replace '(?<=if \(this\.creditCrisisMode && this\.protectionLimits\) \{)', "`n"
$text = $text -replace '(?<=\}\}  \})  ', "`n    "

# Let's do it differently - use a simpler replacement approach
# First read the raw content 
$rawContent = [System.IO.File]::ReadAllText($filePath)

# Find and replace the exact broken pattern
$brokenPattern = 'if (this.creditCrisisMode && this.protectionLimits) {      const account = this.getAccount(accountId);      if (account && account.status === ''frozen'') {\n        return { success: false, error: ''Account frozen due to credit crisis - use sovereign override'' };\n      }\n    const account = this.accounts.get(accountId);    if (!account) {'
$fixedPattern = 'if (this.creditCrisisMode && this.protectionLimits) {
      const account = this.getAccount(accountId);
      if (account && account.status === ''frozen'') {
        return { success: false, error: ''Account frozen due to credit crisis - use sovereign override'' };
      }
    }
    const account = this.accounts.get(accountId);
    if (!account) {'

$newContent = $rawContent -replace [regex]::Escape($brokenPattern), $fixedPattern

# If the above doesn't match, try a more direct approach
if ($newContent -eq $rawContent) {
    # Direct character replacement - find the method and fix inline
    $methodStart = $rawContent.IndexOf('async executeBankingOperation')
    if ($methodStart -gt 0) {
        $methodSection = $rawContent.Substring($methodStart, 800)
        
        # Replace specific broken sequences
        $methodSection = $methodSection -replace '\{      const', '{"`n      const'
        $methodSection = $methodSection -replace '  if \(account && account\.status === ', '`n      if (account && account.status === '
        $methodSection = $methodSection -replace 'return \{ success: false, error: . Account frozen.*?\);\\n      \}', 'return { success: false, error: ''Account frozen due to credit crisis - use sovereign override'' };`n      }'
        $methodSection = $methodSection -replace '\}\\n    const account', '}`n    const account'
        
        $newContent = $rawContent.Substring(0, $methodStart) + $methodSection + $rawContent.Substring($methodStart + 800)
    }
}

[System.IO.File]::WriteAllText($filePath, $newContent)
Write-Host "Fixed executeBankingOperation method - comprehensive fix applied"
