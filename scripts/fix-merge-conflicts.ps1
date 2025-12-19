# PowerShell script to fix merge conflicts by keeping HEAD version

$files = @(
    "earnings_dashboard/jpmorgan_payment.js",
    "earnings_dashboard/merchant_bill_pay.js",
    "services/assetManagementService.js"
)

foreach ($file in $files) {
    if (Test-Path $file) {
        Write-Host "Fixing merge conflicts in: $file"
        
        # Read the file content
        $content = Get-Content $file -Raw
        
        # Remove merge conflict markers and keep HEAD version
        # Pattern: <<<<<<< HEAD\n(content)\n=======\n(other content)\n>>>>>>> hash\n
        $pattern = '<<<<<<< HEAD\r?\n([\s\S]*?)\r?\n=======\r?\n[\s\S]*?\r?\n>>>>>>> [^\r\n]+\r?\n'
        $replacement = '$1' + "`n"
        
        $newContent = $content -replace $pattern, $replacement
        
        # Write back to file
        Set-Content -Path $file -Value $newContent -NoNewline
        
        Write-Host "Fixed: $file"
    } else {
        Write-Host "File not found: $file"
    }
}

Write-Host ""
Write-Host "Merge conflict resolution complete!"
Write-Host "Next step: Run npm run lint to verify fixes"
