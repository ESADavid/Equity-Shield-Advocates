# Fix .env encoding from UTF-16 to UTF-8
$envPath = ".env"
$backupPath = ".env.backup.utf16"
$newPath = ".env.new"

# Check if .env exists
if (Test-Path $envPath) {
    # Backup original
    Copy-Item $envPath $backupPath -Force
    Write-Host "Backed up original to $backupPath"
    
    # Read as UTF-16 and write as UTF-8
    $content = Get-Content -Path $envPath -Raw -Encoding Unicode
    Set-Content -Path $newPath -Value $content -Encoding UTF8
    Write-Host "Created new file with UTF-8 encoding"
    
    # Replace original
    Move-Item $newPath $envPath -Force
    Write-Host "Replaced .env with UTF-8 version"
    
    # Verify encoding
    $reader = [System.IO.File]::OpenRead($envPath)
    $encoding = [System.Text.Encoding]::ASCII
    $bom = New-Object byte[] 4
    $bytesRead = $reader.Read($bom, 0, 4)
    $reader.Close()
    
    if ($bytesRead -ge 3 -and $bom[0] -eq 0xEF -and $bom[1] -eq 0xBB -and $bom[2] -eq 0xBF) {
        Write-Host "VERIFIED: .env is now UTF-8 with BOM"
    } elseif ($bytesRead -ge 2 -and $bom[0] -eq 0xFF -and $bom[1] -eq 0xFE) {
        Write-Host "ERROR: .env is still UTF-16 LE"
    } else {
        Write-Host "VERIFIED: .env is now UTF-8 without BOM"
    }
} else {
    Write-Host "ERROR: .env file not found"
}
