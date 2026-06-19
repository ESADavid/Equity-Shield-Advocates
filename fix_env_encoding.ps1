# Fix .env encoding from UTF-16 to UTF-8
$content = Get-Content ".env" -Raw -Encoding UTF16
[System.IO.File]::WriteAllText(".env", $content, [System.Text.Encoding]::UTF8)
Write-Host "✅ Fixed .env encoding to UTF-8"
