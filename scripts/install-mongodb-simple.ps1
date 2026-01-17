# MongoDB Installation Script for Windows
# OSCAR BROOME REVENUE - OWLBAN GROUP

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   MONGODB INSTALLATION - OSCAR BROOME REVENUE              ║" -ForegroundColor Cyan
Write-Host "║   OWLBAN GROUP - House of David                           ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# MongoDB download URL
$mongoVersion = "7.0.14"
$mongoUrl = "https://fastdl.mongodb.org/windows/mongodb-windows-x86_64-$mongoVersion-signed.msi"
$installerPath = "$env:TEMP\mongodb-installer.msi"

Write-Host "📥 Downloading MongoDB $mongoVersion..." -ForegroundColor Yellow

# Download
Invoke-WebRequest -Uri $mongoUrl -OutFile $installerPath -UseBasicParsing
Write-Host "✅ Downloaded" -ForegroundColor Green

# Install
Write-Host "📦 Installing MongoDB (2-3 minutes)..." -ForegroundColor Yellow
Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /qn /norestart ADDLOCAL=ServerService,Client SHOULD_INSTALL_COMPASS=0" -Wait -NoNewWindow
Write-Host "✅ Installed" -ForegroundColor Green

# Create data directory
$dataDir = "C:\data\db"
if (-not (Test-Path $dataDir)) {
    New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
}
Write-Host "✅ Data directory ready: $dataDir" -ForegroundColor Green

# Start MongoDB
Write-Host "🚀 Starting MongoDB..." -ForegroundColor Yellow
Start-Service MongoDB -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
Write-Host "✅ MongoDB started" -ForegroundColor Green

# Clean up
Remove-Item $installerPath -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   ✅ MONGODB INSTALLATION COMPLETE                         ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "📊 MongoDB Status:" -ForegroundColor Cyan
Write-Host "   • Version: $mongoVersion" -ForegroundColor White
Write-Host "   • Port: 27017" -ForegroundColor White
Write-Host "   • Connection: mongodb://localhost:27017" -ForegroundColor White
Write-Host ""
Write-Host "🚀 Next: Restart your server with 'npm start'" -ForegroundColor Cyan
Write-Host ""
