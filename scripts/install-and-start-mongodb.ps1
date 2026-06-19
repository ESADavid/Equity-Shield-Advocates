# Complete MongoDB Installation and Startup
# OSCAR BROOME REVENUE - OWLBAN GROUP

Write-Host "MONGODB INSTALLATION AND STARTUP" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check if installer downloaded
$installerPath = "$env:TEMP\mongodb.msi"
if (Test-Path $installerPath) {
    Write-Host "MongoDB installer found" -ForegroundColor Green
    
    # Step 2: Install MongoDB
    Write-Host "Installing MongoDB (this takes 2-3 minutes)..." -ForegroundColor Yellow
    Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /qn /norestart ADDLOCAL=ServerService,Client SHOULD_INSTALL_COMPASS=0" -Wait -NoNewWindow
    Write-Host "MongoDB installed" -ForegroundColor Green
    
    # Step 3: Create data directory
    $dataDir = "C:\data\db"
    if (-not (Test-Path $dataDir)) {
        New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
    }
    Write-Host "Data directory ready: $dataDir" -ForegroundColor Green
    
    # Step 4: Start MongoDB service
    Write-Host "Starting MongoDB service..." -ForegroundColor Yellow
    Start-Service MongoDB -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    Write-Host "MongoDB started" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "SUCCESS - MongoDB is ready!" -ForegroundColor Green
    Write-Host "Connection: mongodb://localhost:27017" -ForegroundColor White
    Write-Host ""
    Write-Host "Next: Restart your server with 'npm start'" -ForegroundColor Cyan
    
} else {
    Write-Host "Waiting for MongoDB download to complete..." -ForegroundColor Yellow
    Write-Host "Download in progress at: $installerPath" -ForegroundColor Gray
}
