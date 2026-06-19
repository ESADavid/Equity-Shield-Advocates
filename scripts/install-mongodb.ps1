# MongoDB Installation Script for Windows
# OSCAR BROOME REVENUE - OWLBAN GROUP

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   MONGODB INSTALLATION - OSCAR BROOME REVENUE              ║" -ForegroundColor Cyan
Write-Host "║   OWLBAN GROUP - House of David                           ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# MongoDB download URL (latest stable version)
$mongoVersion = "7.0.14"
$mongoUrl = "https://fastdl.mongodb.org/windows/mongodb-windows-x86_64-$mongoVersion-signed.msi"
$installerPath = "$env:TEMP\mongodb-installer.msi"

Write-Host "📥 Downloading MongoDB $mongoVersion..." -ForegroundColor Yellow
Write-Host "   URL: $mongoUrl" -ForegroundColor Gray

try {
    # Download MongoDB installer
    Invoke-WebRequest -Uri $mongoUrl -OutFile $installerPath -UseBasicParsing
    Write-Host "✅ MongoDB installer downloaded" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "📦 Installing MongoDB..." -ForegroundColor Yellow
    Write-Host "   This may take 2-3 minutes..." -ForegroundColor Gray
    
    # Install MongoDB silently
    $installArgs = @(
        "/i"
        "`"$installerPath`""
        "/qn"
        "/norestart"
        "ADDLOCAL=`"ServerService,Client`""
        "SHOULD_INSTALL_COMPASS=0"
    )
    
    Start-Process "msiexec.exe" -ArgumentList $installArgs -Wait -NoNewWindow
    
    Write-Host "✅ MongoDB installed successfully" -ForegroundColor Green
    
    # Create data directory
    Write-Host ""
    Write-Host "📁 Creating data directory..." -ForegroundColor Yellow
    $dataDir = "C:\data\db"
    if (-not (Test-Path $dataDir)) {
        New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
        Write-Host "✅ Data directory created: $dataDir" -ForegroundColor Green
    } else {
        Write-Host "✅ Data directory already exists: $dataDir" -ForegroundColor Green
    }
    
    # Start MongoDB service
    Write-Host ""
    Write-Host "🚀 Starting MongoDB service..." -ForegroundColor Yellow
    
    try {
        Start-Service MongoDB -ErrorAction Stop
        Write-Host "✅ MongoDB service started" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  MongoDB service not found, starting manually..." -ForegroundColor Yellow
        
        # Start MongoDB manually
        $mongoPath = "C:\Program Files\MongoDB\Server\$mongoVersion\bin\mongod.exe"
        if (Test-Path $mongoPath) {
            Start-Process $mongoPath -ArgumentList "--dbpath `"$dataDir`"" -WindowStyle Hidden
            Start-Sleep -Seconds 3
            Write-Host "✅ MongoDB started manually" -ForegroundColor Green
        } else {
            Write-Host "⚠️  MongoDB executable not found at expected location" -ForegroundColor Yellow
            Write-Host "   Expected: $mongoPath" -ForegroundColor Gray
        }
    }
    
    # Verify MongoDB is running
    Write-Host ""
    Write-Host "🔍 Verifying MongoDB connection..." -ForegroundColor Yellow
    
    Start-Sleep -Seconds 2
    
    $mongoClient = "C:\Program Files\MongoDB\Server\$mongoVersion\bin\mongosh.exe"
    if (Test-Path $mongoClient) {
        try {
            $testResult = & $mongoClient --eval 'db.version()' --quiet 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ MongoDB is running and accessible" -ForegroundColor Green
                Write-Host "   Version: $testResult" -ForegroundColor Gray
            }
        } catch {
            Write-Host "⚠️  Could not verify MongoDB connection" -ForegroundColor Yellow
        }
    } else {
        Write-Host "⚠️  MongoDB shell not found, but service may be running" -ForegroundColor Yellow
    }
    
    # Clean up installer
    Write-Host ""
    Write-Host "🧹 Cleaning up..." -ForegroundColor Yellow
    Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
    Write-Host "✅ Cleanup complete" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║   ✅ MONGODB INSTALLATION COMPLETE                         ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "📊 MongoDB Status:" -ForegroundColor Cyan
    Write-Host "   • Version: $mongoVersion" -ForegroundColor White
    Write-Host "   • Port: 27017" -ForegroundColor White
    Write-Host "   • Data Directory: $dataDir" -ForegroundColor White
    Write-Host "   • Connection String: mongodb://localhost:27017" -ForegroundColor White
    Write-Host ""
    Write-Host "🚀 Next Steps:" -ForegroundColor Cyan
    Write-Host "   1. Restart your server: npm start" -ForegroundColor White
    Write-Host "   2. Server will auto-connect to MongoDB" -ForegroundColor White
    Write-Host "   3. Access system at http://localhost:3000" -ForegroundColor White
    Write-Host ""
    
} catch {
    Write-Host ""
    Write-Host "❌ MongoDB installation failed" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "📝 Manual Installation Instructions:" -ForegroundColor Yellow
    Write-Host "   1. Download MongoDB from: https://www.mongodb.com/try/download/community" -ForegroundColor White
    Write-Host "   2. Run the installer" -ForegroundColor White
    Write-Host "   3. Choose 'Complete' installation" -ForegroundColor White
    Write-Host "   4. Install as a Windows Service" -ForegroundColor White
    Write-Host "   5. Restart your server: npm start" -ForegroundColor White
    Write-Host ""
    exit 1
}
