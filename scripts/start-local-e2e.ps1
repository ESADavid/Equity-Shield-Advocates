# OSCAR BROOME REVENUE - Local E2E Deployment
# Starts all services needed for local E2E testing

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   OSCAR BROOME REVENUE - LOCAL E2E DEPLOYMENT              ║" -ForegroundColor Cyan
Write-Host "║   OWLBAN GROUP - House of David                           ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if MongoDB is installed
Write-Host "🔍 Checking MongoDB..." -ForegroundColor Yellow
$mongoInstalled = Get-Command mongod -ErrorAction SilentlyContinue

if (-not $mongoInstalled) {
    Write-Host "❌ MongoDB not found. Installing MongoDB..." -ForegroundColor Red
    Write-Host "📥 Downloading MongoDB Community Server..." -ForegroundColor Yellow
    
    # Download MongoDB installer
    $mongoUrl = "https://fastdl.mongodb.org/windows/mongodb-windows-x86_64-7.0.4-signed.msi"
    $mongoInstaller = "$env:TEMP\mongodb-installer.msi"
    
    try {
        Invoke-WebRequest -Uri $mongoUrl -OutFile $mongoInstaller
        Write-Host "✅ MongoDB downloaded" -ForegroundColor Green
        
        Write-Host "📦 Installing MongoDB (this may take a few minutes)..." -ForegroundColor Yellow
        Start-Process msiexec.exe -ArgumentList "/i `"$mongoInstaller`" /qn /norestart" -Wait
        
        Write-Host "✅ MongoDB installed" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Could not auto-install MongoDB" -ForegroundColor Yellow
        Write-Host "Please install MongoDB manually from: https://www.mongodb.com/try/download/community" -ForegroundColor Yellow
        Write-Host "Then run this script again." -ForegroundColor Yellow
        exit 1
    }
}

# Start MongoDB
Write-Host "🚀 Starting MongoDB..." -ForegroundColor Yellow
$mongoProcess = Get-Process mongod -ErrorAction SilentlyContinue

if (-not $mongoProcess) {
    # Create data directory
    $dataDir = ".\data\db"
    if (-not (Test-Path $dataDir)) {
        New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
    }
    
    # Start MongoDB in background
    Start-Process mongod -ArgumentList "--dbpath `"$dataDir`" --port 27017" -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Write-Host "✅ MongoDB started on port 27017" -ForegroundColor Green
} else {
    Write-Host "✅ MongoDB already running" -ForegroundColor Green
}

# Check if Redis is needed
Write-Host "🔍 Checking Redis..." -ForegroundColor Yellow
$redisInstalled = Get-Command redis-server -ErrorAction SilentlyContinue

if ($redisInstalled) {
    $redisProcess = Get-Process redis-server -ErrorAction SilentlyContinue
    if (-not $redisProcess) {
        Write-Host "🚀 Starting Redis..." -ForegroundColor Yellow
        Start-Process redis-server -WindowStyle Hidden
        Start-Sleep -Seconds 2
        Write-Host "✅ Redis started" -ForegroundColor Green
    } else {
        Write-Host "✅ Redis already running" -ForegroundColor Green
    }
} else {
    Write-Host "⚠️  Redis not installed (optional)" -ForegroundColor Yellow
}

# Start the application
Write-Host ""
Write-Host "🚀 Starting OSCAR BROOME REVENUE Server..." -ForegroundColor Cyan
Write-Host ""

# Run npm start
npm start
