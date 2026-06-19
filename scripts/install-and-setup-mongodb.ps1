# MongoDB Installation and Setup Script for Windows
# OSCAR BROOME REVENUE SYSTEM

Write-Host "================================" -ForegroundColor Cyan
Write-Host "MongoDB Installation & Setup" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script requires Administrator privileges" -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator and try again" -ForegroundColor Yellow
    exit 1
}

# Step 1: Check if MongoDB is already installed
Write-Host "Step 1: Checking for existing MongoDB installation..." -ForegroundColor Yellow

$mongoPath = "C:\Program Files\MongoDB\Server"
$mongoInstalled = Test-Path $mongoPath

if ($mongoInstalled) {
    Write-Host "MongoDB is already installed at: $mongoPath" -ForegroundColor Green
    
    # Find the version directory
    $versionDirs = Get-ChildItem -Path $mongoPath -Directory | Sort-Object Name -Descending
    if ($versionDirs.Count -gt 0) {
        $latestVersion = $versionDirs[0].Name
        $mongodPath = Join-Path $mongoPath "$latestVersion\bin\mongod.exe"
        
        Write-Host "Found MongoDB version: $latestVersion" -ForegroundColor Green
    }
} else {
    Write-Host "MongoDB not found. Installing..." -ForegroundColor Yellow
    
    # Step 2: Download MongoDB
    Write-Host ""
    Write-Host "Step 2: Downloading MongoDB Community Server..." -ForegroundColor Yellow
    
    $mongoVersion = "7.0.5"
    $downloadUrl = "https://fastdl.mongodb.org/windows/mongodb-windows-x86_64-$mongoVersion-signed.msi"
    $installerPath = "$env:TEMP\mongodb-installer.msi"
    
    try {
        Write-Host "Downloading from: $downloadUrl" -ForegroundColor Cyan
        Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath -UseBasicParsing
        Write-Host "Download complete!" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Failed to download MongoDB" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        exit 1
    }
    
    # Step 3: Install MongoDB
    Write-Host ""
    Write-Host "Step 3: Installing MongoDB (this may take 2-3 minutes)..." -ForegroundColor Yellow
    
    try {
        $arguments = @(
            "/i"
            $installerPath
            "ADDLOCAL=`"ServerService,Client`""
            "SHOULD_INSTALL_COMPASS=0"
            "/qn"
            "/norestart"
        )
        
        Start-Process "msiexec.exe" -ArgumentList $arguments -Wait -NoNewWindow
        Write-Host "MongoDB installed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Failed to install MongoDB" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        exit 1
    }
    
    # Clean up installer
    Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
    
    # Set paths after installation
    $versionDirs = Get-ChildItem -Path $mongoPath -Directory | Sort-Object Name -Descending
    if ($versionDirs.Count -gt 0) {
        $latestVersion = $versionDirs[0].Name
        $mongodPath = Join-Path $mongoPath "$latestVersion\bin\mongod.exe"
    }
}

# Step 4: Create data directory
Write-Host ""
Write-Host "Step 4: Creating MongoDB data directory..." -ForegroundColor Yellow

$dataPath = "C:\data\db"
if (-not (Test-Path $dataPath)) {
    New-Item -ItemType Directory -Path $dataPath -Force | Out-Null
    Write-Host "Created data directory: $dataPath" -ForegroundColor Green
} else {
    Write-Host "Data directory already exists: $dataPath" -ForegroundColor Green
}

# Step 5: Check if MongoDB service is running
Write-Host ""
Write-Host "Step 5: Checking MongoDB service..." -ForegroundColor Yellow

$service = Get-Service -Name "MongoDB" -ErrorAction SilentlyContinue

if ($service) {
    if ($service.Status -eq "Running") {
        Write-Host "MongoDB service is already running" -ForegroundColor Green
    } else {
        Write-Host "Starting MongoDB service..." -ForegroundColor Yellow
        Start-Service -Name "MongoDB"
        Start-Sleep -Seconds 3
        Write-Host "MongoDB service started" -ForegroundColor Green
    }
} else {
    Write-Host "MongoDB service not found. Starting MongoDB manually..." -ForegroundColor Yellow
    
    # Start MongoDB as a background process
    $mongodPath = "C:\Program Files\MongoDB\Server\7.0\bin\mongod.exe"
    if (Test-Path $mongodPath) {
        Start-Process -FilePath $mongodPath -ArgumentList "--dbpath `"$dataPath`"" -WindowStyle Hidden
        Start-Sleep -Seconds 5
        Write-Host "MongoDB started manually" -ForegroundColor Green
    } else {
        Write-Host "ERROR: Could not find mongod.exe" -ForegroundColor Red
        exit 1
    }
}

# Step 6: Test connection
Write-Host ""
Write-Host "Step 6: Testing MongoDB connection..." -ForegroundColor Yellow

try {
    $testConnection = Test-NetConnection -ComputerName localhost -Port 27017 -WarningAction SilentlyContinue
    
    if ($testConnection.TcpTestSucceeded) {
        Write-Host "SUCCESS: MongoDB is running on port 27017" -ForegroundColor Green
    } else {
        Write-Host "WARNING: Could not connect to MongoDB on port 27017" -ForegroundColor Yellow
        Write-Host "MongoDB may still be starting up. Wait 10 seconds and try again." -ForegroundColor Yellow
    }
} catch {
    Write-Host "WARNING: Could not test connection" -ForegroundColor Yellow
}

# Step 7: Summary
Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Installation Complete!" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "MongoDB Status:" -ForegroundColor Cyan
Write-Host "  - Installation Path: C:\Program Files\MongoDB\Server" -ForegroundColor White
Write-Host "  - Data Path: $dataPath" -ForegroundColor White
Write-Host "  - Connection: mongodb://localhost:27017" -ForegroundColor White
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "  1. Close any running servers (Ctrl+C)" -ForegroundColor White
Write-Host "  2. Start your server: npm start" -ForegroundColor White
Write-Host "  3. Server should connect to MongoDB successfully" -ForegroundColor White
Write-Host ""
Write-Host "If MongoDB is not running, start it with:" -ForegroundColor Yellow
Write-Host "  Start-Service -Name MongoDB" -ForegroundColor White
Write-Host ""
