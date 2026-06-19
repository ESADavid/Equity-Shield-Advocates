Write-Host "Starting OSCAR BROOME REVENUE servers..." -ForegroundColor Green

# Start main backend (port 3000)
Write-Host "Starting main server (port 3000)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "npm start" -WorkingDirectory "c:/Users/bsean/OneDrive/Documents/GitHub/OSCAR-BROOME-REVENUE"

Start-Sleep 3

# Start earnings dashboard backend (port 4000)
Write-Host "Starting dashboard server (port 4000)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "node earnings_dashboard/server.js" -WorkingDirectory "c:/Users/bsean/OneDrive/Documents/GitHub/OSCAR-BROOME-REVENUE"

Start-Sleep 3

# Health check (PowerShell compatible)
Write-Host "Checking server health..." -ForegroundColor Yellow
try {
    $response3000 = Invoke-RestMethod -Uri "http://localhost:3000/health" -TimeoutSec 5
    Write-Host "✅ Main server (3000): $($response3000.status)" -ForegroundColor Green
} catch {
    Write-Host "❌ Main server (3000) not ready: $($_.Exception.Message)" -ForegroundColor Red
}

try {
    $response4000 = Invoke-RestMethod -Uri "http://localhost:4000/health" -TimeoutSec 5
    Write-Host "✅ Dashboard server (4000): $($response4000.status)" -ForegroundColor Green
} catch {
    Write-Host "❌ Dashboard server (4000) not ready: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n🌐 Access points:" -ForegroundColor Cyan
Write-Host "   Main API: http://localhost:3000/health" -ForegroundColor White
Write-Host "   Dashboard API: http://localhost:4000/api/earnings" -ForegroundColor White
Write-Host "   Frontend (Vite): http://localhost:5173 (cd earnings_dashboard && npm run dev)" -ForegroundColor White
Write-Host "`nServers started! Press Ctrl+C to stop checks." -ForegroundColor Green

# Keep checking every 10s
while ($true) {
    Start-Sleep 10
}

