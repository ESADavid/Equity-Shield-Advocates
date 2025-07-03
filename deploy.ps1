# Deployment script for OWLban Earnings Dashboard using Docker and PM2 (PowerShell)

Write-Host "Building Docker image..."
docker build -t owlban-earnings-dashboard .

# Stop and remove existing container if running
$container = docker ps -q -f "name=owlban-earnings-dashboard"
if ($container) {
    Write-Host "Stopping existing Docker container..."
    docker stop owlban-earnings-dashboard
}

$containerExited = docker ps -aq -f "status=exited" -f "name=owlban-earnings-dashboard"
if ($containerExited) {
    Write-Host "Removing existing Docker container..."
    docker rm owlban-earnings-dashboard
}

Write-Host "Running Docker container..."
docker run -d -p 4000:4000 --name owlban-earnings-dashboard owlban-earnings-dashboard

Write-Host "Installing npm dependencies..."
npm install --production

Write-Host "Starting server with PM2..."
pm2 start ecosystem.config.js --env production

pm2 save
pm2 startup

Write-Host "Deployment complete. Server should be running on port 4000."
