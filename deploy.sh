#!/bin/bash
# Deployment script for OWLban Earnings Dashboard using Docker and PM2 (Linux/macOS)

echo "Building Docker image..."
docker build -t owlban-earnings-dashboard .

# Stop and remove existing container if running
container=$(docker ps -q -f "name=owlban-earnings-dashboard")
if [ -n "$container" ]; then
  echo "Stopping existing Docker container..."
  docker stop owlban-earnings-dashboard
fi

container_exited=$(docker ps -aq -f "status=exited" -f "name=owlban-earnings-dashboard")
if [ -n "$container_exited" ]; then
  echo "Removing existing Docker container..."
  docker rm owlban-earnings-dashboard
fi

echo "Running Docker container..."
docker run -d -p 4000:4000 --name owlban-earnings-dashboard owlban-earnings-dashboard

echo "Installing npm dependencies..."
npm install --production

echo "Starting server with PM2..."
pm2 start ecosystem.config.js --env production

pm2 save
pm2 startup

echo "Deployment complete. Server should be running on port 4000."
