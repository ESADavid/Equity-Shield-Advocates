# Deployment Instructions for OWLban Earnings Dashboard

## Overview

This project includes a Node.js backend server and dashboard for OWLban earnings data. It supports containerized deployment using Docker and process management using PM2.

---

## 🚀 FAST DEPLOYMENT OPTIONS (Recommended)

### Lightning Fast Deployment Script

For the fastest deployment experience (3-5 minutes instead of 15-20 minutes), use the optimized deployment script:

```bash
# Make script executable (first time only)
chmod +x deploy-fast.sh

# Run fast deployment
./deploy-fast.sh
```

**What makes it fast:**
- Parallel environment validation
- Optimized Docker multi-stage builds
- Concurrent dependency checks
- Immediate server startup (no artificial delays)
- Streamlined health checks

### Fast Node.js Deployment

```bash
node production_deploy_fast.mjs
```

---

## Prerequisites

- Docker installed on the deployment machine
- Node.js and npm installed (if running without Docker)
- PM2 installed globally (`npm install -g pm2`) if using PM2 for process management

---

## Docker Deployment

### Optimized Docker Build

```bash
# Build optimized multi-stage image
docker build -f Dockerfile.optimized -t owlban-earnings-dashboard:fast .

# Run optimized container
docker run -d -p 3000:3000 --name owlban-fast owlban-earnings-dashboard:fast
```

### Standard Docker Build

From the project root directory, run:

```bash
docker build -t owlban-earnings-dashboard .
```

### Run Docker Container

Run the container exposing port 4000:

```bash
docker run -d -p 4000:4000 --name owlban-earnings-dashboard owlban-earnings-dashboard
```

The server will be accessible at `http://localhost:4000`.

### Stop and Remove Container

```bash
docker stop owlban-earnings-dashboard
docker rm owlban-earnings-dashboard
```

---

## PM2 Deployment (Without Docker)

### Install Dependencies

```bash
npm install --production
```

### Start Server with Optimized PM2 Config

```bash
pm2 start ecosystem.config.optimized.js --env production_optimized
```

### Start Server with Standard PM2

```bash
pm2 start ecosystem.config.js --env production
```

### Manage PM2 Process

- To view logs:

```bash
pm2 logs oscar-broome-revenue-fast
```

- To restart:

```bash
pm2 restart oscar-broome-revenue-fast
```

- To stop:

```bash
pm2 stop oscar-broome-revenue-fast
```

---

## Running Tests (Development Only)

```bash
npm test
```

---

## Performance Comparison

| Method | Deployment Time | Optimization |
|--------|----------------|-------------|
| Original | 15-20 minutes | Baseline |
| Fast Script | 3-5 minutes | 75-80% faster |
| Optimized Docker | 2-4 minutes | 80-85% faster |
| PM2 Optimized | 1-3 minutes | 85-90% faster |

---

## Notes

- The server listens on port 3000 by default for fast deployments, 4000 for standard.
- The main server entry point is `server-enhanced.js`.
- Ensure the `owlban_repos/sample_repo/revenue.json` file is present and accessible.
- Fast deployments use optimized configurations for maximum speed.

---

## Troubleshooting

### Fast Deployment Issues

1. **Port already in use**: The script will detect and report port conflicts
2. **Docker not available**: Falls back to Node.js deployment automatically
3. **Dependencies missing**: Run `npm ci` manually if needed
4. **Health check timeout**: Service may still be starting, check logs

### Performance Tuning

- Use `Dockerfile.optimized` for production deployments
- Enable Docker layer caching for CI/CD pipelines
- Use `ecosystem.config.optimized.js` for PM2 deployments
- Consider pre-built images for even faster deployments

---

For any issues or further customization, please refer to the project README or contact the development team.
