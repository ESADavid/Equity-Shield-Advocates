# OWLban Earnings Dashboard

## Overview

This project provides a backend server and frontend dashboard to display earnings data aggregated from various repositories. The server exposes REST API endpoints secured with basic authentication and serves a simple HTML dashboard.

## Features

- Secure API endpoints with basic authentication
- Fetch earnings data from a JSON file
- Download earnings data as JSON file
- Simple frontend dashboard displaying total and per-stream revenue

## Setup

### Prerequisites

- Node.js (v14 or higher recommended)
- npm package manager

### Installation

1. Clone the repository
2. Run `npm install` to install dependencies

### Running the Server

```bash
node earnings_dashboard/server_rebuilt.js
```

The server will start on port 4000.

### API Endpoints

- `GET /api/earnings` - Returns earnings data (requires basic auth)
- `GET /api/earnings/download` - Downloads earnings data as JSON file (requires basic auth)
- `GET /` - Serves the earnings dashboard HTML page (requires basic auth)

### Authentication

Use basic authentication with username `admin` and password `securepassword`.

## Testing

Run the Jest test suite with:

```bash
npx jest earnings_dashboard/server.test.js --runInBand --detectOpenHandles --verbose
```

## Deployment

This project can be deployed using Docker or PM2 process manager.

### Environment Variables

The following environment variables should be set in your production environment:

- `PORT` - Port number the server listens on (default: 4000)
- `ADMIN_USER` - Username for basic authentication (default: admin)
- `ADMIN_PASS` - Password for basic authentication (default: securepassword)
- `NODE_ENV` - Node environment (set to "production" in production)
- `DYNAMICS365_BASE_URL` - (Optional) Base URL for Dynamics365 integration
- `DYNAMICS365_ACCESS_TOKEN` - (Optional) Access token for Dynamics365 API
- `CORS_ORIGIN` - (Optional) Allowed origin for CORS

### Docker Deployment

1. Build the Docker image:

```bash
docker build -t owlban-earnings-dashboard .
```

1. Run the Docker container (example with environment variables):

```bash
docker run -d -p 4000:4000 \
  -e ADMIN_USER=yourusername \
  -e ADMIN_PASS=yourpassword \
  -e NODE_ENV=production \
  --name owlban-dashboard-container \
  owlban-earnings-dashboard
```

### PM2 Deployment

1. Install PM2 globally if not installed:

```bash
npm install -g pm2
```

1. Start the app with PM2 using the ecosystem config:

```bash
pm2 start ecosystem.config.js --env production
```

1. To monitor logs:

```bash
pm2 logs owlban-earnings-dashboard
```

1. To restart the app:

```bash
pm2 restart owlban-earnings-dashboard
```

### Pre-Deployment Testing

Run tests before deployment to ensure stability:

```bash
npm test
```

## Data

- Earnings data is read from `owlban_repos/sample_repo/revenue.json`.
- Replace this file with real data as needed.

## Future Improvements

- Enhance frontend UI with React or similar framework
- Add database integration for dynamic data
- Implement user management and role-based access control
- Add CI/CD pipeline for automated testing and deployment

## License

MIT License
