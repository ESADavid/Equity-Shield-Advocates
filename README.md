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

- Dockerfile is included for containerized deployment.
- Use `ecosystem.config.js` for PM2 process management.

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
