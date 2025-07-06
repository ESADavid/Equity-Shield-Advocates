# Deployment Instructions for OWLban Earnings Dashboard

## Overview

This project includes a Node.js backend server and dashboard for OWLban earnings data. It supports containerized deployment using Docker and process management using PM2.

---

## Prerequisites

- Docker installed on the deployment machine
- Node.js and npm installed (if running without Docker)
- PM2 installed globally (`npm install -g pm2`) if using PM2 for process management

---

## Docker Deployment

### Build Docker Image

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

### Start Server with PM2

```bash
pm2 start ecosystem.config.js --env production
```

### Manage PM2 Process

- To view logs:

```bash
pm2 logs owlban-earnings-dashboard
```

- To restart:

```bash
pm2 restart owlban-earnings-dashboard
```

- To stop:

```bash
pm2 stop owlban-earnings-dashboard
```

---

## Running Tests (Development Only)

```bash
npm test
```

---

## Notes

- The server listens on port 4000 by default.
- The main server entry point is `earnings_dashboard/server_rebuilt.js`.
- Ensure the `owlban_repos/sample_repo/revenue.json` file is present and accessible.

---

For any issues or further customization, please refer to the project README or contact the development team.
