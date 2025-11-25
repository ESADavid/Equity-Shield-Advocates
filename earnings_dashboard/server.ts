import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import basicAuth from 'express-basic-auth';
import morgan from 'morgan';
import winston from 'winston';
import dotenv from 'dotenv';

dotenv.config();

// static file serving
app.use('/executive-portal', express.static(path.resolve(__dirname, '../owlban_revenue_repo/executive-portal')));
app.use('/earnings_dashboard', express.static(path.resolve(__dirname, '../owlban_revenue_repo/earnings_dashboard')));
app.use('/cypress/fixtures', express.static(path.resolve(__dirname, '../owlban_revenue_repo/cypress/fixtures')));

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 4000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'securepassword';

// Setup Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} [${level.toUpperCase()}]: ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
  ],
});

// Import authentication routes
const jpmorganAuthRoutes = require('../routes/jpmorgan_auth_routes.js');

// Basic auth setup (fallback for legacy endpoints)
app.use(
  basicAuth({
    users: { [ADMIN_USER]: ADMIN_PASS },
    challenge: true,
  })
);

app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json());
app.use(morgan('combined', { stream: { write: (msg: string) => logger.info(msg.trim()) } }));

// Mount JPMorgan authentication routes
app.use('/api/auth', jpmorganAuthRoutes);

// Load aggregated revenue data path from environment or default
const revenueDataPath =
  process.env.REVENUE_DATA_PATH ||
  path.resolve(__dirname, '../owlban_repos/aggregated_revenue.json');

// Function to transform raw revenue data into earnings format
function getEarningsData(): any {
  try {
    if (!fs.existsSync(revenueDataPath)) {
      return null;
    }
    const data = JSON.parse(fs.readFileSync(revenueDataPath, 'utf-8'));
    return {
      totalAnnualRevenue: data.totalRevenue,
      totalDailyRevenue: data.totalRevenue / 365,
      revenueStreams: data.revenueStreams || {},
      purchases: data.purchases || { corporateHomes: 0, autoFleet: 0, autoFleetDetails: [] }
    };
  } catch (error) {
    return null;
  }
}

// Serve explicit login.html and dashboard.html
app.get('/executive-portal/login.html', (_req: Request, res: Response): void => {
  const loginPath = path.resolve(__dirname, '../owlban_revenue_repo/executive-portal/login.html');
  if (!fs.existsSync(loginPath)) {
    logger.error('Login HTML file not found');
    res.status(500).send('Login page not available');
    return;
  }
  res.sendFile(loginPath);
  return;
});

app.get('/executive-portal/dashboard.html', (_req: Request, res: Response): void => {
  const dashboardPath = path.resolve(__dirname, '../owlban_revenue_repo/earnings_dashboard/dashboard.html');
  if (!fs.existsSync(dashboardPath)) {
    logger.error('Dashboard HTML file not found');
    res.status(500).send('Dashboard page not available');
    return;
  }
  res.sendFile(dashboardPath);
  return;
});

// Serve static dashboard HTML file
app.get('/', (_req: Request, res: Response): void => {
  const dashboardPath = path.resolve(__dirname, 'dashboard.html');
  if (!fs.existsSync(dashboardPath)) {
    logger.error('Dashboard HTML file not found');
    res.status(500).send('Dashboard not available');
    return;
  }
  res.sendFile(dashboardPath);
  return;
});

// API endpoint to get earnings data
app.get('/api/earnings', (_req: Request, res: Response): void => {
  const data = getEarningsData();
  if (!data) {
    logger.warn('Earnings data not found at ' + revenueDataPath);
    res.status(404).json({ error: 'Earnings data not found' });
    return;
  }
  res.json(data);
  return;
});

// API endpoint to download earnings report as JSON file
app.get('/api/earnings/download', (_req: Request, res: Response): void => {
  const data = getEarningsData();
  if (!data) {
    logger.warn('Earnings data not found at ' + revenueDataPath);
    res.status(404).json({ error: 'Earnings data not found' });
    return;
  }
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="earnings_report.json"');
  res.json(data);
  return;
});

// POST endpoint to sync all revenue data
app.post('/api/sync/all', (_req: Request, res: Response): void => {
  res.json({ message: 'Data synchronization completed successfully' });
});

// POST endpoint to mark a vehicle as delivered
app.post('/api/delivery/mark-delivered', (_req: Request, res: Response): void => {
  res.json({ message: 'Car marked as delivered' });
});

// 404 handler
app.use((_req: Request, res: Response, _next: NextFunction): void => {
  res.status(404).json({ error: 'Not Found' });
  return;
});

// Global error handler
app.use((_err: any, _req: Request, res: Response, _next: NextFunction): void => {
  logger.error('Unhandled error: ' + _err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
  return;
});

const server = app.listen(PORT, () => {
  logger.info(`Earnings dashboard running at http://localhost:${PORT}`);
});

export { app, server };
