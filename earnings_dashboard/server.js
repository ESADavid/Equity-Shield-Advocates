// Convert server.js to ES module with import syntax

import express from 'express';
import cors from 'node:cors';
import fs from 'node:fs';
import path from 'node:path';
import expressBasicAuth from 'express-basic-auth';
import morgan from 'morgan';
import winston from 'winston';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import jpmorganAuthRoutes from '../routes/jpmorganAuthRoutes.js';
import payrollRouter from './payroll_router.js';
import biometricRoutes from '../routes/biometricRoutes.js';

dotenv.config();

const app = express();
export { app };

const PORT = process.env.PORT ? Number.parseInt(process.env.PORT) : 4000;
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

// Connect to MongoDB for biometric data
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/oscar-broome-revenue';
mongoose.connect(MONGODB_URI)
  .then(() => {
    logger.info('MongoDB connected successfully for biometric system');
  })
  .catch((error) => {
    logger.error('MongoDB connection error:', error);
  });

// Basic auth setup (fallback for legacy endpoints)
app.use(
  expressBasicAuth({
    users: { [ADMIN_USER]: ADMIN_PASS },
    challenge: true,
  })
);

app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json());
app.use(
  morgan('combined', { stream: { write: (msg) => logger.info(msg.trim()) } })
);

// Mount JPMorgan authentication routes
app.use('/api/auth', jpmorganAuthRoutes);

// Mount payroll routes
app.use('/api/payroll', payrollRouter);

// Mount biometric routes
app.use('/api/biometric', biometricRoutes);

// Load aggregated revenue data path from environment or default
const revenueDataPath =
  process.env.REVENUE_DATA_PATH ||
  path.resolve(
    path.dirname(new URL(import.meta.url).pathname),
    '../owlban_repos/aggregated_revenue.json'
  );

// Function to transform raw revenue data into earnings format
function getEarningsData() {
  try {
    if (!fs.existsSync(revenueDataPath)) {
      return null;
    }
    const data = JSON.parse(fs.readFileSync(revenueDataPath, 'utf-8'));
    return {
      totalAnnualRevenue: data.totalRevenue,
      totalDailyRevenue: data.totalRevenue / 365,
      revenueStreams: data.revenueStreams || {},
      purchases: data.purchases || {
        corporateHomes: 0,
        autoFleet: 0,
        autoFleetDetails: [],
      },
    };
  } catch (error) {
    // As per SonarLint, handle the error by logging it before returning null
    logger.error('Error reading earnings data:', error);
    return null;
  }
}

// Serve static dashboard HTML file
app.get('/', (_req, res) => {
  const dashboardPath = path.resolve(
    path.dirname(new URL(import.meta.url).pathname),
    'dashboard.html'
  );
  if (!fs.existsSync(dashboardPath)) {
    logger.error('Dashboard HTML file not found');
    res.status(500).send('Dashboard not available');
    return;
  }
  res.sendFile(dashboardPath);
});

// API endpoint to get earnings data
app.get('/api/earnings', (_req, res) => {
  const data = getEarningsData();
  if (!data) {
    logger.warn('Earnings data not found at ' + revenueDataPath);
    res.status(404).json({ error: 'Earnings data not found' });
    return;
  }
  res.json(data);
});

// API endpoint to download earnings report as JSON file
app.get('/api/earnings/download', (_req, res) => {
  const data = getEarningsData();
  if (!data) {
    logger.warn('Earnings data not found at ' + revenueDataPath);
    res.status(404).json({ error: 'Earnings data not found' });
    return;
  }
  res.setHeader('Content-Type', 'application/json');
  res.setHeader(
    'Content-Disposition',
    'attachment; filename="earnings_report.json"'
  );
  res.json(data);
});

// 404 handler
app.use((_req, res, _next) => {
  res.status(404).json({ error: 'Not Found' });
});

// Global error handler
app.use((_err, _req, res, _next) => {
  logger.error('Unhandled error: ' + _err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

const server = app.listen(PORT, () => {
  logger.info(`Earnings dashboard running at http://localhost:${PORT}`);
  logger.info('Biometric authentication system enabled at /api/biometric');
});

export { server };
