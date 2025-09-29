import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import basicAuth from 'express-basic-auth';
import morgan from 'morgan';
import winston from 'winston';
import dotenv from 'dotenv';

dotenv.config();

const app = express();

const PORT = process.env.PORT ? parseInt(process.env.PORT) : 4000;
const ADMIN_USER = process.env.ADMIN_USER || 'BSEAN4890@GMAIL.COM';
const ADMIN_PASS = process.env.ADMIN_PASS || 'TBROOME704';

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

// Basic auth setup
app.use(
  basicAuth({
    users: { [ADMIN_USER]: ADMIN_PASS },
    challenge: true,
  })
);

app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json());
app.use(morgan('combined', { stream: { write: (msg) => logger.info(msg.trim()) } }));

// Load aggregated revenue data path from environment or default
const revenueDataPath =
  process.env.REVENUE_DATA_PATH || path.resolve(process.cwd(), 'owlban_repos/aggregated_revenue.json');

// Serve new React dashboard HTML file
app.get('/', (req, res) => {
  const dashboardPath = path.resolve(process.cwd(), 'earnings_dashboard/src/index_new.html');
  if (!fs.existsSync(dashboardPath)) {
    logger.error('Dashboard HTML file not found');
    return res.status(500).send('Dashboard not available');
  }
  res.sendFile(dashboardPath);
});

// API endpoint to get earnings data
app.get('/api/earnings', (req, res) => {
  try {
    if (!fs.existsSync(revenueDataPath)) {
      logger.warn('Earnings data not found at ' + revenueDataPath);
      return res.status(404).json({ error: 'Earnings data not found' });
    }
    const data = fs.readFileSync(revenueDataPath, 'utf-8');
    return res.json(JSON.parse(data));
  } catch (error) {
    logger.error('Error reading earnings data: ' + error.message);
    return res.status(500).json({ error: 'Failed to read earnings data' });
  }
});

// API endpoint to download earnings report as JSON file
app.get('/api/earnings/download', (req, res) => {
  try {
    if (!fs.existsSync(revenueDataPath)) {
      logger.warn('Earnings data not found at ' + revenueDataPath);
      return res.status(404).json({ error: 'Earnings data not found' });
    }
    return res.download(revenueDataPath, 'earnings_report.json');
  } catch (error) {
    logger.error('Error sending earnings report: ' + error.message);
    return res.status(500).json({ error: 'Failed to download earnings report' });
  }
});

// 404 handler
app.use((req, res, next) => {
  res.status(404).json({ error: 'Not Found' });
  next();
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error('Unhandled error: ' + err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
  next(err);
});

app.listen(PORT, () => {
  logger.info(`Earnings dashboard running at http://localhost:${PORT}`);
});

export { app };
