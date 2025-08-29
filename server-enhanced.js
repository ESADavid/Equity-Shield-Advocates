/**
 * Enhanced Oscar Broome Revenue Server
 * Includes transaction override capabilities
 */

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const basicAuth = require('express-basic-auth');
const morgan = require('morgan');
const winston = require('winston');
const dotenv = require('dotenv');
const transactionOverrideRoutes = require('./routes/transactionOverrideRoutes');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 4000;

// Enhanced auth configuration for override operations
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'securepassword';
const OVERRIDE_MANAGER_USER = process.env.OVERRIDE_MANAGER_USER || 'override_manager';
const OVERRIDE_MANAGER_PASS = process.env.OVERRIDE_MANAGER_PASS || 'override123';

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
        new winston.transports.File({ filename: 'override.log', level: 'info' }),
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
    ],
});

// Enhanced auth setup with multiple roles
const authConfig = {
    users: {
        [ADMIN_USER]: ADMIN_PASS,
        [OVERRIDE_MANAGER_USER]: OVERRIDE_MANAGER_PASS,
        'super_admin': 'supersecure123'
    },
    challenge: true,
    realm: 'Oscar Broome Transaction Override System'
};

// Middleware setup
app.use(basicAuth(authConfig));
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json());
app.use(morgan('combined', { stream: { write: (msg) => logger.info(msg.trim()) } }));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));
app.use('/executive-portal', express.static(path.join(__dirname, 'executive-portal')));

// Load revenue data path
const revenueDataPath = process.env.REVENUE_DATA_PATH ||
    path.resolve(__dirname, 'earnings_report_updated.json');

// API Routes
app.use('/api/transactions', transactionOverrideRoutes);

// Serve override dashboard
app.get('/override-dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'override-dashboard.html'));
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

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        service: 'Oscar Broome Revenue with Override Capabilities'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
    logger.error('Unhandled error: ' + err.stack);
    res.status(500).json({ error: 'Internal Server Error' });
});

// Start server
app.listen(PORT, () => {
    logger.info(`Oscar Broome Revenue with Override Capabilities running at http://localhost:${PORT}`);
    logger.info(`Override Dashboard available at http://localhost:${PORT}/override-dashboard`);
});

module.exports = app;
