"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.app = void 0;
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const express_basic_auth_1 = __importDefault(require("express-basic-auth"));
const morgan_1 = __importDefault(require("morgan"));
const winston_1 = __importDefault(require("winston"));
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const app = (0, express_1.default)();
exports.app = app;
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 4000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'securepassword';
// Setup Winston logger
const logger = winston_1.default.createLogger({
    level: 'info',
    format: winston_1.default.format.combine(winston_1.default.format.timestamp(), winston_1.default.format.printf(({ timestamp, level, message }) => {
        return `${timestamp} [${level.toUpperCase()}]: ${message}`;
    })),
    transports: [
        new winston_1.default.transports.Console(),
        new winston_1.default.transports.File({ filename: 'error.log', level: 'error' }),
    ],
});
// Basic auth setup
app.use((0, express_basic_auth_1.default)({
    users: { [ADMIN_USER]: ADMIN_PASS },
    challenge: true,
}));
app.use((0, cors_1.default)({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express_1.default.json());
app.use((0, morgan_1.default)('combined', { stream: { write: (msg) => logger.info(msg.trim()) } }));
// Load aggregated revenue data path from environment or default
const revenueDataPath = process.env.REVENUE_DATA_PATH ||
    path_1.default.resolve(__dirname, '../owlban_repos/aggregated_revenue.json');
// Serve static dashboard HTML file
app.get('/', (req, res) => {
    const dashboardPath = path_1.default.resolve(__dirname, 'dashboard.html');
    if (!fs_1.default.existsSync(dashboardPath)) {
        logger.error('Dashboard HTML file not found');
        return res.status(500).send('Dashboard not available');
    }
    res.sendFile(dashboardPath);
});
// API endpoint to get earnings data
app.get('/api/earnings', (req, res) => {
    try {
        if (!fs_1.default.existsSync(revenueDataPath)) {
            logger.warn('Earnings data not found at ' + revenueDataPath);
            return res.status(404).json({ error: 'Earnings data not found' });
        }
        const data = fs_1.default.readFileSync(revenueDataPath, 'utf-8');
        return res.json(JSON.parse(data));
    }
    catch (error) {
        logger.error('Error reading earnings data: ' + error.message);
        return res.status(500).json({ error: 'Failed to read earnings data' });
    }
});
// API endpoint to download earnings report as JSON file
app.get('/api/earnings/download', (req, res) => {
    try {
        if (!fs_1.default.existsSync(revenueDataPath)) {
            logger.warn('Earnings data not found at ' + revenueDataPath);
            return res.status(404).json({ error: 'Earnings data not found' });
        }
        return res.download(revenueDataPath, 'earnings_report.json');
    }
    catch (error) {
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
