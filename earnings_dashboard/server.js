"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.server = exports.app = void 0;
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
// Import authentication routes
const jpmorganAuthRoutes = require('../routes/jpmorgan_auth_routes.js');
// Import payroll routes
const payrollRouter = require('./payroll_router.js');
// Basic auth setup (fallback for legacy endpoints)
app.use((0, express_basic_auth_1.default)({
    users: { [ADMIN_USER]: ADMIN_PASS },
    challenge: true,
}));
app.use((0, cors_1.default)({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express_1.default.json());
app.use((0, morgan_1.default)('combined', { stream: { write: (msg) => logger.info(msg.trim()) } }));
// Mount JPMorgan authentication routes
app.use('/api/auth', jpmorganAuthRoutes);
// Mount payroll routes
app.use('/api/payroll', payrollRouter);
// Load aggregated revenue data path from environment or default
const revenueDataPath = process.env.REVENUE_DATA_PATH ||
    path_1.default.resolve(__dirname, '../owlban_repos/aggregated_revenue.json');

// Function to transform raw revenue data into earnings format
function getEarningsData() {
    try {
        if (!fs_1.default.existsSync(revenueDataPath)) {
            return null;
        }
        const data = JSON.parse(fs_1.default.readFileSync(revenueDataPath, 'utf-8'));
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

// Serve static dashboard HTML file
app.get('/', (_req, res) => {
    const dashboardPath = path_1.default.resolve(__dirname, 'dashboard.html');
    if (!fs_1.default.existsSync(dashboardPath)) {
        logger.error('Dashboard HTML file not found');
        res.status(500).send('Dashboard not available');
        return;
    }
    res.sendFile(dashboardPath);
    return;
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
    return;
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
    res.setHeader('Content-Disposition', 'attachment; filename="earnings_report.json"');
    res.json(data);
    return;
});
// 404 handler
app.use((_req, res, _next) => {
    res.status(404).json({ error: 'Not Found' });
    return;
});
// Global error handler
app.use((_err, _req, res, _next) => {
    logger.error('Unhandled error: ' + _err.stack);
    res.status(500).json({ error: 'Internal Server Error' });
    return;
});
const server = app.listen(PORT, () => {
    logger.info(`Earnings dashboard running at http://localhost:${PORT}`);
});
exports.server = server;
//# sourceMappingURL=server.js.map