"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.syncAllData = syncAllData;
const fetch_and_sync_payroll_1 = __importDefault(require("./fetch_and_sync_payroll"));
const update_revenue_data_1 = __importDefault(require("./update_revenue_data"));
const node_cron_1 = __importDefault(require("node-cron"));
async function syncAllData() {
    try {
        console.log('Starting full data synchronization...');
        await (0, fetch_and_sync_payroll_1.default)();
        await (0, update_revenue_data_1.default)();
        console.log('Full data synchronization completed successfully.');
    }
    catch (error) {
        console.error('Error during full data synchronization:', error);
    }
}
// Scheduled daily sync at 2:00 AM
node_cron_1.default.schedule('0 2 * * *', () => {
    console.log('Running scheduled daily data synchronization...');
    syncAllData();
});
