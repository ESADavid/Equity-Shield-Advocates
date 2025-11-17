"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv_1 = require("dotenv");
const sync_jobs_1 = require("../sync_jobs");
(0, dotenv_1.config)(); // Load environment variables from .env file
async function runFullSync() {
    try {
        await (0, sync_jobs_1.syncAllData)();
        console.log('Full data synchronization completed successfully.');
    }
    catch (error) {
        console.error('Error during full data synchronization:', error);
        process.exit(1);
    }
}
runFullSync();
//# sourceMappingURL=run_full_sync.js.map