"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const update_revenue_data_1 = __importDefault(require("../update_revenue_data"));
async function runUpdate() {
    try {
        const success = await (0, update_revenue_data_1.default)(false); // Pass false for incremental update
        if (success) {
            logger.info('Revenue data updated successfully.');
        }
        else {
            logger.error('Revenue data update failed.');
            process.exit(1);
        }
    }
    catch (error) {
        logger.error('Error during revenue update:', error);
        process.exit(1);
    }
}
runUpdate();
//# sourceMappingURL=run_update_revenue.js.map