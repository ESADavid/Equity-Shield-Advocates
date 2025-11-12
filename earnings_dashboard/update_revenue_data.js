"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const revenueDataPath = path_1.default.resolve(__dirname, '../owlban_repos/sample_repo/revenue.json');
function validateNumber(value, fieldName) {
    if (typeof value !== 'number' || isNaN(value) || value < 0) {
        console.warn(`Invalid number for ${fieldName}, defaulting to 0.`);
        return 0;
    }
    return value;
}
/**
 * Flag to control whether to add sample purchase data.
 * Set to false in production to avoid adding hardcoded sample data.
 */
const ADD_SAMPLE_DATA = false;
function ensurePurchasesStructure(data) {
    if (!data.purchases) {
        data.purchases = {
            corporateHomes: 0,
            corporateHomesDetails: [],
            autoFleet: 0,
            autoFleetDetails: []
        };
    }
    else {
        if (!Array.isArray(data.purchases.autoFleetDetails)) {
            data.purchases.autoFleetDetails = [];
        }
        if (!Array.isArray(data.purchases.corporateHomesDetails)) {
            data.purchases.corporateHomesDetails = [];
        }
    }
}
function validatePurchases(data) {
    data.purchases.autoFleet = validateNumber(data.purchases.autoFleet, 'autoFleet');
    data.purchases.corporateHomes = validateNumber(data.purchases.corporateHomes, 'corporateHomes');
}
function addSampleData(data, incremental) {
    if (!incremental && ADD_SAMPLE_DATA) {
        if (data.purchases.autoFleetDetails.length === 0) {
            data.purchases.autoFleetDetails.push({
                model: 'Sample Model',
                vin: 'SAMPLEVIN123456789',
                dealership: 'Sample Dealership',
                cost: 50000,
                purchaseDate: new Date().toISOString()
            });
            data.purchases.autoFleet += 50000;
            data.totalRevenue -= 50000;
        }
        if (data.purchases.corporateHomesDetails.length === 0) {
            data.purchases.corporateHomesDetails.push({
                address: '123 Corporate Blvd',
                city: 'Metropolis',
                state: 'CA',
                cost: 250000,
                purchaseDate: new Date().toISOString()
            });
            data.purchases.corporateHomes += 250000;
            data.totalRevenue -= 250000;
        }
    }
}
function ensureRevenueStreamsDetails(data) {
    if (!data.revenueStreamsDetails) {
        data.revenueStreamsDetails = {};
    }
    if (!data.revenueStreams) {
        data.revenueStreams = {};
    }
}
function addTransactionDetails(data) {
    for (const streamName of Object.keys(data.revenueStreams)) {
        if (!Array.isArray(data.revenueStreamsDetails[streamName])) {
            data.revenueStreamsDetails[streamName] = [];
        }
        if (data.revenueStreamsDetails[streamName].length === 0) {
            data.revenueStreamsDetails[streamName].push({
                transactionId: `TXN-${Math.floor(Math.random() * 1000000)}`,
                amount: validateNumber(data.revenueStreams[streamName].amount, `revenueStreams.${streamName}.amount`),
                date: new Date().toISOString(),
                description: `Initial transaction for ${streamName}`
            });
        }
    }
}
function integratePayroll(data) {
    if (Array.isArray(data.payroll)) {
        let payrollTotal = 0;
        for (const payrollEntry of data.payroll) {
            if (typeof payrollEntry.amount === 'number' && !isNaN(payrollEntry.amount) && payrollEntry.amount >= 0) {
                payrollTotal += payrollEntry.amount;
            }
            else {
                console.warn('Invalid payroll entry amount detected, skipping:', payrollEntry);
            }
        }
        data.payrollTotal = payrollTotal;
        console.log(`Integrated payroll data total amount: ${payrollTotal}`);
    }
}
function addAuditTrail(data, incremental) {
    if (!Array.isArray(data.auditTrail)) {
        data.auditTrail = [];
    }
    data.auditTrail.push({
        timestamp: new Date().toISOString(),
        action: 'updateRevenueData',
        details: {
            totalRevenue: data.totalRevenue,
            purchases: {
                autoFleet: data.purchases.autoFleet,
                corporateHomes: data.purchases.corporateHomes
            },
            payrollTotal: data.payrollTotal || 0,
            incrementalUpdate: incremental
        }
    });
}
async function updateRevenueData(incremental = false, filePath) {
    const dataPath = filePath || revenueDataPath;
    await promises_1.default.access(dataPath);
    let data;
    const fileContent = await promises_1.default.readFile(dataPath, 'utf-8');
    data = JSON.parse(fileContent);
    ensurePurchasesStructure(data);
    validatePurchases(data);
    if (typeof data.totalRevenue !== 'number' || isNaN(data.totalRevenue)) {
        console.warn('Invalid or missing totalRevenue, defaulting to 0.');
        data.totalRevenue = 0;
    }
    addSampleData(data, incremental);
    ensureRevenueStreamsDetails(data);
    addTransactionDetails(data);
    integratePayroll(data);
    addAuditTrail(data, incremental);
    await promises_1.default.writeFile(dataPath, JSON.stringify(data, null, 2), 'utf-8');
    console.log('Revenue data updated with enhanced detailed purchase, revenue stream, payroll information, and audit trail.');
    return true;
}
exports.default = updateRevenueData;
//# sourceMappingURL=update_revenue_data.js.map