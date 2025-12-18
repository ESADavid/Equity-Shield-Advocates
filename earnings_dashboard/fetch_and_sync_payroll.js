"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const fetch_employee_ids_1 = require("./fetch_employee_ids");
// Dynamic imports for JavaScript modules
let PayrollIntegration = null;
let QuickBooksPayrollIntegration = null;
async function loadPayrollIntegrations() {
    try {
        const payrollModule = await Promise.resolve().then(() => __importStar(require('../payroll_integration.js')));
        PayrollIntegration = payrollModule.default || payrollModule;
    }
    catch (error) {
        logger.warn('Failed to load PayrollIntegration:', error);
    }
    try {
        const qbModule = await Promise.resolve().then(() => __importStar(require('../quickbooks_payroll_integration.js')));
        QuickBooksPayrollIntegration = qbModule.default || qbModule;
    }
    catch (error) {
        logger.warn('Failed to load QuickBooksPayrollIntegration:', error);
    }
}
const revenueDataPath = path.resolve(__dirname, '../owlban_repos/sample_repo/revenue.json');
async function fetchAndSyncPayroll() {
    // Load payroll integrations dynamically
    await loadPayrollIntegrations();
    // Fetch employee IDs dynamically
    const employeeIds = await (0, fetch_employee_ids_1.fetchEmployeeIds)();
    const payrollDataList = [];
    // Read existing revenue data to support incremental sync
    let revenueData = {};
    try {
        const fileContent = fs.readFileSync(revenueDataPath, 'utf-8');
        revenueData = JSON.parse(fileContent);
    }
    catch (error) {
        logger.warn('Failed to read existing revenue data, starting with empty object.');
    }
    // Check for Dynamics 365 configuration
    const dynamicsBaseUrl = process.env.DYNAMICS365_BASE_URL;
    const dynamicsAccessToken = process.env.DYNAMICS365_ACCESS_TOKEN;
    let dynamicsIntegration = null;
    if (dynamicsBaseUrl && dynamicsAccessToken) {
        dynamicsIntegration = new PayrollIntegration(dynamicsBaseUrl, dynamicsAccessToken);
        logger.info('Dynamics 365 payroll integration configured.');
    }
    else {
        logger.warn('Dynamics 365 configuration not found, skipping Dynamics 365 payroll sync.');
    }
    // Check for QuickBooks configuration
    const qbBaseUrl = process.env.QUICKBOOKS_BASE_URL || 'https://quickbooks.api.intuit.com';
    const qbAccessToken = process.env.QUICKBOOKS_ACCESS_TOKEN;
    const qbCompanyId = process.env.QUICKBOOKS_COMPANY_ID;
    const qbClientId = process.env.QUICKBOOKS_CLIENT_ID;
    const qbClientSecret = process.env.QUICKBOOKS_CLIENT_SECRET;
    const qbRefreshToken = process.env.QUICKBOOKS_REFRESH_TOKEN;
    let quickbooksIntegration = null;
    if (qbAccessToken && qbCompanyId && qbClientId && qbClientSecret && qbRefreshToken) {
        quickbooksIntegration = new QuickBooksPayrollIntegration(qbBaseUrl, qbAccessToken, qbCompanyId, qbClientId, qbClientSecret, qbRefreshToken);
        logger.info('QuickBooks payroll integration configured.');
    }
    else {
        logger.warn('QuickBooks configuration not complete, skipping QuickBooks payroll sync.');
    }
    if (!dynamicsIntegration && !quickbooksIntegration) {
        logger.error('No payroll integrations configured. Please set environment variables for Dynamics 365 or QuickBooks.');
        process.exit(1);
    }
    for (const employee of employeeIds) {
        const employeeId = employee.id;
        // Try Dynamics 365 first
        if (dynamicsIntegration) {
            try {
                const response = await dynamicsIntegration.getEmployeePayroll(employeeId);
                if (response.success && response.data) {
                    const existingEntry = (revenueData.payroll || []).find((entry) => entry.employeeId === employeeId && entry.date === new Date().toISOString().split('T')[0] && entry.source === 'dynamics365');
                    if (!existingEntry) {
                        payrollDataList.push({
                            employeeId,
                            amount: response.data.salary,
                            taxRate: response.data.taxRate,
                            deductions: response.data.deductions,
                            bonuses: response.data.bonuses,
                            date: new Date().toISOString(),
                            source: 'dynamics365',
                        });
                    }
                }
            }
            catch (error) {
                logger.warn(`Dynamics 365 payroll data for employee ${employeeId} could not be fetched: ${error}`);
            }
        }
        // Try QuickBooks
        if (quickbooksIntegration) {
            try {
                const response = await quickbooksIntegration.getEmployeePayroll(employeeId);
                if (response.success && response.data) {
                    const existingEntry = (revenueData.payroll || []).find((entry) => entry.employeeId === employeeId && entry.date === new Date().toISOString().split('T')[0] && entry.source === 'quickbooks');
                    if (!existingEntry) {
                        payrollDataList.push({
                            employeeId,
                            amount: response.data.amount,
                            taxRate: response.data.taxRate,
                            deductions: response.data.deductions,
                            bonuses: response.data.bonuses,
                            date: new Date().toISOString(),
                            source: 'quickbooks',
                        });
                    }
                }
            }
            catch (error) {
                logger.warn(`QuickBooks payroll data for employee ${employeeId} could not be fetched: ${error}`);
            }
        }
    }
    if (payrollDataList.length === 0) {
        logger.warn('No new payroll data was fetched. Revenue data will not be updated.');
        return;
    }
    // Append new payroll data to existing revenue data
    revenueData.payroll = (revenueData.payroll || []).concat(payrollDataList);
    // Write updated revenue data back to file
    try {
        fs.writeFileSync(revenueDataPath, JSON.stringify(revenueData, null, 2), 'utf-8');
        logger.info('Revenue data updated successfully with payroll data.');
    }
    catch (error) {
        logger.error('Failed to write updated revenue data:', error);
    }
}
exports.default = fetchAndSyncPayroll;
// Run the sync only if this module is the main module
if (typeof require !== 'undefined' && require.main === module) {
    fetchAndSyncPayroll();
}
//# sourceMappingURL=fetch_and_sync_payroll.js.map