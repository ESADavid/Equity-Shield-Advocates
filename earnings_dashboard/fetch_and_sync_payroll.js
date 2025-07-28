"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const payroll_integration_1 = __importDefault(require("../payroll_integration"));
const fetch_employee_ids_1 = require("./fetch_employee_ids");
const revenueDataPath = path_1.default.resolve(__dirname, '../owlban_repos/sample_repo/revenue.json');
async function fetchAndSyncPayroll() {
    const baseUrl = process.env.DYNAMICS365_BASE_URL;
    const accessToken = process.env.DYNAMICS365_ACCESS_TOKEN;
    if (!baseUrl || !accessToken) {
        console.error('Dynamics365 base URL or access token is not set in environment variables.');
        process.exit(1);
    }
    // Fetch employee IDs dynamically
    const employeeIds = await (0, fetch_employee_ids_1.fetchEmployeeIds)();
    const payrollIntegration = new payroll_integration_1.default(baseUrl, accessToken);
    const payrollDataList = [];
    // Read existing revenue data to support incremental sync
    let revenueData = {};
    try {
        const fileContent = fs_1.default.readFileSync(revenueDataPath, 'utf-8');
        revenueData = JSON.parse(fileContent);
    }
    catch (error) {
        console.warn('Failed to read existing revenue data, starting with empty object.');
    }
    for (const employeeId of employeeIds) {
        try {
            const response = await payrollIntegration.getEmployeePayroll(employeeId);
            if (response.success && response.data) {
                // Check if payroll data for this employee and date already exists to avoid duplicates
                const existingEntry = (revenueData.payroll || []).find((entry) => entry.employeeId === employeeId && entry.date === new Date().toISOString().split('T')[0]);
                if (!existingEntry) {
                    payrollDataList.push({
                        employeeId,
                        amount: response.data.salary,
                        taxRate: response.data.taxRate,
                        deductions: response.data.deductions,
                        bonuses: response.data.bonuses,
                        date: new Date().toISOString(),
                    });
                }
            }
            else {
                console.warn(`Payroll data for employee ${employeeId} could not be fetched and will be skipped.`);
            }
        }
        catch (error) {
            console.warn(`Payroll data for employee ${employeeId} could not be fetched and will be skipped.`);
        }
    }
    if (payrollDataList.length === 0) {
        console.warn('No new payroll data was fetched. Revenue data will not be updated.');
        return;
    }
    // Append new payroll data to existing revenue data
    revenueData.payroll = (revenueData.payroll || []).concat(payrollDataList);
    // Write updated revenue data back to file
    try {
        fs_1.default.writeFileSync(revenueDataPath, JSON.stringify(revenueData, null, 2), 'utf-8');
        console.log('Revenue data updated successfully with payroll data.');
    }
    catch (error) {
        console.error('Failed to write updated revenue data:', error);
    }
}
exports.default = fetchAndSyncPayroll;
// Run the sync only if this module is the main module
if (require.main === module) {
    fetchAndSyncPayroll();
}
