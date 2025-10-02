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
function validateEnvironmentVariables() {
    const baseUrl = process.env.DYNAMICS365_BASE_URL;
    const accessToken = process.env.DYNAMICS365_ACCESS_TOKEN;
    if (!baseUrl || !accessToken) {
        const errorMessage = 'Dynamics365 base URL or access token is not set in environment variables.';
        console.error(errorMessage);
        if (process.env.NODE_ENV === 'test') {
            throw new Error(errorMessage);
        } else {
            process.exit(1);
        }
    }
    return { baseUrl, accessToken };
}

function readExistingRevenueData() {
    let revenueData = {};
    try {
        const fileContent = fs_1.default.readFileSync(revenueDataPath, 'utf-8');
        revenueData = JSON.parse(fileContent);
    }
    catch (error) {
        console.warn('Failed to read existing revenue data, starting with empty object.');
    }
    return revenueData;
}

function isDuplicatePayrollEntry(revenueData, employeeId, currentDate) {
    return (revenueData.payroll || []).find((entry) => entry.employeeId === employeeId && entry.date === currentDate);
}

async function fetchPayrollForEmployee(payrollIntegration, employeeId, revenueData) {
    try {
        const response = await payrollIntegration.getEmployeePayroll(employeeId);
        if (response.success && response.data) {
            const currentDate = new Date().toISOString().split('T')[0];
            const existingEntry = isDuplicatePayrollEntry(revenueData, employeeId, currentDate);
            if (!existingEntry) {
                return {
                    employeeId,
                    amount: response.data.salary,
                    taxRate: response.data.taxRate,
                    deductions: response.data.deductions,
                    bonuses: response.data.bonuses,
                    date: new Date().toISOString(),
                };
            }
        }
        else {
            console.warn(`Payroll data for employee ${employeeId} could not be fetched and will be skipped.`);
        }
    }
    catch (error) {
        console.warn(`Payroll data for employee ${employeeId} could not be fetched and will be skipped.`);
    }
    return null;
}

function writeRevenueData(revenueData) {
    try {
        fs_1.default.writeFileSync(revenueDataPath, JSON.stringify(revenueData, null, 2), 'utf-8');
        console.log('Revenue data updated successfully with payroll data.');
    }
    catch (error) {
        console.error('Failed to write updated revenue data:', error);
        if (process.env.NODE_ENV !== 'test') {
            throw error; // Re-throw to let caller handle in non-test environments
        }
    }
}

async function fetchAndSyncPayroll() {
    const { baseUrl, accessToken } = validateEnvironmentVariables();

    // Fetch employee IDs dynamically
    const employeeIds = await (0, fetch_employee_ids_1.fetchEmployeeIds)();
    const payrollIntegration = new payroll_integration_1.default(baseUrl, accessToken);
    const payrollDataList = [];

    // Read existing revenue data to support incremental sync
    const revenueData = readExistingRevenueData();

    for (const employeeId of employeeIds) {
        const payrollData = await fetchPayrollForEmployee(payrollIntegration, employeeId, revenueData);
        if (payrollData) {
            payrollDataList.push(payrollData);
        }
    }

    if (payrollDataList.length === 0) {
        console.warn('No new payroll data was fetched. Revenue data will not be updated.');
        return;
    }

    // Append new payroll data to existing revenue data
    revenueData.payroll = (revenueData.payroll || []).concat(payrollDataList);

    // Write updated revenue data back to file
    writeRevenueData(revenueData);
}
exports.default = fetchAndSyncPayroll;
// Run the sync only if this module is the main module
if (require.main === module) {
    fetchAndSyncPayroll();
}
