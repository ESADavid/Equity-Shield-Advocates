import * as fs from 'fs';
import * as path from 'path';
import { fetchEmployeeIds } from './fetch_employee_ids.js';

// Type definitions for payroll integrations
interface PayrollResponse {
  success: boolean;
  data?: any;
}

interface PayrollIntegration {
  getEmployeePayroll(_employeeId: string): Promise<PayrollResponse>;
}

interface QuickBooksPayrollIntegration {
  getEmployeePayroll(_employeeId: string): Promise<PayrollResponse>;
}

// Dynamic imports for JavaScript modules
let PayrollIntegration: any = null;
let QuickBooksPayrollIntegration: any = null;

async function loadPayrollIntegrations() {
  try {
    const payrollModule = await import('../payroll_integration.js');
    PayrollIntegration = payrollModule.default || payrollModule;
  } catch (error) {
    /* console.warn('Failed to load PayrollIntegration:', error); */
  }

  try {
    const qbModule = await import('../quickbooks_payroll_integration.js');
    QuickBooksPayrollIntegration = qbModule.default || qbModule;
  } catch (error) {
    /* console.warn('Failed to load QuickBooksPayrollIntegration:', error); */
  }
}

interface PayrollData {
  employeeId: string;
  amount: number;
  date: string;
  taxRate?: number;
  deductions?: number;
  bonuses?: number;
  source?: string; // 'dynamics365' or 'quickbooks'
}

const revenueDataPath = path.resolve(
  __dirname,
  '../owlban_repos/sample_repo/revenue.json'
);

async function fetchAndSyncPayroll(): Promise<void> {
  // Load payroll integrations dynamically
  await loadPayrollIntegrations();

  // Fetch employee IDs dynamically
  const employeeIds = await fetchEmployeeIds();

  const payrollDataList: PayrollData[] = [];

  // Read existing revenue data to support incremental sync
  let revenueData: any = {};
  try {
    const fileContent = fs.readFileSync(revenueDataPath, 'utf-8');
    revenueData = JSON.parse(fileContent);
  } catch (error) {
    /* console.warn(
      'Failed to read existing revenue data, starting with empty object.'
    ); */
  }

  // Check for Dynamics 365 configuration
  const dynamicsBaseUrl = process.env.DYNAMICS365_BASE_URL;
  const dynamicsAccessToken = process.env.DYNAMICS365_ACCESS_TOKEN;
  let dynamicsIntegration: PayrollIntegration | null = null;

  if (dynamicsBaseUrl && dynamicsAccessToken) {
    dynamicsIntegration = new PayrollIntegration(
      dynamicsBaseUrl,
      dynamicsAccessToken
    );
    /* console.log('Dynamics 365 payroll integration configured.'); */
  } else {
    /* console.warn(
      'Dynamics 365 configuration not found, skipping Dynamics 365 payroll sync.'
    ); */
  }

  // Check for QuickBooks configuration
  const qbBaseUrl =
    process.env.QUICKBOOKS_BASE_URL || 'https://quickbooks.api.intuit.com';
  const qbAccessToken = process.env.QUICKBOOKS_ACCESS_TOKEN;
  const qbCompanyId = process.env.QUICKBOOKS_COMPANY_ID;
  const qbClientId = process.env.QUICKBOOKS_CLIENT_ID;
  const qbClientSecret = process.env.QUICKBOOKS_CLIENT_SECRET;
  const qbRefreshToken = process.env.QUICKBOOKS_REFRESH_TOKEN;
  let quickbooksIntegration: QuickBooksPayrollIntegration | null = null;

  if (
    qbAccessToken &&
    qbCompanyId &&
    qbClientId &&
    qbClientSecret &&
    qbRefreshToken
  ) {
    quickbooksIntegration = new QuickBooksPayrollIntegration(
      qbBaseUrl,
      qbAccessToken,
      qbCompanyId,
      qbClientId,
      qbClientSecret,
      qbRefreshToken
    );
    /* console.log('QuickBooks payroll integration configured.'); */
  } else {
    /* console.warn(
      'QuickBooks configuration not complete, skipping QuickBooks payroll sync.'
    ); */
  }

  if (!dynamicsIntegration && !quickbooksIntegration) {
    /* console.error(
      'No payroll integrations configured. Please set environment variables for Dynamics 365 or QuickBooks.'
    ); */
    process.exit(1);
  }

  for (const employee of employeeIds) {
    const employeeId = employee.id;
    // Try Dynamics 365 first
    if (dynamicsIntegration) {
      try {
        const response =
          await dynamicsIntegration.getEmployeePayroll(employeeId);
        if (response.success && response.data) {
          const existingEntry = (revenueData.payroll || []).find(
            (entry: any) =>
              entry.employeeId === employeeId &&
              entry.date === new Date().toISOString().split('T')[0] &&
              entry.source === 'dynamics365'
          );
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
      } catch (error) {
        /* console.warn(
          `Dynamics 365 payroll data for employee ${employeeId} could not be fetched: ${error}`
        ); */
      }
    }

    // Try QuickBooks
    if (quickbooksIntegration) {
      try {
        const response =
          await quickbooksIntegration.getEmployeePayroll(employeeId);
        if (response.success && response.data) {
          const existingEntry = (revenueData.payroll || []).find(
            (entry: any) =>
              entry.employeeId === employeeId &&
              entry.date === new Date().toISOString().split('T')[0] &&
              entry.source === 'quickbooks'
          );
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
      } catch (error) {
        /* console.warn(
          `QuickBooks payroll data for employee ${employeeId} could not be fetched: ${error}`
        ); */
      }
    }
  }

  if (payrollDataList.length === 0) {
    /* console.warn(
      'No new payroll data was fetched. Revenue data will not be updated.'
    ); */
    return;
  }

  // Append new payroll data to existing revenue data
  revenueData.payroll = (revenueData.payroll || []).concat(payrollDataList);

  // Write updated revenue data back to file
  try {
    fs.writeFileSync(
      revenueDataPath,
      JSON.stringify(revenueData, null, 2),
      'utf-8'
    );
    /* console.log('Revenue data updated successfully with payroll data.'); */
  } catch (error) {
    /* console.error('Failed to write updated revenue data:', error); */
  }
}

export default fetchAndSyncPayroll;

// Run the sync only if this module is the main module
if (typeof require !== 'undefined' && require.main === module) {
  fetchAndSyncPayroll();
}
