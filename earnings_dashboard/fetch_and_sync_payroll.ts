import axios from 'axios';
import fs from 'fs';
import path from 'path';

interface PayrollData {
  employeeId: string;
  amount: number;
  date: string;
}

const revenueDataPath = path.resolve(__dirname, '../owlban_repos/sample_repo/revenue.json');

async function fetchPayrollData(employeeId: string): Promise<PayrollData | null> {
  const baseUrl = process.env.DYNAMICS365_BASE_URL;
  const accessToken = process.env.DYNAMICS365_ACCESS_TOKEN;

  if (!baseUrl || !accessToken) {
    console.error('Dynamics365 base URL or access token is not set in environment variables. Please set DYNAMICS365_BASE_URL and DYNAMICS365_ACCESS_TOKEN.');
    process.exit(1);
  }

  try {
    const response = await axios.get(`${baseUrl}/payroll/${employeeId}`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });
    const data = response.data;
    return {
      employeeId,
      amount: data.amount,
      date: data.date,
    };
  } catch (error) {
    console.error(`Failed to fetch payroll data for employee ${employeeId}:`, error);
    return null;
  }
}

async function fetchAndSyncPayroll(): Promise<void> {
  // TODO: Replace with actual employee IDs or fetch dynamically
  const employeeIds = [
    'OSCAR BROOME',
    // Add more employee IDs here
  ];

  const payrollDataList: PayrollData[] = [];

  for (const employeeId of employeeIds) {
    const payrollData = await fetchPayrollData(employeeId);
    if (payrollData) {
      payrollDataList.push(payrollData);
    } else {
      console.warn(`Payroll data for employee ${employeeId} could not be fetched and will be skipped.`);
    }
  }

  if (payrollDataList.length === 0) {
    console.warn('No payroll data was fetched. Revenue data will not be updated.');
    return;
  }

  // Read existing revenue data
  let revenueData: any = {};
  try {
    const fileContent = fs.readFileSync(revenueDataPath, 'utf-8');
    revenueData = JSON.parse(fileContent);
  } catch (error) {
    console.warn('Failed to read existing revenue data, starting with empty object.');
  }

  // Update revenue data with payroll data
  revenueData.payroll = payrollDataList;

  // Write updated revenue data back to file
  try {
    fs.writeFileSync(revenueDataPath, JSON.stringify(revenueData, null, 2), 'utf-8');
    console.log('Revenue data updated successfully with payroll data.');
  } catch (error) {
    console.error('Failed to write updated revenue data:', error);
  }
}

export default fetchAndSyncPayroll;

// Run the sync only if this module is the main module
if (require.main === module) {
  fetchAndSyncPayroll();
}
