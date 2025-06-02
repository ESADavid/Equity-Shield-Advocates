import PayrollIntegration from '../payroll_integration';
import fs from 'fs';
import path from 'path';

const revenueDataPath = path.resolve(__dirname, '../owlban_repos/sample_repo/revenue.json');

async function fetchAndSyncPayroll() {
  const baseUrl = process.env.DYNAMICS365_BASE_URL;
  const accessToken = process.env.DYNAMICS365_ACCESS_TOKEN;

  if (!baseUrl || !accessToken) {
    console.error('Dynamics365 base URL or access token is not set in environment variables.');
    process.exit(1);
  }

  const payrollIntegration = new PayrollIntegration(baseUrl, accessToken);

  // Example: Fetch payroll data for a list of employee IDs (this list should be replaced with real IDs)
  const employeeIds = ['emp1', 'emp2', 'emp3'];

  let revenueData = null;
  if (fs.existsSync(revenueDataPath)) {
    revenueData = JSON.parse(fs.readFileSync(revenueDataPath, 'utf-8'));
  } else {
    console.error('Revenue data file not found at', revenueDataPath);
    process.exit(1);
  }

  for (const employeeId of employeeIds) {
    try {
      const response = await payrollIntegration.getEmployeePayroll(employeeId);
      if (response.success && response.data) {
        // Process payroll data and update revenueData as needed
        console.log(`Payroll data for employee ${employeeId}:`, response.data);
        // Example: Add salary to totalRevenue (this logic should be adapted to real requirements)
        if (typeof response.data.salary === 'number') {
          revenueData.totalRevenue += response.data.salary;
        }
      } else {
        console.warn(`Failed to fetch payroll data for employee ${employeeId}:`, response.message);
      }
    } catch (error) {
      console.error(`Error fetching payroll data for employee ${employeeId}:`, error);
    }
  }

  // Write updated revenue data back to file
  fs.writeFileSync(revenueDataPath, JSON.stringify(revenueData, null, 2), 'utf-8');
  console.log('Revenue data updated with payroll information.');
}

fetchAndSyncPayroll().catch((error) => {
  console.error('Error in fetchAndSyncPayroll:', error);
  process.exit(1);
});
