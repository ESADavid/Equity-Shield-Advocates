import fetchAndSyncPayroll from './fetch_and_sync_payroll';
import updateRevenueData from './update_revenue_data';

import cron from 'node-cron';

export async function syncAllData(): Promise<void> {
  try {
    console.log('Starting full data synchronization...');
    await fetchAndSyncPayroll();
    await updateRevenueData();
    console.log('Full data synchronization completed successfully.');
  } catch (error) {
    console.error('Error during full data synchronization:', error);
  }
}

// Scheduled daily sync at 2:00 AM
cron.schedule('0 2 * * *', () => {
  console.log('Running scheduled daily data synchronization...');
  syncAllData();
});
