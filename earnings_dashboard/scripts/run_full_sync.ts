import { config } from 'dotenv';
import { syncAllData } from '../sync_jobs.js';

config(); // Load environment variables from .env file

async function runFullSync() {
  try {
    await syncAllData();
    /* console.log('Full data synchronization completed successfully.'); */
  } catch (error) {
    /* console.error('Error during full data synchronization:', error); */
    // Only exit in non-test environments
    if (process.env.NODE_ENV !== 'test' && !process.env.JEST_WORKER_ID) {
      process.exit(1);
    }
    // In test environments, re-throw the error instead of exiting
    throw error;
  }
}

runFullSync();
