import { config } from 'dotenv';
import { syncAllData } from '../sync_jobs';

config(); // Load environment variables from .env file

async function runFullSync() {
  try {
    await syncAllData();
    console.log('Full data synchronization completed successfully.');
  } catch (error) {
    console.error('Error during full data synchronization:', error);
    process.exit(1);
  }
}

runFullSync();
