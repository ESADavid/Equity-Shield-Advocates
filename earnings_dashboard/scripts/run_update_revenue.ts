import updateRevenueData from '../update_revenue_data.js';

async function runUpdate() {
  try {
    const success = await updateRevenueData(false); // Pass false for incremental update
    if (success) {
      console.log('Revenue data updated successfully.');
    } else {
      console.error('Revenue data update failed.');
      // Only exit in non-test environments
      if (process.env.NODE_ENV !== 'test' && !process.env.JEST_WORKER_ID) {
        process.exit(1);
      }
      // In test environments, throw error instead of exiting
      throw new Error('Revenue data update failed');
    }
  } catch (error) {
    console.error('Error during revenue update:', error);
    // Only exit in non-test environments
    if (process.env.NODE_ENV !== 'test' && !process.env.JEST_WORKER_ID) {
      process.exit(1);
    }
    // In test environments, re-throw the error instead of exiting
    throw error;
  }
}

runUpdate();
