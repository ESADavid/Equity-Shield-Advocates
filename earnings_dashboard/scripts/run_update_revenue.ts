import updateRevenueData from '../update_revenue_data.js';

async function runUpdate() {
  try {
    const success = await updateRevenueData(false); // Pass false for incremental update
    if (success) {
      console.log('Revenue data updated successfully.');
    } else {
      console.error('Revenue data update failed.');
      process.exit(1);
    }
  } catch (error) {
    console.error('Error during revenue update:', error);
    process.exit(1);
  }
}

runUpdate();
