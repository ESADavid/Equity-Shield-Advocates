import updateRevenueData from '../update_revenue_data';

async function runUpdate() {
  try {
    const success = updateRevenueData();
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
