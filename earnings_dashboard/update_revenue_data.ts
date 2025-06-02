import fs from 'fs';
import path from 'path';

const revenueDataPath = path.resolve(__dirname, '../owlban_repos/sample_repo/revenue.json');

function updateRevenueData() {
  if (!fs.existsSync(revenueDataPath)) {
    console.error('Revenue data file not found at', revenueDataPath);
    process.exit(1);
  }

  const data = JSON.parse(fs.readFileSync(revenueDataPath, 'utf-8'));

  // Ensure purchases object exists
  if (!data.purchases) {
    data.purchases = {
      corporateHomes: 0,
      autoFleet: 0,
      autoFleetDetails: []
    };
  } else {
    // Ensure autoFleetDetails array exists
    if (!Array.isArray(data.purchases.autoFleetDetails)) {
      data.purchases.autoFleetDetails = [];
    }
  }

  // Example: Add a sample auto fleet purchase if none exist
  if (data.purchases.autoFleetDetails.length === 0) {
    data.purchases.autoFleetDetails.push({
      model: 'Sample Model',
      vin: 'SAMPLEVIN123456789',
      dealership: 'Sample Dealership',
      cost: 50000,
      purchaseDate: new Date().toISOString()
    });
    data.purchases.autoFleet += 50000;
    data.totalRevenue -= 50000;
  }

  fs.writeFileSync(revenueDataPath, JSON.stringify(data, null, 2), 'utf-8');
  console.log('Revenue data updated with detailed purchase information.');
}

updateRevenueData();
