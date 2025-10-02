import fs from 'fs/promises';
import path from 'path';

const revenueDataPath = path.resolve(__dirname, '../owlban_repos/sample_repo/revenue.json');

function validateNumber(value: any, fieldName: string): number {
  if (typeof value !== 'number' || isNaN(value) || value < 0) {
    console.warn(`Invalid number for ${fieldName}, defaulting to 0.`);
    return 0;
  }
  return value;
}

/**
 * Flag to control whether to add sample purchase data.
 * Set to false in production to avoid adding hardcoded sample data.
 */
const ADD_SAMPLE_DATA = false;

async function updateRevenueData(incremental: boolean = false, filePath?: string): Promise<boolean> {
  const dataPath = filePath || revenueDataPath;
  try {
    await fs.access(dataPath);
  } catch {
    console.error('Revenue data file not found at', dataPath);
    return false;
  }

  let data;
  try {
    const fileContent = await fs.readFile(dataPath, 'utf-8');
    data = JSON.parse(fileContent);
  } catch (error) {
    console.error('Failed to read or parse revenue data JSON:', error);
    return false;
  }

  // Ensure purchases object exists
  if (!data.purchases) {
    data.purchases = {
      corporateHomes: 0,
      corporateHomesDetails: [],
      autoFleet: 0,
      autoFleetDetails: []
    };
  } else {
    // Ensure autoFleetDetails array exists
    if (!Array.isArray(data.purchases.autoFleetDetails)) {
      data.purchases.autoFleetDetails = [];
    }
    // Ensure corporateHomesDetails array exists
    if (!Array.isArray(data.purchases.corporateHomesDetails)) {
      data.purchases.corporateHomesDetails = [];
    }
  }

  // Validate and sanitize purchase costs
  data.purchases.autoFleet = validateNumber(data.purchases.autoFleet, 'autoFleet');
  data.purchases.corporateHomes = validateNumber(data.purchases.corporateHomes, 'corporateHomes');

  // Validate totalRevenue before decrementing
  if (typeof data.totalRevenue !== 'number' || isNaN(data.totalRevenue)) {
    console.warn('Invalid or missing totalRevenue, defaulting to 0.');
    data.totalRevenue = 0;
  }

  if (!incremental && ADD_SAMPLE_DATA) {
    // Add a sample auto fleet purchase if none exist
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

    // Add a sample corporate home purchase if none exist
    if (data.purchases.corporateHomesDetails.length === 0) {
      data.purchases.corporateHomesDetails.push({
        address: '123 Corporate Blvd',
        city: 'Metropolis',
        state: 'CA',
        cost: 250000,
        purchaseDate: new Date().toISOString()
      });
      data.purchases.corporateHomes += 250000;
      data.totalRevenue -= 250000;
    }
  }

  // Ensure revenueStreamsDetails object exists
  if (!data.revenueStreamsDetails) {
    data.revenueStreamsDetails = {};
  }

  // Add sample transaction details for each revenue stream if missing
  if (!data.revenueStreams) {
    data.revenueStreams = {};
  }
  for (const streamName of Object.keys(data.revenueStreams)) {
    if (!Array.isArray(data.revenueStreamsDetails[streamName])) {
      data.revenueStreamsDetails[streamName] = [];
    }
    if (data.revenueStreamsDetails[streamName].length === 0) {
      data.revenueStreamsDetails[streamName].push({
        transactionId: `TXN-${Math.floor(Math.random() * 1000000)}`,
        amount: validateNumber(data.revenueStreams[streamName].amount, `revenueStreams.${streamName}.amount`),
        date: new Date().toISOString(),
        description: `Initial transaction for ${streamName}`
      });
    }
  }

  // Integrate payroll data if present
  if (Array.isArray(data.payroll)) {
    let payrollTotal = 0;
    for (const payrollEntry of data.payroll) {
      if (typeof payrollEntry.amount === 'number' && !isNaN(payrollEntry.amount) && payrollEntry.amount >= 0) {
        payrollTotal += payrollEntry.amount;
      } else {
        console.warn('Invalid payroll entry amount detected, skipping:', payrollEntry);
      }
    }
    data.payrollTotal = payrollTotal;
    console.log(`Integrated payroll data total amount: ${payrollTotal}`);
  }

  // Add audit trail entry
  if (!Array.isArray(data.auditTrail)) {
    data.auditTrail = [];
  }
  data.auditTrail.push({
    timestamp: new Date().toISOString(),
    action: 'updateRevenueData',
    details: {
      totalRevenue: data.totalRevenue,
      purchases: {
        autoFleet: data.purchases.autoFleet,
        corporateHomes: data.purchases.corporateHomes
      },
      payrollTotal: data.payrollTotal || 0,
      incrementalUpdate: incremental
    }
  });

  try {
    await fs.writeFile(dataPath, JSON.stringify(data, null, 2), 'utf-8');
    console.log('Revenue data updated with enhanced detailed purchase, revenue stream, payroll information, and audit trail.');
    return true;
  } catch (error) {
    console.error('Error writing updated revenue data file:', error);
    throw error;
  }
}

export default updateRevenueData;
