import { info, warn, error } from '../../utils/loggerWrapper.js';
import fs from 'node:fs/promises';
import path from 'node:path';

const revenueDataPath = path.resolve(
  __dirname,
  '../owlban_repos/sample_repo/revenue.json'
);

function isValidNumber(value: any): value is number {
  return typeof value === 'number' && !Number.isNaN(value) && value >= 0;
}

function validateNumber(value: any, fieldName: string): number {
  if (isValidNumber(value)) {
    return value;
  } else {
warn(`Invalid number for ${fieldName}, defaulting to 0.`);
    return 0;
  }
}

/**
 * Flag to control whether to add sample purchase data.
 * Set to false in production to avoid adding hardcoded sample data.
 */
const ADD_SAMPLE_DATA = false;

function ensurePurchasesStructure(data: any): void {
  // Changed negated condition to positive condition to fix SonarQube warning
  if (data.purchases === undefined || data.purchases === null) {
    data.purchases = {
      corporateHomes: 0,
      corporateHomesDetails: [],
      autoFleet: 0,
      autoFleetDetails: [],
    };
  } else {
    if (!Array.isArray(data.purchases.autoFleetDetails)) {
      data.purchases.autoFleetDetails = [];
    }
    if (!Array.isArray(data.purchases.corporateHomesDetails)) {
      data.purchases.corporateHomesDetails = [];
    }
  }
}

function validatePurchases(data: any): void {
  data.purchases.autoFleet = validateNumber(
    data.purchases.autoFleet,
    'autoFleet'
  );
  data.purchases.corporateHomes = validateNumber(
    data.purchases.corporateHomes,
    'corporateHomes'
  );
}

function addSampleData(data: any, incremental: boolean): void {
  if (!incremental && ADD_SAMPLE_DATA) {
    if (data.purchases.autoFleetDetails.length === 0) {
      data.purchases.autoFleetDetails.push({
        model: 'Sample Model',
        vin: 'SAMPLEVIN123456789',
        dealership: 'Sample Dealership',
        cost: 50000,
        purchaseDate: new Date().toISOString(),
      });
      data.purchases.autoFleet += 50000;
      data.totalRevenue -= 50000;
    }

    if (data.purchases.corporateHomesDetails.length === 0) {
      data.purchases.corporateHomesDetails.push({
        address: '123 Corporate Blvd',
        city: 'Metropolis',
        state: 'CA',
        cost: 250000,
        purchaseDate: new Date().toISOString(),
      });
      data.purchases.corporateHomes += 250000;
      data.totalRevenue -= 250000;
    }
  }
}

function ensureRevenueStreamsDetails(data: any): void {
  if (!data.revenueStreamsDetails) {
    data.revenueStreamsDetails = {};
  }

  if (!data.revenueStreams) {
    data.revenueStreams = {};
  }
}

function addTransactionDetails(data: any): void {
  for (const streamName of Object.keys(data.revenueStreams)) {
    if (!Array.isArray(data.revenueStreamsDetails[streamName])) {
      data.revenueStreamsDetails[streamName] = [];
    }
    if (data.revenueStreamsDetails[streamName].length === 0) {
      data.revenueStreamsDetails[streamName].push({
        transactionId: `TXN-${Math.floor(Math.random() * 1000000)}`,
        amount: validateNumber(
          data.revenueStreams[streamName].amount,
          `revenueStreams.${streamName}.amount`
        ),
        date: new Date().toISOString(),
        description: `Initial transaction for ${streamName}`,
      });
    }
  }
}

function integratePayroll(data: any): void {
  if (Array.isArray(data.payroll)) {
    let payrollTotal = 0;
    for (const payrollEntry of data.payroll) {
      if (
        typeof payrollEntry.amount === 'number' &&
        Number.isNaN(payrollEntry.amount) === false &&
        payrollEntry.amount >= 0
      ) {
        payrollTotal += payrollEntry.amount;
      } else {
warn(
          'Invalid payroll entry amount detected, skipping:',
          payrollEntry
        );
      }
    }
    data.payrollTotal = payrollTotal;
info(`Integrated payroll data total amount: ${payrollTotal}`);
  }
}

function addAuditTrail(data: any, incremental: boolean): void {
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
        corporateHomes: data.purchases.corporateHomes,
      },
      payrollTotal: data.payrollTotal || 0,
      incrementalUpdate: incremental,
    },
  });
}

async function updateRevenueData(
  incremental: boolean = false,
  filePath?: string
): Promise<boolean> {
  try {
    const dataPath = filePath || revenueDataPath;

    await fs.access(dataPath);

    const fileContent = await fs.readFile(dataPath, 'utf-8');

    let data;
    try {
      data = JSON.parse(fileContent);
    } catch (jsonError) {
error(`JSON parsing error in file ${dataPath}:`, (jsonError as Error).message);
      return false;
    }

    ensurePurchasesStructure(data);
    validatePurchases(data);

    if (
      typeof data.totalRevenue !== 'number' ||
      Number.isNaN(data.totalRevenue)
    ) {
      warn('Invalid or missing totalRevenue, defaulting to 0.');
      data.totalRevenue = 0;
    }

    addSampleData(data, incremental);
    ensureRevenueStreamsDetails(data);
    addTransactionDetails(data);
    integratePayroll(data);
    addAuditTrail(data, incremental);

    await fs.writeFile(dataPath, JSON.stringify(data, null, 2), 'utf-8');
    info(
      'Revenue data updated with enhanced detailed purchase, revenue stream, payroll information, and audit trail.'
    );
    return true;
  } catch (error) {
error('Error in updateRevenueData:', (error as Error).message);
    return false;
  }
}

export default updateRevenueData;
