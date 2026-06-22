/**
 * Revenue Data Sync Module
 * Syncs revenue data from aggregated_revenue.json to monthly reporting template
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Account to Entity mapping from INTEGRATION_ENTITY_MAPPING.md
const ACCOUNT_ENTITY_MAP = {
  'ACCT-1001': { entity: 'LBWG', account: 'Operating', type: 'checking' },
  'ACCT-1002': { entity: 'MERCDEE', account: 'Operating', type: 'checking' },
  'ACCT-1003': { entity: 'Family Trust', account: 'Primary', type: 'checking' }
};

/**
 * Load revenue data from aggregated_revenue.json
 */
export function loadRevenueData(dataPath) {
  try {
    const data = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
    return data;
  } catch (err) {
    console.error('Error loading revenue data:', err.message);
    throw err;
  }
}

/**
 * Map revenue streams to entity accounts
 */
export function mapRevenueToEntities(revenueData) {
  const entityRevenue = {
    LBWG: { Operating: 0, Reserve: 0 },
    MERCDEE: { Operating: 0, Reserve: 0 },
    'Family Trust': { Primary: 0, Reserve: 0 }
  };
  
  // Map each revenue stream to its entity
  if (revenueData.revenueStreams) {
    for (const [stream, data] of Object.entries(revenueData.revenueStreams)) {
      const mapping = Object.values(ACCOUNT_ENTITY_MAP).find(
        m => data.accountNumber === getAccountNumberForEntity(m.entity, m.account)
      );
      if (mapping) {
        entityRevenue[mapping.entity][mapping.account] = data.amount;
      }
    }
  }
  
  return entityRevenue;
}

/**
 * Helper to get account number for entity
 */
function getAccountNumberForEntity(entity, account) {
  const map = {
    'LBWG-Operating': 'ACCT-1001',
    'MERCDEE-Operating': 'ACCT-1002',
    'Family Trust-Primary': 'ACCT-1003'
  };
  return map[`${entity}-${account}`];
}

/**
 * Calculate MTD, QTD, YTD from revenue data
 */
export function calculateTimePeriods(entityRevenue, month = 1, quarter = 1, year = 2025) {
  const summary = {
    LBWG: { MTD: 0, QTD: 0, YTD: 0 },
    MERCDEE: { MTD: 0, QTD: 0, YTD: 0 },
    'Family Trust': { MTD: 0, QTD: 0, YTD: 0 }
  };
  
  // Calculate totals (simplified - assumes all revenue is current month)
  for (const [entity, accounts] of Object.entries(entityRevenue)) {
    const operatingRevenue = accounts.Operating || 0;
    const reserveRevenue = accounts.Reserve || 0;
    const total = operatingRevenue + reserveRevenue;
    
    summary[entity] = {
      MTD: total,
      QTD: total,
      YTD: total
    };
  }
  
  return summary;
}

/**
 * Generate monthly report data object
 */
export function generateReportData(revenueData, options = {}) {
  const entityRevenue = mapRevenueToEntities(revenueData);
  const timePeriods = calculateTimePeriods(entityRevenue, options.month, options.quarter, options.year);
  
  const reportPeriod = options.period || 'January 2025';
  const reportDate = new Date().toISOString().split('T')[0];
  
  return {
    period: reportPeriod,
    reportDate,
    preparedBy: options.preparer || '[Preparer Name]',
    reviewedBy: options.reviewer || '[Reviewer Name]',
    entities: entityRevenue,
    summary: timePeriods,
    lastUpdated: new Date().toISOString()
  };
}

/**
 * Apply revenue data to monthly reporting packet template
 */
export function populateMonthlyReport(templatePath, revenueData, outputPath) {
  const reportData = generateReportData(revenueData);
  
  // Read template
  let template = fs.readFileSync(templatePath, 'utf8');
  
  // Replace placeholders with actual data
  template = template.replace(
    '**[Month Year]**',
    reportData.period
  );
  template = template.replace(
    '**[Date Generated]**',
    reportData.reportDate
  );
  template = template.replace(
    '**[ preparer Name]**',
    reportData.preparedBy
  );
  template = template.replace(
    '**[ reviewer Name]**',
    reportData.reviewedBy
  );
  
  // Update LBWG Operating
  template = template.replace(
    /\| LBWG \| Operating \|(\s*\*\$\d+\*\*)/,
    `| LBWG | Operating | **$${reportData.entities.LBWG.Operating.toLocaleString()}**`
  );
  
  // Update LBWG Reserve
  template = template.replace(
    /\| LBWG \| Reserve \|(\s*\*\$\d+\*\*)/,
    `| LBWG | Reserve | **$${reportData.entities.LBWG.Reserve.toLocaleString()}**`
  );
  
  // Update MERCDEE Operating
  template = template.replace(
    /\| MERCDEE \| Operating \|(\s*\*\$\d+\*\*)/,
    `| MERCDEE | Operating | **$${reportData.entities.MERCDEE.Operating.toLocaleString()}**`
  );
  
  // Update MERCDEE Reserve
  template = template.replace(
    /\| MERCDEE \| Reserve \|(\s*\*\$\d+\*\*)/,
    `| MERCDEE | Reserve | **$${reportData.entities.MERCDEE.Reserve.toLocaleString()}**`
  );
  
  // Update Family Trust Primary
  template = template.replace(
    /\| Family Trust \| Primary \|(\s*\*\$\d+\*\*)/,
    `| Family Trust | Primary | **$${reportData.entities['Family Trust'].Primary.toLocaleString()}**`
  );
  
  // Update Family Trust Reserve
  template = template.replace(
    /\| Family Trust \| Reserve \|(\s*\*\$\d+\*\*)/,
    `| Family Trust | Reserve | **$${reportData.entities['Family Trust'].Reserve.toLocaleString()}**`
  );
  
  // Update Consolidated Summary - LBWG row
  template = template.replace(
    /\| LBWG \|(\s*\*\$\d+\*\*\|){3}/,
    `| LBWG | **$${reportData.summary.LBWG.MTD.toLocaleString()}** | **$${reportData.summary.LBWG.QTD.toLocaleString()}** | **$${reportData.summary.LBWG.YTD.toLocaleString()}**`
  );
  
  // Update Consolidated Summary - MERCDEE row
  template = template.replace(
    /\| MERCDEE \|(\s*\*\$\d+\*\*\|){3}/,
    `| MERCDEE | **$${reportData.summary.MERCDEE.MTD.toLocaleString()}** | **$${reportData.summary.MERCDEE.QTD.toLocaleString()}** | **$${reportData.summary.MERCDEE.YTD.toLocaleString()}**`
  );
  
  // Update Consolidated Summary - Family Trust row
  template = template.replace(
    /\| Family Trust \|(\s*\*\$\d+\*\*\|){3}/,
    `| Family Trust | **$${reportData.summary['Family Trust'].MTD.toLocaleString()}** | **$${reportData.summary['Family Trust'].QTD.toLocaleString()}** | **$${reportData.summary['Family Trust'].YTD.toLocaleString()}**`
  );
  
  // Calculate and update Total row
  const totalMTD = Object.values(reportData.summary).reduce((sum, e) => sum + e.MTD, 0);
  const totalQTD = Object.values(reportData.summary).reduce((sum, e) => sum + e.QTD, 0);
  const totalYTD = Object.values(reportData.summary).reduce((sum, e) => sum + e.YTD, 0);
  
  template = template.replace(
    /\| \*\*Total\*\* \|(\s*\*\$\d+\*\*\|){3}/,
    `| **Total** | **$${totalMTD.toLocaleString()}** | **$${totalQTD.toLocaleString()}** | **$${totalYTD.toLocaleString()}**`
  );
  
  // Write output
  fs.writeFileSync(outputPath, template, 'utf8');
  
  return {
    ok: true,
    period: reportData.period,
    entities: Object.keys(reportData.entities),
    lastUpdated: reportData.lastUpdated
  };
}

// Main execution
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const revenuePath = path.join(__dirname, '../OSCAR-BROOME-REVENUE/earnings_dashboard/aggregated_revenue.json');
  const templatePath = path.join(__dirname, '../data/monthly_reporting_packet.md');
  const outputPath = path.join(__dirname, '../data/monthly_reporting_packet.md');
  
  const revenueData = loadRevenueData(revenuePath);
  const result = populateMonthlyReport(templatePath, revenueData, outputPath);
  
  console.log('Revenue sync complete:', JSON.stringify(result, null, 2));
}

export default {
  loadRevenueData,
  mapRevenueToEntities,
  calculateTimePeriods,
  generateReportData,
  populateMonthlyReport
};
