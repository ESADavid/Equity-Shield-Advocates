#!/usr/bin/env node

import { info, error, warn, debug } from 'utils/loggerWrapper.js';

/**
 * JPMorgan Credentials Setup Script
 *
 * This script helps you configure your JPMorgan Payments API credentials
 * for the OSCAR-BROOME-REVENUE integration.
 *
 * Prerequisites:
 * 1. JPMorgan Developer Account: https://developer.jpmorgan.com/
 * 2. QuickBooks Developer Account: https://developer.intuit.com/
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function askQuestion(question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer);
    });
  });
}

async function setupCredentials() {
  logger.info('🚀 JPMorgan & QuickBooks Credentials Setup');
  logger.info('==========================================\n');

  logger.info('📋 Prerequisites:');
  logger.info('1. JPMorgan Developer Account: https://developer.jpmorgan.com/');
  logger.info('2. QuickBooks Developer Account: https://developer.intuit.com/');
  logger.info('3. Your project ID: DK2MQSR1FS7V (already configured)\n');

  const credentials = {};

  // JPMorgan Configuration
  logger.info('🏦 JPMorgan Payments API Configuration:');
  logger.info('---------------------------------------');

  credentials.JPMORGAN_CLIENT_ID = await askQuestion(
    'Enter your JPMorgan Client ID: '
  );
  credentials.JPMORGAN_CLIENT_SECRET = await askQuestion(
    'Enter your JPMorgan Client Secret: '
  );
  credentials.JPMORGAN_MERCHANT_ID = await askQuestion(
    'Enter your JPMorgan Merchant ID: '
  );
  credentials.JPMORGAN_TERMINAL_ID = await askQuestion(
    'Enter your JPMorgan Terminal ID: '
  );

  // QuickBooks Configuration
  logger.info('\n📊 QuickBooks API Configuration:');
  logger.info('--------------------------------');

  credentials.QUICKBOOKS_ACCESS_TOKEN = await askQuestion(
    'Enter your QuickBooks Access Token: '
  );
  credentials.QUICKBOOKS_COMPANY_ID = await askQuestion(
    'Enter your QuickBooks Company ID: '
  );
  credentials.QUICKBOOKS_CLIENT_ID = await askQuestion(
    'Enter your QuickBooks Client ID: '
  );
  credentials.QUICKBOOKS_CLIENT_SECRET = await askQuestion(
    'Enter your QuickBooks Client Secret: '
  );
  credentials.QUICKBOOKS_REFRESH_TOKEN = await askQuestion(
    'Enter your QuickBooks Refresh Token: '
  );

  // Fixed values
  credentials.JPMORGAN_BASE_URL = 'https://api.payments.jpmorgan.com';
  credentials.JPMORGAN_ORGANIZATION_ID = 'D3R56WRGSR3R';
  credentials.JPMORGAN_PROJECT_ID = 'DK2MQSR1FS7V';
  credentials.QUICKBOOKS_BASE_URL = 'https://sandbox-quickbooks.api.intuit.com';

  // Create .env file
  const envPath = path.join(__dirname, '.env');
  let envContent = '# JPMorgan Payments API Configuration\n';

  Object.keys(credentials).forEach((key) => {
    if (key.startsWith('JPMORGAN_') || key.startsWith('QUICKBOOKS_')) {
      envContent += `${key}=${credentials[key]}\n`;
    }
  });

  // Add base URLs
  envContent += '\n# API Base URLs\n';
  envContent += `JPMORGAN_BASE_URL=${credentials.JPMORGAN_BASE_URL}\n`;
  envContent += `QUICKBOOKS_BASE_URL=${credentials.QUICKBOOKS_BASE_URL}\n`;

  fs.writeFileSync(envPath, envContent);

  logger.info('\n✅ Credentials configured successfully!');
  logger.info(`📄 .env file created at: ${envPath}`);
  logger.info('\n🔧 Next Steps:');
  logger.info('1. Review the .env file to ensure all credentials are correct');
  logger.info(
    '2. Run the integration test: node test_jpmorgan_quickbooks_integration.js'
  );
  logger.info('3. Test individual payment endpoints if needed');

  rl.close();
}

// Handle script execution
if (require.main === module) {
  setupCredentials().catch(console.error);
}

module.exports = { setupCredentials };
