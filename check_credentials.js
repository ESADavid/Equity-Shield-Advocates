import { info, error, warn, debug } from '../utils/loggerWrapper.js';

#!/usr/bin/env node

/**
 * Simple credential check script for JPMorgan integration
 */

require('dotenv').config();

logger.info('🔍 JPMorgan Credentials Check');
logger.info('=============================\n');

// Check JPMorgan credentials
logger.info('🏦 JPMorgan Configuration:');
logger.info('  Client ID:', process.env.JPMORGAN_CLIENT_ID ? '✅ Set' : '❌ Not set');
logger.info('  Client Secret:', process.env.JPMORGAN_CLIENT_SECRET ? '✅ Set' : '❌ Not set');
logger.info('  Merchant ID:', process.env.JPMORGAN_MERCHANT_ID ? '✅ Set' : '❌ Not set');
logger.info('  Terminal ID:', process.env.JPMORGAN_TERMINAL_ID ? '✅ Set' : '❌ Not set');
logger.info('  Organization ID:', process.env.JPMORGAN_ORGANIZATION_ID || 'D3R56WRGSR3R');
logger.info('  Project ID:', process.env.JPMORGAN_PROJECT_ID || 'DK2MQSR1FS7V');
logger.info('  Base URL:', process.env.JPMORGAN_BASE_URL || 'https://api.payments.jpmorgan.com');

logger.info('\n📊 QuickBooks Configuration:');
logger.info('  Access Token:', process.env.QUICKBOOKS_ACCESS_TOKEN ? '✅ Set' : '❌ Not set');
logger.info('  Company ID:', process.env.QUICKBOOKS_COMPANY_ID ? '✅ Set' : '❌ Not set');
logger.info('  Client ID:', process.env.QUICKBOOKS_CLIENT_ID ? '✅ Set' : '❌ Not set');
logger.info('  Client Secret:', process.env.QUICKBOOKS_CLIENT_SECRET ? '✅ Set' : '❌ Not set');
logger.info('  Refresh Token:', process.env.QUICKBOOKS_REFRESH_TOKEN ? '✅ Set' : '❌ Not set');
logger.info('  Base URL:', process.env.QUICKBOOKS_BASE_URL || 'https://sandbox-quickbooks.api.intuit.com');

// Summary
const jpmorganReady = process.env.JPMORGAN_CLIENT_ID && process.env.JPMORGAN_CLIENT_SECRET &&
                     process.env.JPMORGAN_MERCHANT_ID && process.env.JPMORGAN_TERMINAL_ID;

const quickbooksReady = process.env.QUICKBOOKS_ACCESS_TOKEN && process.env.QUICKBOOKS_COMPANY_ID;

logger.info('\n📋 Status Summary:');
logger.info('  JPMorgan Ready:', jpmorganReady ? '✅ Yes' : '❌ No');
logger.info('  QuickBooks Ready:', quickbooksReady ? '✅ Yes' : '❌ No');
logger.info('  Integration Ready:', (jpmorganReady && quickbooksReady) ? '✅ Yes' : '❌ No');

if (!jpmorganReady || !quickbooksReady) {
  logger.info('\n🔧 Next Steps:');
  if (!jpmorganReady) {
    logger.info('  1. Get JPMorgan credentials from https://developer.jpmorgan.com/');
    logger.info('  2. Update .env file with JPMorgan credentials');
  }
  if (!quickbooksReady) {
    logger.info('  1. Get QuickBooks credentials from https://developer.intuit.com/');
    logger.info('  2. Update .env file with QuickBooks credentials');
  }
  logger.info('  3. Run: node test_jpmorgan_quickbooks_integration.js');
} else {
  logger.info('\n🚀 Ready to test!');
  logger.info('  Run: node test_jpmorgan_quickbooks_integration.js');
}

logger.info('\n✅ Credential check complete!');
