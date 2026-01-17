#!/usr/bin/env node

/**
 * Simple credential check script for JPMorgan integration
 */

import { config } from 'dotenv';
import { info } from './utils/loggerWrapper.js';

config();

info('🔍 JPMorgan Credentials Check');
info('=============================\n');

// Check JPMorgan credentials
info('🏦 JPMorgan Configuration:');
info('  Client ID:', process.env.JPMORGAN_CLIENT_ID ? '✅ Set' : '❌ Not set');
info(
  '  Client Secret:',
  process.env.JPMORGAN_CLIENT_SECRET ? '✅ Set' : '❌ Not set'
);
info(
  '  Merchant ID:',
  process.env.JPMORGAN_MERCHANT_ID ? '✅ Set' : '❌ Not set'
);
info(
  '  Terminal ID:',
  process.env.JPMORGAN_TERMINAL_ID ? '✅ Set' : '❌ Not set'
);
info(
  '  Organization ID:',
  process.env.JPMORGAN_ORGANIZATION_ID || 'D3R56WRGSR3R'
);
info('  Project ID:', process.env.JPMORGAN_PROJECT_ID || 'DK2MQSR1FS7V');
info(
  '  Base URL:',
  process.env.JPMORGAN_BASE_URL || 'https://api.payments.jpmorgan.com'
);

info('\n📊 QuickBooks Configuration:');
info(
  '  Access Token:',
  process.env.QUICKBOOKS_ACCESS_TOKEN ? '✅ Set' : '❌ Not set'
);
info(
  '  Company ID:',
  process.env.QUICKBOOKS_COMPANY_ID ? '✅ Set' : '❌ Not set'
);
info(
  '  Client ID:',
  process.env.QUICKBOOKS_CLIENT_ID ? '✅ Set' : '❌ Not set'
);
info(
  '  Client Secret:',
  process.env.QUICKBOOKS_CLIENT_SECRET ? '✅ Set' : '❌ Not set'
);
info(
  '  Refresh Token:',
  process.env.QUICKBOOKS_REFRESH_TOKEN ? '✅ Set' : '❌ Not set'
);
info(
  '  Base URL:',
  process.env.QUICKBOOKS_BASE_URL || 'https://sandbox-quickbooks.api.intuit.com'
);

// Summary
const jpmorganReady =
  process.env.JPMORGAN_CLIENT_ID &&
  process.env.JPMORGAN_CLIENT_SECRET &&
  process.env.JPMORGAN_MERCHANT_ID &&
  process.env.JPMORGAN_TERMINAL_ID;

const quickbooksReady =
  process.env.QUICKBOOKS_ACCESS_TOKEN && process.env.QUICKBOOKS_COMPANY_ID;

info('\n📋 Status Summary:');
info('  JPMorgan Ready:', jpmorganReady ? '✅ Yes' : '❌ No');
info('  QuickBooks Ready:', quickbooksReady ? '✅ Yes' : '❌ No');
info(
  '  Integration Ready:',
  jpmorganReady && quickbooksReady ? '✅ Yes' : '❌ No'
);

if (!jpmorganReady || !quickbooksReady) {
  info('\n🔧 Next Steps:');
  if (!jpmorganReady) {
    info('  1. Get JPMorgan credentials from https://developer.jpmorgan.com/');
    info('  2. Update .env file with JPMorgan credentials');
  }
  if (!quickbooksReady) {
    info('  1. Get QuickBooks credentials from https://developer.intuit.com/');
    info('  2. Update .env file with QuickBooks credentials');
  }
  info('  3. Run: node test_jpmorgan_quickbooks_integration.js');
} else {
  info('\n🚀 Ready to test!');
  info('  Run: node test_jpmorgan_quickbooks_integration.js');
}

info('\n✅ Credential check complete!');
