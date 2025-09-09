#!/usr/bin/env node

/**
 * Simple credential check script for JPMorgan integration
 */

require('dotenv').config();

console.log('🔍 JPMorgan Credentials Check');
console.log('=============================\n');

// Check JPMorgan credentials
console.log('🏦 JPMorgan Configuration:');
console.log('  Client ID:', process.env.JPMORGAN_CLIENT_ID ? '✅ Set' : '❌ Not set');
console.log('  Client Secret:', process.env.JPMORGAN_CLIENT_SECRET ? '✅ Set' : '❌ Not set');
console.log('  Merchant ID:', process.env.JPMORGAN_MERCHANT_ID ? '✅ Set' : '❌ Not set');
console.log('  Terminal ID:', process.env.JPMORGAN_TERMINAL_ID ? '✅ Set' : '❌ Not set');
console.log('  Organization ID:', process.env.JPMORGAN_ORGANIZATION_ID || 'D3R56WRGSR3R');
console.log('  Project ID:', process.env.JPMORGAN_PROJECT_ID || 'DK2MQSR1FS7V');
console.log('  Base URL:', process.env.JPMORGAN_BASE_URL || 'https://api.payments.jpmorgan.com');

console.log('\n📊 QuickBooks Configuration:');
console.log('  Access Token:', process.env.QUICKBOOKS_ACCESS_TOKEN ? '✅ Set' : '❌ Not set');
console.log('  Company ID:', process.env.QUICKBOOKS_COMPANY_ID ? '✅ Set' : '❌ Not set');
console.log('  Client ID:', process.env.QUICKBOOKS_CLIENT_ID ? '✅ Set' : '❌ Not set');
console.log('  Client Secret:', process.env.QUICKBOOKS_CLIENT_SECRET ? '✅ Set' : '❌ Not set');
console.log('  Refresh Token:', process.env.QUICKBOOKS_REFRESH_TOKEN ? '✅ Set' : '❌ Not set');
console.log('  Base URL:', process.env.QUICKBOOKS_BASE_URL || 'https://sandbox-quickbooks.api.intuit.com');

// Summary
const jpmorganReady = process.env.JPMORGAN_CLIENT_ID && process.env.JPMORGAN_CLIENT_SECRET &&
                     process.env.JPMORGAN_MERCHANT_ID && process.env.JPMORGAN_TERMINAL_ID;

const quickbooksReady = process.env.QUICKBOOKS_ACCESS_TOKEN && process.env.QUICKBOOKS_COMPANY_ID;

console.log('\n📋 Status Summary:');
console.log('  JPMorgan Ready:', jpmorganReady ? '✅ Yes' : '❌ No');
console.log('  QuickBooks Ready:', quickbooksReady ? '✅ Yes' : '❌ No');
console.log('  Integration Ready:', (jpmorganReady && quickbooksReady) ? '✅ Yes' : '❌ No');

if (!jpmorganReady || !quickbooksReady) {
  console.log('\n🔧 Next Steps:');
  if (!jpmorganReady) {
    console.log('  1. Get JPMorgan credentials from https://developer.jpmorgan.com/');
    console.log('  2. Update .env file with JPMorgan credentials');
  }
  if (!quickbooksReady) {
    console.log('  1. Get QuickBooks credentials from https://developer.intuit.com/');
    console.log('  2. Update .env file with QuickBooks credentials');
  }
  console.log('  3. Run: node test_jpmorgan_quickbooks_integration.js');
} else {
  console.log('\n🚀 Ready to test!');
  console.log('  Run: node test_jpmorgan_quickbooks_integration.js');
}

console.log('\n✅ Credential check complete!');
