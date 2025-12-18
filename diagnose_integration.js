import { info, error, warn, debug } from '../utils/loggerWrapper.js';

#!/usr/bin/env node

/**
 * Diagnostic script for JPMorgan-QuickBooks integration issues
 */

require('dotenv').config();
const axios = require('axios');

logger.info('🔍 JPMorgan-QuickBooks Integration Diagnostics');
logger.info('==============================================\n');

// Test JPMorgan API endpoints
async function testJPMorganEndpoints() {
  logger.info('🏦 Testing JPMorgan API endpoints...');

  const baseUrl = process.env.JPMORGAN_BASE_URL || 'https://api.payments.jpmorgan.com';
  const orgId = process.env.JPMORGAN_ORGANIZATION_ID || 'D3R56WRGSR3R';
  const projectId = process.env.JPMORGAN_PROJECT_ID || 'DK2MQSR1FS7V';

  // Test different possible endpoints
  const endpoints = [
    `${baseUrl}/organizations/${orgId}/projects/${projectId}/v1/health`,
    `${baseUrl}/organizations/${orgId}/projects/${projectId}/health`,
    `${baseUrl}/health`,
    `${baseUrl}/v1/health`
  ];

  for (const endpoint of endpoints) {
    try {
      logger.info(`Testing: ${endpoint}`);
      const response = await axios.get(endpoint, {
        headers: {
          'Client-Id': process.env.JPMORGAN_CLIENT_ID,
          'Timestamp': Math.floor(Date.now() / 1000).toString(),
          'Nonce': Math.random().toString(36),
          'Merchant-Id': process.env.JPMORGAN_MERCHANT_ID,
          'Terminal-Id': process.env.JPMORGAN_TERMINAL_ID
        },
        timeout: 10000
      });
      logger.info(`✅ Success: ${response.status} - ${response.statusText}`);
      return true;
    } catch (error) {
      logger.info(`❌ Failed: ${error.response?.status || 'Network Error'} - ${error.response?.statusText || error.message}`);
    }
  }

  logger.info('\n🔧 JPMorgan Troubleshooting:');
  logger.info('1. Verify your JPMorgan credentials are correct');
  logger.info('2. Check if you\'re using sandbox vs production endpoints');
  logger.info('3. Confirm your merchant account is active');
  logger.info('4. Verify the organization and project IDs are correct');
  return false;
}

// Test QuickBooks API endpoints
async function testQuickBooksEndpoints() {
  logger.info('\n📊 Testing QuickBooks API endpoints...');

  const baseUrl = process.env.QUICKBOOKS_BASE_URL || 'https://sandbox-quickbooks.api.intuit.com';
  const companyId = process.env.QUICKBOOKS_COMPANY_ID;

  if (!companyId) {
    logger.info('❌ QuickBooks Company ID not set');
    return false;
  }

  const endpoints = [
    `${baseUrl}/v3/company/${companyId}/companyinfo/${companyId}`,
    `${baseUrl}/v3/company/${companyId}/companyinfo`,
    `${baseUrl}/v3/company/${companyId}/Query?query=SELECT * FROM CompanyInfo`
  ];

  for (const endpoint of endpoints) {
    try {
      logger.info(`Testing: ${endpoint}`);
      const response = await axios.get(endpoint, {
        headers: {
          'Authorization': `Bearer ${process.env.QUICKBOOKS_ACCESS_TOKEN}`,
          'Accept': 'application/json'
        },
        timeout: 10000
      });
      logger.info(`✅ Success: ${response.status} - ${response.statusText}`);
      return true;
    } catch (error) {
      logger.info(`❌ Failed: ${error.response?.status || 'Network Error'} - ${error.response?.statusText || error.message}`);
    }
  }

  logger.info('\n🔧 QuickBooks Troubleshooting:');
  logger.info('1. Your access token may be expired - refresh it');
  logger.info('2. Verify your QuickBooks app permissions');
  logger.info('3. Check if you\'re using the correct company ID');
  logger.info('4. Confirm your app is authorized for the company');
  return false;
}

// Check environment variables
function checkEnvironment() {
  logger.info('🔧 Environment Variables Check:');
  logger.info('=============================');

  const requiredVars = {
    'JPMorgan': [
      'JPMORGAN_CLIENT_ID',
      'JPMORGAN_CLIENT_SECRET',
      'JPMORGAN_MERCHANT_ID',
      'JPMORGAN_TERMINAL_ID'
    ],
    'QuickBooks': [
      'QUICKBOOKS_ACCESS_TOKEN',
      'QUICKBOOKS_COMPANY_ID',
      'QUICKBOOKS_CLIENT_ID',
      'QUICKBOOKS_CLIENT_SECRET',
      'QUICKBOOKS_REFRESH_TOKEN'
    ]
  };

  let allSet = true;

  for (const [service, vars] of Object.entries(requiredVars)) {
    logger.info(`\n${service}:`);
    for (const varName of vars) {
      const isSet = process.env[varName] ? true : false;
      logger.info(`  ${varName}: ${isSet ? '✅ Set' : '❌ Not set'}`);
      if (!isSet) allSet = false;
    }
  }

  return allSet;
}

// Main diagnostic function
async function runDiagnostics() {
  const envOk = checkEnvironment();

  if (!envOk) {
    logger.info('\n❌ Environment variables are not properly configured.');
    logger.info('Please check your .env file and ensure all required variables are set.');
    return;
  }

  logger.info('\n✅ All environment variables are set.');
  logger.info('Testing API connectivity...\n');

  const jpmorganOk = await testJPMorganEndpoints();
  const quickbooksOk = await testQuickBooksEndpoints();

  logger.info('\n📋 Diagnostic Summary:');
  logger.info('=====================');
  logger.info(`JPMorgan API: ${jpmorganOk ? '✅ Working' : '❌ Failed'}`);
  logger.info(`QuickBooks API: ${quickbooksOk ? '✅ Working' : '❌ Failed'}`);
  logger.info(`Overall Status: ${(jpmorganOk && quickbooksOk) ? '✅ Ready' : '❌ Issues Found'}`);

  if (!jpmorganOk || !quickbooksOk) {
    logger.info('\n🔧 Next Steps:');
    if (!jpmorganOk) {
      logger.info('1. Contact JPMorgan support to verify your credentials');
      logger.info('2. Check JPMorgan developer portal for correct endpoints');
      logger.info('3. Ensure your merchant account is properly configured');
    }
    if (!quickbooksOk) {
      logger.info('1. Refresh your QuickBooks access token');
      logger.info('2. Re-authorize your QuickBooks app');
      logger.info('3. Verify company permissions in QuickBooks');
    }
  }
}

// Run diagnostics
runDiagnostics().catch(console.error);
