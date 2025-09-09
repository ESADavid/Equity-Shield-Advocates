#!/usr/bin/env node

/**
 * Diagnostic script for JPMorgan-QuickBooks integration issues
 */

require('dotenv').config();
const axios = require('axios');

console.log('🔍 JPMorgan-QuickBooks Integration Diagnostics');
console.log('==============================================\n');

// Test JPMorgan API endpoints
async function testJPMorganEndpoints() {
  console.log('🏦 Testing JPMorgan API endpoints...');

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
      console.log(`Testing: ${endpoint}`);
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
      console.log(`✅ Success: ${response.status} - ${response.statusText}`);
      return true;
    } catch (error) {
      console.log(`❌ Failed: ${error.response?.status || 'Network Error'} - ${error.response?.statusText || error.message}`);
    }
  }

  console.log('\n🔧 JPMorgan Troubleshooting:');
  console.log('1. Verify your JPMorgan credentials are correct');
  console.log('2. Check if you\'re using sandbox vs production endpoints');
  console.log('3. Confirm your merchant account is active');
  console.log('4. Verify the organization and project IDs are correct');
  return false;
}

// Test QuickBooks API endpoints
async function testQuickBooksEndpoints() {
  console.log('\n📊 Testing QuickBooks API endpoints...');

  const baseUrl = process.env.QUICKBOOKS_BASE_URL || 'https://sandbox-quickbooks.api.intuit.com';
  const companyId = process.env.QUICKBOOKS_COMPANY_ID;

  if (!companyId) {
    console.log('❌ QuickBooks Company ID not set');
    return false;
  }

  const endpoints = [
    `${baseUrl}/v3/company/${companyId}/companyinfo/${companyId}`,
    `${baseUrl}/v3/company/${companyId}/companyinfo`,
    `${baseUrl}/v3/company/${companyId}/Query?query=SELECT * FROM CompanyInfo`
  ];

  for (const endpoint of endpoints) {
    try {
      console.log(`Testing: ${endpoint}`);
      const response = await axios.get(endpoint, {
        headers: {
          'Authorization': `Bearer ${process.env.QUICKBOOKS_ACCESS_TOKEN}`,
          'Accept': 'application/json'
        },
        timeout: 10000
      });
      console.log(`✅ Success: ${response.status} - ${response.statusText}`);
      return true;
    } catch (error) {
      console.log(`❌ Failed: ${error.response?.status || 'Network Error'} - ${error.response?.statusText || error.message}`);
    }
  }

  console.log('\n🔧 QuickBooks Troubleshooting:');
  console.log('1. Your access token may be expired - refresh it');
  console.log('2. Verify your QuickBooks app permissions');
  console.log('3. Check if you\'re using the correct company ID');
  console.log('4. Confirm your app is authorized for the company');
  return false;
}

// Check environment variables
function checkEnvironment() {
  console.log('🔧 Environment Variables Check:');
  console.log('=============================');

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
    console.log(`\n${service}:`);
    for (const varName of vars) {
      const isSet = process.env[varName] ? true : false;
      console.log(`  ${varName}: ${isSet ? '✅ Set' : '❌ Not set'}`);
      if (!isSet) allSet = false;
    }
  }

  return allSet;
}

// Main diagnostic function
async function runDiagnostics() {
  const envOk = checkEnvironment();

  if (!envOk) {
    console.log('\n❌ Environment variables are not properly configured.');
    console.log('Please check your .env file and ensure all required variables are set.');
    return;
  }

  console.log('\n✅ All environment variables are set.');
  console.log('Testing API connectivity...\n');

  const jpmorganOk = await testJPMorganEndpoints();
  const quickbooksOk = await testQuickBooksEndpoints();

  console.log('\n📋 Diagnostic Summary:');
  console.log('=====================');
  console.log(`JPMorgan API: ${jpmorganOk ? '✅ Working' : '❌ Failed'}`);
  console.log(`QuickBooks API: ${quickbooksOk ? '✅ Working' : '❌ Failed'}`);
  console.log(`Overall Status: ${(jpmorganOk && quickbooksOk) ? '✅ Ready' : '❌ Issues Found'}`);

  if (!jpmorganOk || !quickbooksOk) {
    console.log('\n🔧 Next Steps:');
    if (!jpmorganOk) {
      console.log('1. Contact JPMorgan support to verify your credentials');
      console.log('2. Check JPMorgan developer portal for correct endpoints');
      console.log('3. Ensure your merchant account is properly configured');
    }
    if (!quickbooksOk) {
      console.log('1. Refresh your QuickBooks access token');
      console.log('2. Re-authorize your QuickBooks app');
      console.log('3. Verify company permissions in QuickBooks');
    }
  }
}

// Run diagnostics
runDiagnostics().catch(console.error);
