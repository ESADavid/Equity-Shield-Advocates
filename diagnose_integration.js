#!/usr/bin/env node

/**
 * Diagnostic script for JPMorgan-QuickBooks integration issues
 */

import { info, error, warn, debug } from './utils/loggerWrapper.js';
import dotenv from 'dotenv';
import axios from 'axios';

dotenv.config();

info('🔍 JPMorgan-QuickBooks Integration Diagnostics');
info('==============================================\n');

// Test JPMorgan API endpoints
async function testJPMorganEndpoints() {
  info('🏦 Testing JPMorgan API endpoints...');

  const baseUrl =
    process.env.JPMORGAN_BASE_URL || 'https://api.payments.jpmorgan.com';
  const orgId = process.env.JPMORGAN_ORGANIZATION_ID || 'D3R56WRGSR3R';
  const projectId = process.env.JPMORGAN_PROJECT_ID || 'DK2MQSR1FS7V';

  // Test different possible endpoints
  const endpoints = [
    `${baseUrl}/organizations/${orgId}/projects/${projectId}/v1/health`,
    `${baseUrl}/organizations/${orgId}/projects/${projectId}/health`,
    `${baseUrl}/health`,
    `${baseUrl}/v1/health`,
  ];

  for (const endpoint of endpoints) {
    try {
      info(`Testing: ${endpoint}`);
      const response = await axios.get(endpoint, {
        headers: {
          'Client-Id': process.env.JPMORGAN_CLIENT_ID,
          Timestamp: Math.floor(Date.now() / 1000).toString(),
          Nonce: Math.random().toString(36),
          'Merchant-Id': process.env.JPMORGAN_MERCHANT_ID,
          'Terminal-Id': process.env.JPMORGAN_TERMINAL_ID,
        },
        timeout: 10000,
      });
      info(`✅ Success: ${response.status} - ${response.statusText}`);
      return true;
    } catch (err) {
      info(
        `❌ Failed: ${err.response?.status || 'Network Error'} - ${err.response?.statusText || err.message}`
      );
    }
  }

  info('\n🔧 JPMorgan Troubleshooting:');
  info('1. Verify your JPMorgan credentials are correct');
  info("2. Check if you're using sandbox vs production endpoints");
  info('3. Confirm your merchant account is active');
  info('4. Verify the organization and project IDs are correct');
  return false;
}

// Test QuickBooks API endpoints
async function testQuickBooksEndpoints() {
  info('\n📊 Testing QuickBooks API endpoints...');

  const baseUrl =
    process.env.QUICKBOOKS_BASE_URL ||
    'https://sandbox-quickbooks.api.intuit.com';
  const companyId = process.env.QUICKBOOKS_COMPANY_ID;

  if (!companyId) {
    info('❌ QuickBooks Company ID not set');
    return false;
  }

  const endpoints = [
    `${baseUrl}/v3/company/${companyId}/companyinfo/${companyId}`,
    `${baseUrl}/v3/company/${companyId}/companyinfo`,
    `${baseUrl}/v3/company/${companyId}/Query?query=SELECT * FROM CompanyInfo`,
  ];

  for (const endpoint of endpoints) {
    try {
      info(`Testing: ${endpoint}`);
      const response = await axios.get(endpoint, {
        headers: {
          Authorization: `Bearer ${process.env.QUICKBOOKS_ACCESS_TOKEN}`,
          Accept: 'application/json',
        },
        timeout: 10000,
      });
      info(`✅ Success: ${response.status} - ${response.statusText}`);
      return true;
    } catch (err) {
      info(
        `❌ Failed: ${err.response?.status || 'Network Error'} - ${err.response?.statusText || err.message}`
      );
    }
  }

  info('\n🔧 QuickBooks Troubleshooting:');
  info('1. Your access token may be expired - refresh it');
  info('2. Verify your QuickBooks app permissions');
  info("3. Check if you're using the correct company ID");
  info('4. Confirm your app is authorized for the company');
  return false;
}

// Check environment variables
function checkEnvironment() {
  info('🔧 Environment Variables Check:');
  info('=============================');

  const requiredVars = {
    JPMorgan: [
      'JPMORGAN_CLIENT_ID',
      'JPMORGAN_CLIENT_SECRET',
      'JPMORGAN_MERCHANT_ID',
      'JPMORGAN_TERMINAL_ID',
    ],
    QuickBooks: [
      'QUICKBOOKS_ACCESS_TOKEN',
      'QUICKBOOKS_COMPANY_ID',
      'QUICKBOOKS_CLIENT_ID',
      'QUICKBOOKS_CLIENT_SECRET',
      'QUICKBOOKS_REFRESH_TOKEN',
    ],
  };

  let allSet = true;

  for (const [service, vars] of Object.entries(requiredVars)) {
    info(`\n${service}:`);
    for (const varName of vars) {
      const isSet = process.env[varName] ? true : false;
      info(`  ${varName}: ${isSet ? '✅ Set' : '❌ Not set'}`);
      if (!isSet) allSet = false;
    }
  }

  return allSet;
}

// Main diagnostic function
async function runDiagnostics() {
  const envOk = checkEnvironment();

  if (!envOk) {
    info('\n❌ Environment variables are not properly configured.');
    info(
      'Please check your .env file and ensure all required variables are set.'
    );
    return;
  }

  info('\n✅ All environment variables are set.');
  info('Testing API connectivity...\n');

  const jpmorganOk = await testJPMorganEndpoints();
  const quickbooksOk = await testQuickBooksEndpoints();

  info('\n📋 Diagnostic Summary:');
  info('=====================');
  info(`JPMorgan API: ${jpmorganOk ? '✅ Working' : '❌ Failed'}`);
  info(`QuickBooks API: ${quickbooksOk ? '✅ Working' : '❌ Failed'}`);
  info(
    `Overall Status: ${jpmorganOk && quickbooksOk ? '✅ Ready' : '❌ Issues Found'}`
  );

  if (!jpmorganOk || !quickbooksOk) {
    info('\n🔧 Next Steps:');
    if (!jpmorganOk) {
      info('1. Contact JPMorgan support to verify your credentials');
      info('2. Check JPMorgan developer portal for correct endpoints');
      info('3. Ensure your merchant account is properly configured');
    }
    if (!quickbooksOk) {
      info('1. Refresh your QuickBooks access token');
      info('2. Re-authorize your QuickBooks app');
      info('3. Verify company permissions in QuickBooks');
    }
  }
}

// Run diagnostics
runDiagnostics().catch(error);
