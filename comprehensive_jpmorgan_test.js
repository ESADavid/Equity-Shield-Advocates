#!/usr/bin/env node

/**
 * Comprehensive JPMorgan Payment Integration Test Suite
 *
 * This test suite provides thorough testing of all JPMorgan payment endpoints
 * and integration functionality.
 */

import express from 'express';
import axios from 'axios';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

// Test configuration
const TEST_CONFIG = {
  JPMORGAN: {
    BASE_URL:
      process.env.JPMORGAN_BASE_URL || 'https://api.payments.jpmorgan.com',
    ORGANIZATION_ID: process.env.JPMORGAN_ORGANIZATION_ID || 'D3R56WRGSR3R',
    PROJECT_ID: process.env.JPMORGAN_PROJECT_ID || 'DK2MQSR1FS7V',
    CLIENT_ID: process.env.JPMORGAN_CLIENT_ID,
    CLIENT_SECRET: process.env.JPMORGAN_CLIENT_SECRET,
    MERCHANT_ID: process.env.JPMORGAN_MERCHANT_ID,
    TERMINAL_ID: process.env.JPMORGAN_TERMINAL_ID,
  },
  SERVER: {
    PORT: 3000,
    HOST: 'http://localhost:3000',
  },
};

// Check if credentials are configured
const hasCredentials =
  TEST_CONFIG.JPMORGAN.CLIENT_ID && TEST_CONFIG.JPMORGAN.CLIENT_SECRET;
const isMockMode = !hasCredentials;

// Generate JPMorgan authentication headers
function generateAuthHeaders() {
  if (!TEST_CONFIG.JPMORGAN.CLIENT_ID || !TEST_CONFIG.JPMORGAN.CLIENT_SECRET) {
    throw new Error('JPMorgan credentials not configured');
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(16).toString('hex');
  const message = TEST_CONFIG.JPMORGAN.CLIENT_ID + timestamp + nonce;
  const signature = crypto
    .createHmac('sha256', TEST_CONFIG.JPMORGAN.CLIENT_SECRET)
    .update(message)
    .digest('base64');

  return {
    'Content-Type': 'application/json',
    'Client-Id': TEST_CONFIG.JPMORGAN.CLIENT_ID,
    Timestamp: timestamp.toString(),
    Nonce: nonce,
    Signature: signature,
    'Merchant-Id': TEST_CONFIG.JPMORGAN.MERCHANT_ID,
    'Terminal-Id': TEST_CONFIG.JPMORGAN.TERMINAL_ID,
  };
}

// Test result tracking
class TestSuite {
  constructor() {
    this.results = {
      total: 0,
      passed: 0,
      failed: 0,
      skipped: 0,
      tests: [],
    };
  }

  log(message, type = 'info') {
    const timestamp = new Date().toISOString();
    const prefix =
      type === 'error'
        ? '❌'
        : type === 'success'
          ? '✅'
          : type === 'warning'
            ? '⚠️'
            : 'ℹ️';
    console.log(`[${timestamp}] ${prefix} ${message}`);
  }

  addTest(name, result, message = '') {
    this.results.total++;
    this.results.tests.push({
      name,
      result,
      message,
      timestamp: new Date().toISOString(),
    });

    if (result === 'passed') {
      this.results.passed++;
      this.log(`${name}: PASSED`, 'success');
    } else if (result === 'failed') {
      this.results.failed++;
      this.log(`${name}: FAILED - ${message}`, 'error');
    } else if (result === 'skipped') {
      this.results.skipped++;
      this.log(`${name}: SKIPPED - ${message}`, 'warning');
    }
  }

  generateReport() {
    const report = {
      summary: {
        total: this.results.total,
        passed: this.results.passed,
        failed: this.results.failed,
        skipped: this.results.skipped,
        successRate:
          this.results.total > 0
            ? ((this.results.passed / this.results.total) * 100).toFixed(2)
            : 0,
      },
      tests: this.results.tests,
      timestamp: new Date().toISOString(),
    };

    console.log('\n' + '='.repeat(60));
    console.log('📊 COMPREHENSIVE TEST REPORT');
    console.log('='.repeat(60));
    console.log(`Total Tests: ${report.summary.total}`);
    console.log(`✅ Passed: ${report.summary.passed}`);
    console.log(`❌ Failed: ${report.summary.failed}`);
    console.log(`⚠️ Skipped: ${report.summary.skipped}`);
    console.log(`📈 Success Rate: ${report.summary.successRate}%`);
    console.log('='.repeat(60));

    if (report.summary.failed > 0) {
      console.log('\n❌ FAILED TESTS:');
      this.results.tests
        .filter((t) => t.result === 'failed')
        .forEach((test) => {
          console.log(`• ${test.name}: ${test.message}`);
        });
    }

    return report;
  }
}

// Individual test functions
class JPMorganEndpointTests {
  constructor(testSuite) {
    this.testSuite = testSuite;
    this.baseURL = TEST_CONFIG.SERVER.HOST;
  }

  async testHealthEndpoint() {
    try {
      this.testSuite.log('Testing health endpoint...');
      const response = await axios.get(`${this.baseURL}/jpmorgan/health`, {
        timeout: 5000,
      });

      if (response.status === 200 && response.data.status === 'healthy') {
        this.testSuite.addTest(
          'Health Endpoint',
          'passed',
          'Health check successful'
        );
        return true;
      } else {
        this.testSuite.addTest(
          'Health Endpoint',
          'failed',
          `Unexpected response: ${JSON.stringify(response.data)}`
        );
        return false;
      }
    } catch (error) {
      if (!hasCredentials && error.code === 'ECONNREFUSED') {
        this.testSuite.addTest(
          'Health Endpoint',
          'skipped',
          'Server not running - credentials not configured'
        );
        return false;
      }
      this.testSuite.addTest(
        'Health Endpoint',
        'failed',
        `Health check failed: ${error.message}`
      );
      return false;
    }
  }

  async testCreatePaymentEndpoint() {
    try {
      this.testSuite.log('Testing payment creation endpoint...');

      let headers = {};
      let paymentData;

      if (isMockMode) {
        // Simple payload for mock mode
        paymentData = {
          amount: 100,
          currency: 'USD',
          orderId: `TEST-${Date.now()}`,
          description: 'Comprehensive test payment',
          customer: {
            id: 'TEST-CUSTOMER-001',
            name: 'Test Customer',
          },
        };
      } else {
        headers = generateAuthHeaders();
        paymentData = {
          amount: {
            value: 100.0,
            currency: 'USD',
          },
          order: {
            id: `TEST-${Date.now()}`,
            description: 'Comprehensive test payment',
          },
          customer: {
            id: 'TEST-CUSTOMER-001',
            name: 'Test Customer',
          },
          merchant: {
            id: TEST_CONFIG.JPMORGAN.MERCHANT_ID,
            terminalId: TEST_CONFIG.JPMORGAN.TERMINAL_ID,
          },
          paymentMethod: {
            type: 'CARD',
          },
        };
      }

      const response = await axios.post(
        `${this.baseURL}/jpmorgan/create-payment`,
        paymentData,
        { headers, timeout: 15000 }
      );

      if (
        response.status === 200 &&
        response.data.success &&
        response.data.paymentId
      ) {
        this.testSuite.addTest(
          'Create Payment',
          'passed',
          `Payment created: ${response.data.paymentId} (Mock: ${isMockMode})`
        );
        return response.data.paymentId;
      } else {
        this.testSuite.addTest(
          'Create Payment',
          'failed',
          `Unexpected response: ${JSON.stringify(response.data)}`
        );
        return false;
      }
    } catch (error) {
      this.testSuite.addTest(
        'Create Payment',
        'failed',
        `Payment creation failed: ${error.message}`
      );
      return false;
    }
  }

  async testPaymentStatusEndpoint(paymentId) {
    try {
      this.testSuite.log('Testing payment status endpoint...');

      if (!paymentId) {
        this.testSuite.addTest(
          'Payment Status',
          'skipped',
          'No payment ID available'
        );
        return false;
      }

      let headers = {};
      if (!isMockMode) {
        headers = generateAuthHeaders();
      }

      const response = await axios.get(
        `${this.baseURL}/jpmorgan/payment-status/${paymentId}`,
        { headers, timeout: 10000 }
      );

      if (response.status === 200 && response.data.success) {
        this.testSuite.addTest(
          'Payment Status',
          'passed',
          `Status: ${response.data.paymentStatus?.status || response.data.status || 'Unknown'} (Mock: ${isMockMode})`
        );
        return true;
      } else {
        this.testSuite.addTest(
          'Payment Status',
          'failed',
          `Unexpected response: ${JSON.stringify(response.data)}`
        );
        return false;
      }
    } catch (error) {
      this.testSuite.addTest(
        'Payment Status',
        'failed',
        `Status check failed: ${error.message}`
      );
      return false;
    }
  }

  async testRefundEndpoint(paymentId) {
    try {
      this.testSuite.log('Testing refund endpoint...');

      if (!paymentId) {
        this.testSuite.addTest(
          'Refund Payment',
          'skipped',
          'No payment ID available'
        );
        return false;
      }

      let headers = {};
      if (!isMockMode) {
        headers = generateAuthHeaders();
      }

      const refundData = {
        paymentId: paymentId,
        amount: 50,
        reason: 'Test refund',
      };

      const response = await axios.post(
        `${this.baseURL}/jpmorgan/refund`,
        refundData,
        { headers, timeout: 15000 }
      );

      if (response.status === 200 && response.data.success) {
        this.testSuite.addTest(
          'Refund Payment',
          'passed',
          `Refund created: ${response.data.refundId} (Mock: ${isMockMode})`
        );
        return true;
      } else {
        this.testSuite.addTest(
          'Refund Payment',
          'failed',
          `Unexpected response: ${JSON.stringify(response.data)}`
        );
        return false;
      }
    } catch (error) {
      this.testSuite.addTest(
        'Refund Payment',
        'failed',
        `Refund failed: ${error.message}`
      );
      return false;
    }
  }

  async testCaptureEndpoint(paymentId) {
    try {
      this.testSuite.log('Testing capture endpoint...');

      if (!paymentId) {
        this.testSuite.addTest(
          'Capture Payment',
          'skipped',
          'No payment ID available'
        );
        return false;
      }

      let headers = {};
      if (!isMockMode) {
        headers = generateAuthHeaders();
      }

      const captureData = {
        paymentId: paymentId,
        amount: 50,
      };

      const response = await axios.post(
        `${this.baseURL}/jpmorgan/capture`,
        captureData,
        { headers, timeout: 15000 }
      );

      if (response.status === 200 && response.data.success) {
        this.testSuite.addTest(
          'Capture Payment',
          'passed',
          `Payment captured: ${response.data.captureId} (Mock: ${isMockMode})`
        );
        return true;
      } else {
        this.testSuite.addTest(
          'Capture Payment',
          'failed',
          `Unexpected response: ${JSON.stringify(response.data)}`
        );
        return false;
      }
    } catch (error) {
      this.testSuite.addTest(
        'Capture Payment',
        'failed',
        `Capture failed: ${error.message}`
      );
      return false;
    }
  }

  async testVoidEndpoint(paymentId) {
    try {
      this.testSuite.log('Testing void endpoint...');

      if (!paymentId) {
        this.testSuite.addTest(
          'Void Payment',
          'skipped',
          'No payment ID available'
        );
        return false;
      }

      let headers = {};
      if (!isMockMode) {
        headers = generateAuthHeaders();
      }

      const voidData = {
        paymentId: paymentId,
        reason: 'Test void',
      };

      const response = await axios.post(
        `${this.baseURL}/jpmorgan/void`,
        voidData,
        { headers, timeout: 15000 }
      );

      if (response.status === 200 && response.data.success) {
        this.testSuite.addTest(
          'Void Payment',
          'passed',
          `Payment voided: ${response.data.voidId} (Mock: ${isMockMode})`
        );
        return true;
      } else {
        this.testSuite.addTest(
          'Void Payment',
          'failed',
          `Unexpected response: ${JSON.stringify(response.data)}`
        );
        return false;
      }
    } catch (error) {
      this.testSuite.addTest(
        'Void Payment',
        'failed',
        `Void failed: ${error.message}`
      );
      return false;
    }
  }

  async testTransactionsEndpoint() {
    try {
      this.testSuite.log('Testing transactions endpoint...');

      let headers = {};
      if (!isMockMode) {
        headers = generateAuthHeaders();
      }

      const response = await axios.get(
        `${this.baseURL}/jpmorgan/transactions?limit=10`,
        { headers, timeout: 10000 }
      );

      if (response.status === 200 && response.data.success) {
        this.testSuite.addTest(
          'Get Transactions',
          'passed',
          `Retrieved ${response.data.transactions?.length || 0} transactions (Mock: ${isMockMode})`
        );
        return true;
      } else {
        this.testSuite.addTest(
          'Get Transactions',
          'failed',
          `Unexpected response: ${JSON.stringify(response.data)}`
        );
        return false;
      }
    } catch (error) {
      this.testSuite.addTest(
        'Get Transactions',
        'failed',
        `Transactions fetch failed: ${error.message}`
      );
      return false;
    }
  }

  async testWebhookEndpoint() {
    try {
      this.testSuite.log('Testing webhook endpoint...');

      const webhookData = {
        type: 'payment.authorized',
        id: 'test-webhook-001',
        data: {
          paymentId: 'test-payment-001',
          amount: 100.0,
          status: 'AUTHORIZED',
        },
      };

      const headers = {
        'Content-Type': 'application/json',
      };

      if (!isMockMode) {
        // For real mode, add signature headers (but for test, use invalid to check validation)
        headers['x-jpmorgan-signature'] = 'test-signature';
        headers['x-jpmorgan-timestamp'] = Math.floor(
          Date.now() / 1000
        ).toString();
        headers['x-jpmorgan-nonce'] = 'test-nonce';
      }

      const response = await axios.post(
        `${this.baseURL}/jpmorgan/webhook`,
        webhookData,
        {
          headers,
          timeout: 10000,
        }
      );

      if (response.status === 200 && response.data.received) {
        this.testSuite.addTest(
          'Webhook Endpoint',
          'passed',
          'Webhook processed successfully (Mock: ${isMockMode})'
        );
        return true;
      } else {
        this.testSuite.addTest(
          'Webhook Endpoint',
          'failed',
          `Unexpected response: ${JSON.stringify(response.data)}`
        );
        return false;
      }
    } catch (error) {
      if (!isMockMode && error.response?.status === 401) {
        this.testSuite.addTest(
          'Webhook Endpoint',
          'passed',
          'Webhook signature validation working (expected 401 for test signature)'
        );
        return true;
      }
      this.testSuite.addTest(
        'Webhook Endpoint',
        'failed',
        `Webhook test failed: ${error.message}`
      );
      return false;
    }
  }

  async testEnvironmentConfiguration() {
    this.testSuite.log('Testing environment configuration...');

    if (isMockMode) {
      this.testSuite.addTest(
        'Environment Config',
        'passed',
        'Mock mode active - environment config not required'
      );
      return true;
    }

    const requiredVars = [
      'JPMORGAN_BASE_URL',
      'JPMORGAN_ORGANIZATION_ID',
      'JPMORGAN_PROJECT_ID',
    ];

    let configValid = true;
    const missingVars = [];

    requiredVars.forEach((varName) => {
      if (!process.env[varName]) {
        missingVars.push(varName);
        configValid = false;
      }
    });

    if (configValid) {
      this.testSuite.addTest(
        'Environment Config',
        'passed',
        'All required environment variables are set'
      );
    } else {
      this.testSuite.addTest(
        'Environment Config',
        'failed',
        `Missing variables: ${missingVars.join(', ')}`
      );
    }

    return configValid;
  }
}

// Main test execution
async function runComprehensiveTests() {
  const testSuite = new TestSuite();
  const endpointTests = new JPMorganEndpointTests(testSuite);

  console.log('🚀 Starting Comprehensive JPMorgan Payment Integration Tests');
  console.log('='.repeat(70));
  console.log(`Server URL: ${TEST_CONFIG.SERVER.HOST}`);
  console.log(`Project ID: ${TEST_CONFIG.JPMORGAN.PROJECT_ID}`);
  console.log(`Credentials Configured: ${hasCredentials ? '✅ Yes' : '⚠️ No'}`);
  console.log('='.repeat(70));

  // Test environment configuration
  await endpointTests.testEnvironmentConfiguration();

  // Test health endpoint
  const healthOk = await endpointTests.testHealthEndpoint();

  if (!healthOk && !hasCredentials) {
    testSuite.log(
      '⚠️ Server not running - most tests will be skipped',
      'warning'
    );
    testSuite.log(
      'To run live API tests, configure credentials and start the server',
      'warning'
    );
  }

  // Test payment creation
  const paymentId = await endpointTests.testCreatePaymentEndpoint();

  // Test other endpoints (only if we have a payment ID)
  if (paymentId) {
    await endpointTests.testPaymentStatusEndpoint(paymentId);
    await endpointTests.testRefundEndpoint(paymentId);
    await endpointTests.testCaptureEndpoint(paymentId);
    await endpointTests.testVoidEndpoint(paymentId);
  } else {
    testSuite.addTest('Payment Status', 'skipped', 'Payment creation failed');
    testSuite.addTest('Refund Payment', 'skipped', 'Payment creation failed');
    testSuite.addTest('Capture Payment', 'skipped', 'Payment creation failed');
    testSuite.addTest('Void Payment', 'skipped', 'Payment creation failed');
  }

  // Test transactions endpoint
  await endpointTests.testTransactionsEndpoint();

  // Test webhook endpoint
  await endpointTests.testWebhookEndpoint();

  // Generate final report
  const report = testSuite.generateReport();

  // Save detailed report to file
  const reportPath = path.join(__dirname, 'comprehensive_test_report.json');
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  console.log(`\n📄 Detailed report saved to: ${reportPath}`);

  return report;
}

// Run tests if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runComprehensiveTests()
    .then((report) => {
      console.log('\n🏁 Comprehensive testing completed!');
      process.exit(report.summary.failed > 0 ? 1 : 0);
    })
    .catch((error) => {
      console.error('❌ Test execution failed:', error);
      process.exit(1);
    });
}

export { runComprehensiveTests, JPMorganEndpointTests, TestSuite };
