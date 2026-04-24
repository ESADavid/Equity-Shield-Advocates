#!/usr/bin/env node

/**
 * Comprehensive Merchant Bill Pay Integration Test Suite
 *
 * This test suite provides thorough testing of all merchant payment endpoints
 * and integration functionality.
 */

import axios from 'axios';
import fs from 'node:fs';
import path from 'node:path';
import dotenv from 'dotenv';
import { info, error as logError } from 'utils/loggerWrapper.js';

dotenv.config();

// Test configuration
const TEST_CONFIG = {
  SERVER: {
    PORT: 3000,
    HOST: 'http://localhost:3000',
  },
};

// Check if credentials are configured
const hasStripeCredentials = !!process.env.STRIPE_SECRET_KEY;
const isMockMode = !hasStripeCredentials;

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
    let prefix;
    if (type === 'error') {
      prefix = '❌';
    } else if (type === 'success') {
      prefix = '✅';
    } else if (type === 'warning') {
      prefix = '⚠️';
    } else {
      prefix = 'ℹ️';
    }
    const logMessage = `[${timestamp}] ${prefix} ${message}`;
    if (type === 'error') {
      logError(logMessage);
    } else {
      info(logMessage);
    }
  }

  addTest(name, result, message = '') {
    this.results.total++;
    this.results.tests.push({
      name,
      result,
      message,
      timestamp: new Date().toISOString(),
    });

    const logMessage = `${name}: ${result.toUpperCase()}`;
    let logType;
    if (result === 'passed') {
      logType = 'success';
    } else if (result === 'failed') {
      logType = 'error';
    } else {
      logType = 'warning';
    }

    const isPassed = result === 'passed';
    const isFailed = result === 'failed';
    const isSkipped = result === 'skipped';

    if (isPassed) {
      this.results.passed++;
    } else if (isFailed) {
      this.results.failed++;
    } else if (isSkipped) {
      this.results.skipped++;
    }

    this.log(logMessage, logType);
  }

  generateReport() {
    const totalTests = this.results.total;
    const successRate =
      totalTests > 0
        ? ((this.results.passed / totalTests) * 100).toFixed(2)
        : 0;

    const report = {
      summary: {
        total: totalTests,
        passed: this.results.passed,
        failed: this.results.failed,
        skipped: this.results.skipped,
        successRate,
      },
      tests: this.results.tests,
      timestamp: new Date().toISOString(),
    };

    info('\n' + '='.repeat(60));
    info('🧪 COMPREHENSIVE MERCHANT TEST REPORT');
    info('='.repeat(60));
    info(`Total Tests: ${report.summary.total}`);
    info(`✅ Passed: ${report.summary.passed}`);
    info(`❌ Failed: ${report.summary.failed}`);
    info(`⚠️ Skipped: ${report.summary.skipped}`);
    info(`📈 Success Rate: ${report.summary.successRate}%`);
    info('='.repeat(60));

    const failedTests = this.results.tests.filter((t) => t.result === 'failed');
    if (failedTests.length > 0) {
      info('\n❌ FAILED TESTS:');
      for (const test of failedTests) {
        info(`• ${test.name}: ${test.message}`);
      }
    }

    return report;
  }
}

// Individual test functions
class MerchantEndpointTests {
  constructor(testSuite) {
    this.testSuite = testSuite;
    this.baseURL = TEST_CONFIG.SERVER.HOST;
  }

  async testCreateMerchantPaymentIntent() {
    try {
      this.testSuite.log('Testing create merchant payment intent endpoint...');

      const paymentData = {
        amount: 1000, // $10.00 in cents
        currency: 'usd',
        merchantId: 'merchant_001',
        description: 'Test merchant payment',
      };

      const response = await axios.post(
        `${this.baseURL}/api/merchant/create-merchant-payment-intent`,
        paymentData,
        { timeout: 15000 }
      );

      if (
        response.status === 200 &&
        response.data.success &&
        response.data.clientSecret
      ) {
        this.testSuite.addTest(
          'Create Merchant Payment Intent',
          'passed',
          `Payment intent created: ${response.data.paymentIntent?.id} (Mock: ${isMockMode})`
        );
        return response.data.paymentIntent?.id;
      } else {
        this.testSuite.addTest(
          'Create Merchant Payment Intent',
          'failed',
          `Unexpected response: ${JSON.stringify(response.data)}`
        );
        return false;
      }
    } catch (error) {
      this.testSuite.addTest(
        'Create Merchant Payment Intent',
        'failed',
        `Payment intent creation failed: ${error.message}`
      );
      return false;
    }
  }

  async testMerchantWebhook() {
    try {
      this.testSuite.log('Testing merchant webhook endpoint...');

      const webhookData = {
        id: 'evt_test_webhook',
        object: 'event',
        type: 'payment_intent.succeeded',
        data: {
          object: {
            id: 'pi_test_123',
            amount: 1000,
            metadata: { merchantId: 'merchant_001' },
            description: 'Test payment',
            last_payment_error: null,
          },
        },
      };

      const response = await axios.post(
        `${this.baseURL}/api/merchant/merchant-webhook`,
        webhookData,
        {
          headers: {
            'Content-Type': 'application/json',
          },
          timeout: 10000,
        }
      );

      if (response.status === 200 && response.data.received) {
        this.testSuite.addTest(
          'Merchant Webhook',
          'passed',
          `Webhook processed successfully (Mock: ${isMockMode})`
        );
        return true;
      } else {
        this.testSuite.addTest(
          'Merchant Webhook',
          'failed',
          `Unexpected response: ${JSON.stringify(response.data)}`
        );
        return false;
      }
    } catch (error) {
      this.testSuite.addTest(
        'Merchant Webhook',
        'failed',
        `Webhook test failed: ${error.message}`
      );
      return false;
    }
  }

  async testMerchantPaymentIntentValidation() {
    try {
      this.testSuite.log('Testing payment intent validation...');

      // Test missing amount
      const testRequest = {
        merchantId: 'merchant_001',
      };

      try {
        await axios.post(
          `${this.baseURL}/api/merchant/create-merchant-payment-intent`,
          testRequest
        );
        this.testSuite.addTest(
          'Payment Intent Validation',
          'failed',
          'Should have rejected missing amount'
        );
        return false;
      } catch (error) {
        const isBadRequest = error.response?.status === 400;
        if (isBadRequest) {
          this.testSuite.addTest(
            'Payment Intent Validation',
            'passed',
            'Properly validates required fields'
          );
          return true;
        } else {
          this.testSuite.addTest(
            'Payment Intent Validation',
            'failed',
            `Unexpected error: ${error.message}`
          );
          return false;
        }
      }
    } catch (error) {
      this.testSuite.addTest(
        'Payment Intent Validation',
        'failed',
        `Validation test failed: ${error.message}`
      );
      return false;
    }
  }

  async testEnvironmentConfiguration() {
    this.testSuite.log('Testing environment configuration...');

    // Check if server is running in mock mode by testing a health endpoint
    try {
      const healthResponse = await axios.get(`${this.baseURL}/health`);
      const isServerHealthy =
        healthResponse.data &&
        (healthResponse.data.status === 'healthy' ||
          healthResponse.data.status === 'degraded');

      if (isMockMode && isServerHealthy) {
        this.testSuite.addTest(
          'Environment Config',
          'passed',
          'Mock mode active - Stripe credentials not required'
        );
      } else if (!isMockMode && isServerHealthy) {
        this.testSuite.addTest(
          'Environment Config',
          'passed',
          'Stripe credentials configured and server running in live mode'
        );
      } else {
        this.testSuite.addTest(
          'Environment Config',
          'failed',
          'Environment configuration mismatch between client and server'
        );
      }
    } catch (error) {
      this.testSuite.addTest(
        'Environment Config',
        'failed',
        `Could not verify server health: ${error.message}`
      );
    }

    return true;
  }
}

// Main test execution
async function runComprehensiveMerchantTests() {
  const testSuite = new TestSuite();
  const endpointTests = new MerchantEndpointTests(testSuite);

  info('🧪 Starting Comprehensive Merchant Bill Pay Integration Tests');
  info('='.repeat(70));
  info(`Server URL: ${TEST_CONFIG.SERVER.HOST}`);
  info(
    `Stripe Credentials Configured: ${hasStripeCredentials ? '✅ Yes' : '⚠️ No'}`
  );
  info('='.repeat(70));

  // Test environment configuration
  await endpointTests.testEnvironmentConfiguration();

  // Test payment intent creation
  await endpointTests.testCreateMerchantPaymentIntent();

  // Test webhook endpoint
  await endpointTests.testMerchantWebhook();

  // Test validation
  await endpointTests.testMerchantPaymentIntentValidation();

  // Generate final report
  const report = testSuite.generateReport();

  // Save detailed report to file
  const reportPath = path.join(
    process.cwd(),
    'comprehensive_merchant_test_report.json'
  );
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  info(`\n📄 Detailed report saved to: ${reportPath}`);

  return report;
}

// Run tests if called directly
if (require.main === module) {
  (async () => {
    try {
      const report = await runComprehensiveMerchantTests();
      info('\n🏁 Comprehensive merchant testing completed!');
      process.exit(report.summary.failed > 0 ? 1 : 0);
    } catch (error) {
      logError('❌ Test execution failed:', error);
      process.exit(1);
    }
  })();
}

export { runComprehensiveMerchantTests, MerchantEndpointTests, TestSuite };
