#!/usr/bin/env node

/**
 * Comprehensive Merchant Bill Pay Integration Test Suite
 *
 * This test suite provides thorough testing of all merchant payment endpoints
 * and integration functionality.
 */

import express from 'express';
import axios from 'axios';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

// Test configuration
const TEST_CONFIG = {
  SERVER: {
    PORT: 3000,
    HOST: 'http://localhost:3000'
  }
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
      tests: []
    };
  }

  log(message, type = 'info') {
    const timestamp = new Date().toISOString();
    const prefix = type === 'error' ? '❌' : type === 'success' ? '✅' : type === 'warning' ? '⚠️' : 'ℹ️';
    console.log(`[${timestamp}] ${prefix} ${message}`);
  }

  addTest(name, result, message = '') {
    this.results.total++;
    this.results.tests.push({ name, result, message, timestamp: new Date().toISOString() });

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
        successRate: this.results.total > 0 ? (this.results.passed / this.results.total * 100).toFixed(2) : 0
      },
      tests: this.results.tests,
      timestamp: new Date().toISOString()
    };

    console.log('\n' + '='.repeat(60));
    console.log('🧪 COMPREHENSIVE MERCHANT TEST REPORT');
    console.log('='.repeat(60));
    console.log(`Total Tests: ${report.summary.total}`);
    console.log(`✅ Passed: ${report.summary.passed}`);
    console.log(`❌ Failed: ${report.summary.failed}`);
    console.log(`⚠️ Skipped: ${report.summary.skipped}`);
    console.log(`📈 Success Rate: ${report.summary.successRate}%`);
    console.log('='.repeat(60));

    if (report.summary.failed > 0) {
      console.log('\n❌ FAILED TESTS:');
      this.results.tests.filter(t => t.result === 'failed').forEach(test => {
        console.log(`• ${test.name}: ${test.message}`);
      });
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
        description: 'Test merchant payment'
      };

      const response = await axios.post(
        `${this.baseURL}/api/merchant/create-merchant-payment-intent`,
        paymentData,
        { timeout: 15000 }
      );

      if (response.status === 200 && response.data.success && response.data.clientSecret) {
        this.testSuite.addTest('Create Merchant Payment Intent', 'passed', `Payment intent created: ${response.data.paymentIntent?.id} (Mock: ${isMockMode})`);
        return response.data.paymentIntent?.id;
      } else {
        this.testSuite.addTest('Create Merchant Payment Intent', 'failed', `Unexpected response: ${JSON.stringify(response.data)}`);
        return false;
      }
    } catch (error) {
      this.testSuite.addTest('Create Merchant Payment Intent', 'failed', `Payment intent creation failed: ${error.message}`);
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
            last_payment_error: null
          }
        }
      };

      const response = await axios.post(
        `${this.baseURL}/api/merchant/merchant-webhook`,
        webhookData,
        {
          headers: {
            'Content-Type': 'application/json'
          },
          timeout: 10000
        }
      );

      if (response.status === 200 && response.data.received) {
        this.testSuite.addTest('Merchant Webhook', 'passed', 'Webhook processed successfully (Mock: ${isMockMode})');
        return true;
      } else {
        this.testSuite.addTest('Merchant Webhook', 'failed', `Unexpected response: ${JSON.stringify(response.data)}`);
        return false;
      }
    } catch (error) {
      this.testSuite.addTest('Merchant Webhook', 'failed', `Webhook test failed: ${error.message}`);
      return false;
    }
  }

  async testMerchantPaymentIntentValidation() {
    try {
      this.testSuite.log('Testing payment intent validation...');

      // Test missing amount
      try {
        await axios.post(`${this.baseURL}/api/merchant/create-merchant-payment-intent`, {
          merchantId: 'merchant_001'
        });
        this.testSuite.addTest('Payment Intent Validation', 'failed', 'Should have rejected missing amount');
        return false;
      } catch (error) {
        if (error.response?.status === 400) {
          this.testSuite.addTest('Payment Intent Validation', 'passed', 'Properly validates required fields');
          return true;
        } else {
          this.testSuite.addTest('Payment Intent Validation', 'failed', `Unexpected error: ${error.message}`);
          return false;
        }
      }
    } catch (error) {
      this.testSuite.addTest('Payment Intent Validation', 'failed', `Validation test failed: ${error.message}`);
      return false;
    }
  }

  async testEnvironmentConfiguration() {
    this.testSuite.log('Testing environment configuration...');

    if (isMockMode) {
      this.testSuite.addTest('Environment Config', 'passed', 'Mock mode active - Stripe credentials not required');
    } else {
      this.testSuite.addTest('Environment Config', 'passed', 'Stripe credentials configured');
    }

    return true;
  }
}

// Main test execution
async function runComprehensiveMerchantTests() {
  const testSuite = new TestSuite();
  const endpointTests = new MerchantEndpointTests(testSuite);

  console.log('🧪 Starting Comprehensive Merchant Bill Pay Integration Tests');
  console.log('='.repeat(70));
  console.log(`Server URL: ${TEST_CONFIG.SERVER.HOST}`);
  console.log(`Stripe Credentials Configured: ${hasStripeCredentials ? '✅ Yes' : '⚠️ No'}`);
  console.log('='.repeat(70));

  // Test environment configuration
  await endpointTests.testEnvironmentConfiguration();

  // Test payment intent creation
  const paymentIntentId = await endpointTests.testCreateMerchantPaymentIntent();

  // Test webhook endpoint
  await endpointTests.testMerchantWebhook();

  // Test validation
  await endpointTests.testMerchantPaymentIntentValidation();

  // Generate final report
  const report = testSuite.generateReport();

  // Save detailed report to file
  const reportPath = path.join(process.cwd(), 'comprehensive_merchant_test_report.json');
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  console.log(`\n📄 Detailed report saved to: ${reportPath}`);

  return report;
}

// Run tests if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runComprehensiveMerchantTests()
    .then(report => {
      console.log('\n🏁 Comprehensive merchant testing completed!');
      process.exit(report.summary.failed > 0 ? 1 : 0);
    })
    .catch(error => {
      console.error('❌ Test execution failed:', error);
      process.exit(1);
    });
}

export { runComprehensiveMerchantTests, MerchantEndpointTests, TestSuite };
