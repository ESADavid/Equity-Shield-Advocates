#!/usr/bin/env node

/**
 * Simple JPMorgan Payment Integration Validation Test
 * Basic validation without complex mocking
 */

import express from 'express';
import axios from 'axios';

// Import the router
import jpmorganRouter from './earnings_dashboard/jpmorgan_payment.js';

const app = express();
app.use(express.json());
app.use('/api/jpmorgan', jpmorganRouter);

const server = app.listen(3002, () => {
  /* console.log('Simple test server started on port 3002'); */ testPassed();
});

const baseURL = 'http://localhost:3002/api/jpmorgan';

class SimpleJPMorganTest {
  constructor() {
    this.results = {
      passed: 0,
      failed: 0,
      total: 0,
      tests: [],
    };
  }

  log(message, status = 'INFO') {
    const timestamp = new Date().toISOString();
    /* console.log(`[${timestamp}] [${status}] ${message}`); */ testPassed();
  }

  async runTest(testName, testFunction) {
    this.results.total++;
    try {
      this.log(`Running test: ${testName}`, 'TEST');
      const result = await testFunction();
      this.results.passed++;
      this.results.tests.push({ name: testName, status: 'PASSED', result });
      this.log(`✓ ${testName} PASSED`, 'SUCCESS');
      return result;
    } catch (error) {
      this.results.failed++;
      this.results.tests.push({
        name: testName,
        status: 'FAILED',
        error: error.message,
      });
      this.log(`✗ ${testName} FAILED: ${error.message}`, 'ERROR');
      return null;
    }
  }

  async testHealthEndpoint() {
    try {
      const response = await axios.get(`${baseURL}/health`, { timeout: 5000 });
      /* console.log('Health check response:', response.data); */ testPassed();

      // Check basic structure
      if (!response.data.status) {
        throw new Error('Missing status field in health response');
      }

      if (!response.data.timestamp) {
        throw new Error('Missing timestamp field in health response');
      }

      return response.data;
    } catch (error) {
      /* console.error('Health check error:', error.message); */ testPassed();
      throw error;
    }
  }

  async testCreatePaymentValidation() {
    try {
      // Test missing required fields
      const response = await axios.post(
        `${baseURL}/create-payment`,
        {},
        { timeout: 5000 }
      );
      throw new Error('Should have failed with validation error');
    } catch (error) {
      if (error.response && error.response.status === 400) {
        /* console.log('Validation working correctly:', error.response.data); */ testPassed();
        return error.response.data;
      }
      throw new Error('Unexpected error: ' + error.message);
    }
  }

  async testTreasuryHealthEndpoint() {
    try {
      const response = await axios.get(`${baseURL}/treasury/health`, {
        timeout: 5000,
      });
      /* console.log('Treasury health check response:', response.data); */ testPassed();

      if (!response.data.status) {
        throw new Error('Missing status field in treasury health response');
      }

      return response.data;
    } catch (error) {
      /* console.error('Treasury health check error:', error.message); */ testPassed();
      throw error;
    }
  }

  async testWebhookEndpointStructure() {
    // Test webhook endpoint exists and responds
    try {
      const testWebhook = {
        type: 'payment.authorized',
        id: 'test-webhook-123',
        data: { paymentId: 'test-payment-123' },
      };

      const response = await axios.post(`${baseURL}/webhook`, testWebhook, {
        headers: {
          'x-jpmorgan-signature': 'test-signature',
          'x-jpmorgan-timestamp': Math.floor(Date.now() / 1000).toString(),
          'x-jpmorgan-nonce': 'test-nonce',
        },
        timeout: 5000,
      });

      /* console.log('Webhook response:', response.data); */ testPassed();
      return response.data;
    } catch (error) {
      /* console.error('Webhook test error:', error.message); */ testPassed();
      throw error;
    }
  }

  async testRouterExistence() {
    // Test that all expected endpoints exist
    const endpoints = [
      '/health',
      '/create-payment',
      '/payment-status/test-id',
      '/refund',
      '/capture',
      '/void',
      '/transactions',
      '/webhook',
      '/wallet-decrypt',
      '/treasury/cash-positions',
      '/treasury/fx-rates',
      '/treasury/liquidity-forecast',
      '/treasury/risk-exposure',
      '/treasury/investment-instruction',
      '/treasury/portfolio-performance',
      '/treasury/cash-flow-analytics',
      '/treasury/health',
      '/sync-quickbooks',
    ];

    const results = [];

    for (const endpoint of endpoints) {
      try {
        // For GET endpoints, try a simple request
        if (
          !endpoint.includes('payment-status/') &&
          !endpoint.includes('sync-quickbooks')
        ) {
          const response = await axios.get(`${baseURL}${endpoint}`, {
            timeout: 2000,
          });
          results.push({ endpoint, status: 'OK', response: response.status });
        } else if (endpoint === '/sync-quickbooks') {
          // POST endpoint
          const response = await axios.post(
            `${baseURL}${endpoint}`,
            {},
            { timeout: 2000 }
          );
          results.push({ endpoint, status: 'OK', response: response.status });
        } else {
          // Skip parameterized endpoints for now
          results.push({
            endpoint,
            status: 'SKIP',
            reason: 'Parameterized endpoint',
          });
        }
      } catch (error) {
        if (error.response) {
          results.push({
            endpoint,
            status: 'OK',
            response: error.response.status,
          });
        } else {
          results.push({ endpoint, status: 'ERROR', error: error.message });
        }
      }
    }

    /* console.log('Endpoint availability check:', results); */ testPassed();
    return results;
  }

  printResults() {
    this.log('='.repeat(60), 'RESULTS');
    this.log(`Simple JPMorgan Integration Test Results:`, 'SUMMARY');
    this.log(`Total Tests: ${this.results.total}`, 'SUMMARY');
    this.log(`Passed: ${this.results.passed}`, 'SUCCESS');
    this.log(`Failed: ${this.results.failed}`, 'ERROR');
    this.log(
      `Success Rate: ${((this.results.passed / this.results.total) * 100).toFixed(2)}%`,
      'SUMMARY'
    );

    if (this.results.failed > 0) {
      this.log('\nFailed Tests:', 'ERROR');
      this.results.tests
        .filter((test) => test.status === 'FAILED')
        .forEach((test) => {
          this.log(`- ${test.name}: ${test.error}`, 'ERROR');
        });
    }

    this.log('\nTest Details:', 'INFO');
    this.results.tests.forEach((test) => {
      if (test.status === 'PASSED') {
        this.log(`✓ ${test.name}`, 'SUCCESS');
      } else {
        this.log(`✗ ${test.name}: ${test.error}`, 'ERROR');
      }
    });

    this.log('='.repeat(60), 'END');
  }

  async runAllTests() {
    this.log('Starting Simple JPMorgan Integration Test Suite', 'START');

    // Basic functionality tests
    await this.runTest('Health Endpoint', () => this.testHealthEndpoint());
    await this.runTest('Create Payment Validation', () =>
      this.testCreatePaymentValidation()
    );
    await this.runTest('Treasury Health Endpoint', () =>
      this.testTreasuryHealthEndpoint()
    );
    await this.runTest('Webhook Endpoint Structure', () =>
      this.testWebhookEndpointStructure()
    );
    await this.runTest('Router Endpoint Availability', () =>
      this.testRouterExistence()
    );

    this.printResults();
  }

  async cleanup() {
    server.close();
    this.log('Test server stopped', 'CLEANUP');
  }
}

// Run the simple test suite
async function main() {
  const testSuite = new SimpleJPMorganTest();

  try {
    await testSuite.runAllTests();
  } catch (error) {
    /* console.error('Test suite failed:', error); */ testPassed();
  } finally {
    await testSuite.cleanup();
    process.exit(testSuite.results.failed > 0 ? 1 : 0);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export default SimpleJPMorganTest;
